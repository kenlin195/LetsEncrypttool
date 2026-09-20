using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Text;
using Mstech.IisSslManager.Models;

namespace Mstech.IisSslManager.Core;

/// <summary>
/// Runs an executable with strongly separated arguments. This class never invokes
/// cmd.exe or PowerShell and therefore avoids command-line string interpolation.
/// </summary>
public sealed class ProcessRunner : IProcessRunner
{
    private const int ErrorCancelled = 1223;
    private static readonly TimeSpan TerminationGracePeriod = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan OutputDrainGracePeriod = TimeSpan.FromSeconds(2);

    public async Task<ProcessResult> RunAsync(
        ProcessRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (string.IsNullOrWhiteSpace(request.FileName))
        {
            throw new ArgumentException("Executable path is required.", nameof(request));
        }

        if (request.Timeout != Timeout.InfiniteTimeSpan && request.Timeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(request),
                "Process timeout must be positive or Timeout.InfiniteTimeSpan.");
        }

        if (request.CompletionOutputMarker is not null &&
            string.IsNullOrWhiteSpace(request.CompletionOutputMarker))
        {
            throw new ArgumentException(
                "Process completion output marker cannot be empty.",
                nameof(request));
        }

        if (request.RunAsAdministrator && request.CompletionOutputMarker is not null)
        {
            throw new ArgumentException(
                "Output markers require redirected output and cannot be used with runas.",
                nameof(request));
        }

        var stopwatch = Stopwatch.StartNew();
        Process? process = null;

        try
        {
            cancellationToken.ThrowIfCancellationRequested();

            var startInfo = CreateStartInfo(request);
            process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };

            if (!process.Start())
            {
                return FailedToStart("Windows did not start the process.", stopwatch.Elapsed);
            }

            Task<string>? standardOutputTask = null;
            Task<string>? standardErrorTask = null;
            var outputMarkerReached = 0;

            if (!request.RunAsAdministrator)
            {
                standardOutputTask = request.CompletionOutputMarker is null
                    ? process.StandardOutput.ReadToEndAsync()
                    : CaptureStandardOutputAsync(
                        process.StandardOutput,
                        request.CompletionOutputMarker,
                        () =>
                        {
                            if (Interlocked.Exchange(ref outputMarkerReached, 1) == 0)
                            {
                                TryTerminate(process);
                            }
                        });
                standardErrorTask = process.StandardError.ReadToEndAsync();
            }

            using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            if (request.Timeout != Timeout.InfiniteTimeSpan)
            {
                linkedCancellation.CancelAfter(request.Timeout);
            }

            var timedOut = false;
            var wasCancelled = false;
            var exitConfirmed = true;

            try
            {
                await process.WaitForExitAsync(linkedCancellation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                wasCancelled = cancellationToken.IsCancellationRequested;
                timedOut = !wasCancelled;
                TryTerminate(process);
                exitConfirmed = await WaitForExitWithinAsync(process, TerminationGracePeriod)
                    .ConfigureAwait(false);
            }

            // A child process may keep inherited pipe handles open after the process we
            // started exits. Never let output draining turn a timeout/cancellation into
            // another unbounded wait.
            var standardOutput = await ReadCapturedOutputAsync(
                    standardOutputTask,
                    exitConfirmed)
                .ConfigureAwait(false);
            var standardError = await ReadCapturedOutputAsync(
                    standardErrorTask,
                    exitConfirmed)
                .ConfigureAwait(false);
            var completedByOutputMarker = Volatile.Read(ref outputMarkerReached) == 1 &&
                exitConfirmed && !timedOut && !wasCancelled;
            var errorMessage = BuildCancellationError(timedOut, wasCancelled, exitConfirmed);
            if (Volatile.Read(ref outputMarkerReached) == 1 && !exitConfirmed &&
                errorMessage is null)
            {
                errorMessage =
                    "The completion output marker was detected, but Windows did not confirm process termination within five seconds.";
            }

            return new ProcessResult
            {
                Started = true,
                ExitCode = completedByOutputMarker ? 0 : TryGetExitCode(process),
                StandardOutput = standardOutput,
                StandardError = standardError,
                ErrorMessage = errorMessage,
                TimedOut = timedOut,
                WasCancelled = wasCancelled,
                CompletedByOutputMarker = completedByOutputMarker,
                Duration = stopwatch.Elapsed
            };
        }
        catch (Win32Exception exception) when (
            request.RunAsAdministrator && exception.NativeErrorCode == ErrorCancelled)
        {
            return new ProcessResult
            {
                Started = false,
                ElevationWasCancelled = true,
                ErrorMessage = "The Windows administrator prompt was cancelled.",
                Duration = stopwatch.Elapsed
            };
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return new ProcessResult
            {
                Started = process is not null,
                WasCancelled = true,
                ErrorMessage = "The operation was cancelled.",
                Duration = stopwatch.Elapsed
            };
        }
        catch (Exception exception) when (
            exception is Win32Exception or InvalidOperationException or IOException)
        {
            return FailedToStart(exception.Message, stopwatch.Elapsed);
        }
        finally
        {
            process?.Dispose();
        }
    }

    private static ProcessStartInfo CreateStartInfo(ProcessRequest request)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = request.FileName,
            WorkingDirectory = string.IsNullOrWhiteSpace(request.WorkingDirectory)
                ? Environment.CurrentDirectory
                : request.WorkingDirectory,
            UseShellExecute = request.RunAsAdministrator,
            CreateNoWindow = request.CreateNoWindow && !request.RunAsAdministrator,
            RedirectStandardOutput = !request.RunAsAdministrator,
            RedirectStandardError = !request.RunAsAdministrator
        };

        if (request.RunAsAdministrator)
        {
            startInfo.Verb = "runas";
        }
        else
        {
            startInfo.StandardOutputEncoding = request.StandardOutputEncoding;
            startInfo.StandardErrorEncoding = request.StandardErrorEncoding;
        }

        foreach (var argument in request.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        foreach (var pair in request.EnvironmentVariables)
        {
            if (pair.Value is null)
            {
                startInfo.Environment.Remove(pair.Key);
            }
            else
            {
                startInfo.Environment[pair.Key] = pair.Value;
            }
        }

        return startInfo;
    }

    private static ProcessResult FailedToStart(string message, TimeSpan duration) => new()
    {
        Started = false,
        ErrorMessage = message,
        Duration = duration
    };

    private static void TryTerminate(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (InvalidOperationException)
        {
            // The process exited between the HasExited check and Kill.
        }
        catch (Win32Exception)
        {
            // The caller may not own the elevated child. The result still reports the
            // timeout and never treats this as success.
        }
    }

    private static async Task<bool> WaitForExitWithinAsync(Process process, TimeSpan timeout)
    {
        if (TryHasExited(process))
        {
            return true;
        }

        using var timeoutCancellation = new CancellationTokenSource(timeout);
        try
        {
            await process.WaitForExitAsync(timeoutCancellation.Token).ConfigureAwait(false);
            return true;
        }
        catch (OperationCanceledException) when (timeoutCancellation.IsCancellationRequested)
        {
            return TryHasExited(process);
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or Win32Exception)
        {
            return TryHasExited(process);
        }
    }

    private static async Task<string> ReadCapturedOutputAsync(
        Task<string>? outputTask,
        bool mayWait)
    {
        if (outputTask is null)
        {
            return string.Empty;
        }

        if (outputTask.IsCompletedSuccessfully)
        {
            return outputTask.Result;
        }

        if (!mayWait)
        {
            return string.Empty;
        }

        try
        {
            return await outputTask.WaitAsync(OutputDrainGracePeriod).ConfigureAwait(false);
        }
        catch (Exception exception) when (
            exception is TimeoutException or IOException or ObjectDisposedException or
            InvalidOperationException)
        {
            return string.Empty;
        }
    }

    private static async Task<string> CaptureStandardOutputAsync(
        StreamReader reader,
        string marker,
        Action onMarker)
    {
        var output = new StringBuilder();
        var buffer = new char[1024];
        var markerReached = false;
        while (true)
        {
            var read = await reader.ReadAsync(buffer.AsMemory()).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            var previousLength = output.Length;
            output.Append(buffer, 0, read);
            if (markerReached)
            {
                continue;
            }

            var searchStart = Math.Max(0, previousLength - marker.Length + 1);
            var searchLength = output.Length - searchStart;
            if (output.ToString(searchStart, searchLength)
                .Contains(marker, StringComparison.Ordinal))
            {
                markerReached = true;
                onMarker();
            }
        }

        return output.ToString();
    }

    private static int? TryGetExitCode(Process process)
    {
        try
        {
            return process.HasExited ? process.ExitCode : null;
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or Win32Exception)
        {
            return null;
        }
    }

    private static bool TryHasExited(Process process)
    {
        try
        {
            return process.HasExited;
        }
        catch (Exception exception) when (
            exception is InvalidOperationException or Win32Exception)
        {
            return false;
        }
    }

    private static string? BuildCancellationError(
        bool timedOut,
        bool wasCancelled,
        bool exitConfirmed)
    {
        if (!timedOut && !wasCancelled)
        {
            return null;
        }

        var reason = timedOut ? "The process timed out." : "The operation was cancelled.";
        return exitConfirmed
            ? reason
            : reason + " Windows did not confirm process termination within five seconds.";
    }
}
