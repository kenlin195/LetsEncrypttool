using System.IO;
using System.Security;
using Mstech.IisSslManager.Core;
using Mstech.IisSslManager.Infrastructure;
using Mstech.IisSslManager.Models;

namespace Mstech.IisSslManager.Services;

public sealed class WinAcmeService
{
    private readonly IProcessRunner _processRunner;
    private readonly ElevationService _elevationService;

    public WinAcmeService(IProcessRunner processRunner, ElevationService? elevationService = null)
    {
        _processRunner = processRunner ?? throw new ArgumentNullException(nameof(processRunner));
        _elevationService = elevationService ?? new ElevationService(processRunner);
    }

    public async Task<WinAcmeExecutionResult> ExecuteAsync(
        string executablePath,
        WinAcmeCommand command,
        bool requestElevationWhenRequired = true,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(command);
        var normalizedPath = WinAcmeLocator.NormalizeExecutablePath(executablePath);
        if (!File.Exists(normalizedPath))
        {
            throw new FileNotFoundException("找不到 wacs.exe。", normalizedPath);
        }

        ProcessResult result;
        IReadOnlyList<WinAcmeTemporaryCleanupResult> cleanupResults = [];
        try
        {
            foreach (var temporaryDirectory in command.TemporaryDirectoriesToDelete)
            {
                EnsureOwnedTemporaryDirectory(temporaryDirectory);
            }

            if (command.RequiresAdministrator && !_elevationService.IsAdministrator)
            {
                if (!requestElevationWhenRequired)
                {
                    result = new ProcessResult
                    {
                        Started = false,
                        ErrorMessage = "此操作需要系統管理員權限，請先通過 Windows UAC 驗證。"
                    };
                }
                else
                {
                    result = await _elevationService.RunAsAdministratorAsync(
                        normalizedPath,
                        command.Arguments,
                        Path.GetDirectoryName(normalizedPath),
                        TimeSpan.FromMinutes(30),
                        cancellationToken).ConfigureAwait(false);
                }
            }
            else
            {
                result = await _processRunner.RunAsync(new ProcessRequest
                {
                    FileName = normalizedPath,
                    Arguments = command.Arguments,
                    WorkingDirectory = Path.GetDirectoryName(normalizedPath),
                    Timeout = TimeSpan.FromMinutes(30),
                    RunAsAdministrator = false,
                    CreateNoWindow = true,
                    CompletionOutputMarker = command.CompletionOutputMarker
                }, cancellationToken).ConfigureAwait(false);
            }

        }
        finally
        {
            cleanupResults = command.TemporaryDirectoriesToDelete
                .Select(DeleteOwnedTemporaryDirectory)
                .ToArray();
        }

        result = result with
        {
            StandardOutput = SecurityArgumentService.RedactSecretValues(
                result.StandardOutput,
                command.Arguments),
            StandardError = SecurityArgumentService.RedactSecretValues(
                result.StandardError,
                command.Arguments),
            ErrorMessage = result.ErrorMessage is null
                ? null
                : SecurityArgumentService.RedactSecretValues(
                    result.ErrorMessage,
                    command.Arguments)
        };

        return new WinAcmeExecutionResult
        {
            Command = command,
            ProcessResult = result,
            SafeCommandLine = SecurityArgumentService.ToSafeDisplayCommand(
                normalizedPath,
                command.Arguments),
            TemporaryCleanupResults = cleanupResults
        };
    }

    private static void EnsureOwnedTemporaryDirectory(string path)
    {
        var root = Path.GetFullPath(AppPaths.SecureStagingDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var fullPath = Path.GetFullPath(path);
        if (!string.Equals(Path.GetDirectoryName(fullPath), root, StringComparison.OrdinalIgnoreCase) ||
            Path.GetFileName(fullPath).Length != 32 ||
            !Guid.TryParseExact(Path.GetFileName(fullPath), "N", out _))
        {
            throw new InvalidOperationException("拒絕使用不屬於本工具的暫存目錄。");
        }

        ProgramDataSecurity.EnsureDirectory(
            AppPaths.SecureStagingDirectory,
            ProgramDataAccess.MachinePrivate);
        ProgramDataSecurity.EnsureDirectory(fullPath, ProgramDataAccess.MachinePrivate);
        ProgramDataSecurity.ValidateTreeNoReparse(fullPath);
    }

    private static WinAcmeTemporaryCleanupResult DeleteOwnedTemporaryDirectory(string path)
    {
        var reportedPath = path;
        var existed = false;
        try
        {
            var root = Path.GetFullPath(AppPaths.SecureStagingDirectory)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var fullPath = Path.GetFullPath(path);
            reportedPath = fullPath;
            if (!string.Equals(Path.GetDirectoryName(fullPath), root, StringComparison.OrdinalIgnoreCase) ||
                Path.GetFileName(fullPath).Length != 32 ||
                !Guid.TryParseExact(Path.GetFileName(fullPath), "N", out _))
            {
                return CleanupFailure(reportedPath, false, "拒絕清除不屬於本工具的暫存路徑。");
            }

            existed = Directory.Exists(fullPath) || File.Exists(fullPath);
            if (existed)
            {
                if (!Directory.Exists(fullPath))
                {
                    return CleanupFailure(reportedPath, true, "暫存路徑不是目錄，基於安全考量未刪除。");
                }

                ProgramDataSecurity.ValidateTreeNoReparse(fullPath);
                Directory.Delete(fullPath, recursive: true);
            }

            if (Directory.Exists(fullPath) || File.Exists(fullPath))
            {
                return CleanupFailure(reportedPath, existed, "刪除完成後暫存路徑仍然存在。");
            }

            return new WinAcmeTemporaryCleanupResult
            {
                DirectoryPath = reportedPath,
                DirectoryExisted = existed,
                Succeeded = true
            };
        }
        catch (Exception exception) when (
            exception is ArgumentException or IOException or UnauthorizedAccessException or
            NotSupportedException or SecurityException)
        {
            return CleanupFailure(reportedPath, existed, exception.Message);
        }
    }

    private static WinAcmeTemporaryCleanupResult CleanupFailure(
        string path,
        bool existed,
        string message) => new()
        {
            DirectoryPath = path,
            DirectoryExisted = existed,
            Succeeded = false,
            ErrorMessage = message
        };
}
