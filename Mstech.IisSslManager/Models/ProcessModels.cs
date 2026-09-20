using System.Collections.ObjectModel;
using System.Text;

namespace Mstech.IisSslManager.Models;

public sealed record ProcessRequest
{
    public required string FileName { get; init; }

    public IReadOnlyList<string> Arguments { get; init; } = Array.Empty<string>();

    public string? WorkingDirectory { get; init; }

    public IReadOnlyDictionary<string, string?> EnvironmentVariables { get; init; } =
        new ReadOnlyDictionary<string, string?>(new Dictionary<string, string?>());

    public TimeSpan Timeout { get; init; } = TimeSpan.FromMinutes(2);

    public Encoding? StandardOutputEncoding { get; init; }

    public Encoding? StandardErrorEncoding { get; init; }

    /// <summary>
    /// Optional trusted stdout marker that completes the operation. When the exact
    /// marker is observed, the runner terminates the process tree and reports a
    /// successful completion only after Windows confirms termination.
    /// </summary>
    public string? CompletionOutputMarker { get; init; }

    /// <summary>
    /// Starts the process through the Windows UAC runas verb. Elevated processes
    /// cannot have their standard streams redirected by this runner.
    /// </summary>
    public bool RunAsAdministrator { get; init; }

    public bool CreateNoWindow { get; init; } = true;
}

public sealed record ProcessResult
{
    public required bool Started { get; init; }

    public int? ExitCode { get; init; }

    public string StandardOutput { get; init; } = string.Empty;

    public string StandardError { get; init; } = string.Empty;

    public string? ErrorMessage { get; init; }

    public bool TimedOut { get; init; }

    public bool WasCancelled { get; init; }

    public bool ElevationWasCancelled { get; init; }

    public bool CompletedByOutputMarker { get; init; }

    public TimeSpan Duration { get; init; }

    public bool Succeeded => Started && ExitCode == 0 && !TimedOut && !WasCancelled;
}
