using System.Collections.ObjectModel;
using Mstech.IisSslManager.Infrastructure;

namespace Mstech.IisSslManager.Services;

/// <summary>
/// The win-acme build that has been verified with this release of the application.
/// Updating any of these values is a release engineering operation: download the
/// new archive from the official project, test it, and pin both hashes again.
/// </summary>
public static class WinAcmeRecommendedRelease
{
    public const string ManagedClientName = "MSTECH-IisSslManager";
    public const string ProductionBaseUri = "https://acme-v02.api.letsencrypt.org/";
    public const string StagingBaseUri = "https://acme-staging-v02.api.letsencrypt.org/";
    public const string StagingCompletionOutputMarker =
        "[--test] Store and install the certificate for order";
    public const string Version = "2.2.9.1701";
    public const long ArchiveSizeBytes = 14_291_591;
    public const string ArchiveSha256 =
        "F4DC3B144841FFDBA391CE168C273D7A686D45A359075E30EE4BF4EE186857D6";
    public const string ExecutableSha256 =
        "FDFF5C5612E0BCBC8ABA52720E5D37E5C3821267179E2FA7341084148AD4B1EA";

    public static Uri DownloadUri { get; } = new(
        "https://github.com/win-acme/win-acme/releases/download/" +
        "v2.2.9.1701/win-acme.v2.2.9.1701.x64.trimmed.zip");

    public static string InstallDirectory => AppPaths.WinAcmeDirectory;

    public static string ExecutablePath => AppPaths.WinAcmeExecutable;
}

public enum WinAcmeLocationSource
{
    Configured,
    ManagedInstallation,
    ApplicationDirectory,
    ProgramFiles,
    PathEnvironment,
    ConventionalDirectory,
    UserSelected
}

public sealed record WinAcmeInstallationInfo
{
    public required string ExecutablePath { get; init; }

    public required WinAcmeLocationSource Source { get; init; }

    public bool Exists { get; init; }

    public string? FileVersion { get; init; }

    public string? ProductVersion { get; init; }

    public string? Sha256 { get; init; }

    /// <summary>
    /// True only for the exact executable extracted from the pinned official
    /// archive. Merely reporting the same version number is not sufficient.
    /// </summary>
    public bool IntegrityVerified { get; init; }

    public bool IsRecommendedVersion =>
        string.Equals(FileVersion, WinAcmeRecommendedRelease.Version, StringComparison.OrdinalIgnoreCase);

    public string StatusMessage { get; init; } = string.Empty;
}

public sealed record WinAcmeDownloadProgress
{
    public required string Stage { get; init; }

    public long BytesReceived { get; init; }

    public long? TotalBytes { get; init; }

    public int? Percentage => TotalBytes is > 0
        ? (int)Math.Clamp(BytesReceived * 100L / TotalBytes.Value, 0, 100)
        : null;
}

public sealed record WinAcmeCertificateRequest
{
    public required long SiteId { get; init; }

    public required IReadOnlyList<string> HostNames { get; init; }

    public required string ContactEmail { get; init; }

    public string? CommonName { get; init; }

    public string? FriendlyName { get; init; }
}

public enum WinAcmeCommandKind
{
    StagingValidation,
    ProductionIssuance,
    RenewalCheck,
    ForcedRenewal,
    ListRenewals,
    SetupTaskScheduler,
    Version
}

public sealed record WinAcmeCommand
{
    public required WinAcmeCommandKind Kind { get; init; }

    public required IReadOnlyList<string> Arguments { get; init; }

    public bool RequiresAdministrator { get; init; } = true;

    public bool ChangesIisBindings { get; init; }

    public bool UsesStagingEnvironment { get; init; }

    /// <summary>
    /// Exact stdout marker that safely completes this command before the pinned
    /// win-acme test-mode prompt attempts to read from a hidden console.
    /// </summary>
    public string? CompletionOutputMarker { get; init; }

    /// <summary>
    /// Unique application-owned directories that must be removed after the command.
    /// Used for the untrusted staging PFX only.
    /// </summary>
    public IReadOnlyList<string> TemporaryDirectoriesToDelete { get; init; } = [];

    public static WinAcmeCommand Create(
        WinAcmeCommandKind kind,
        IEnumerable<string> arguments,
        bool requiresAdministrator = true,
        bool changesIisBindings = false,
        bool usesStagingEnvironment = false,
        string? completionOutputMarker = null,
        IEnumerable<string>? temporaryDirectoriesToDelete = null) => new()
        {
            Kind = kind,
            Arguments = new ReadOnlyCollection<string>(arguments.ToArray()),
            RequiresAdministrator = requiresAdministrator,
            ChangesIisBindings = changesIisBindings,
            UsesStagingEnvironment = usesStagingEnvironment,
            CompletionOutputMarker = completionOutputMarker,
            TemporaryDirectoriesToDelete = new ReadOnlyCollection<string>(
                temporaryDirectoriesToDelete?.ToArray() ?? [])
        };
}

public sealed record WinAcmeExecutionResult
{
    public required WinAcmeCommand Command { get; init; }

    public required Models.ProcessResult ProcessResult { get; init; }

    public required string SafeCommandLine { get; init; }

    /// <summary>
    /// Per-directory confirmation for command-owned temporary material, such as
    /// the untrusted PFX produced by a staging validation.
    /// </summary>
    public IReadOnlyList<WinAcmeTemporaryCleanupResult> TemporaryCleanupResults { get; init; } = [];

    public bool TemporaryCleanupSucceeded =>
        TemporaryCleanupResults.Count == Command.TemporaryDirectoriesToDelete.Count &&
        TemporaryCleanupResults.All(result => result.Succeeded);
}

public sealed record WinAcmeTemporaryCleanupResult
{
    public required string DirectoryPath { get; init; }

    public bool DirectoryExisted { get; init; }

    /// <summary>
    /// True only when the target was already absent or its absence was confirmed
    /// after deletion.
    /// </summary>
    public bool Succeeded { get; init; }

    public string? ErrorMessage { get; init; }
}

public enum WinAcmeScheduledTaskState
{
    Unknown,
    Disabled,
    Queued,
    Ready,
    Running
}

public sealed record WinAcmeScheduledTaskInfo
{
    public required string Name { get; init; }

    public string Path { get; init; } = "\\";

    public WinAcmeScheduledTaskState State { get; init; }

    public bool Enabled { get; init; }

    public DateTime? LastRunTime { get; init; }

    public DateTime? NextRunTime { get; init; }

    public int? LastTaskResult { get; init; }

    public string? RunAsUser { get; init; }

    public string? ExecutablePath { get; init; }

    public string? Arguments { get; init; }

    public string? WorkingDirectory { get; init; }

    public int ActionCount { get; init; }

    public int TriggerCount { get; init; }

    public int EnabledRecurringTriggerCount { get; init; }

    public bool LastRunSucceeded => LastRunTime is not null && LastTaskResult == 0;
}

public sealed record WinAcmeScheduledTaskReadResult
{
    public bool Succeeded { get; init; }

    public string? ErrorMessage { get; init; }

    public IReadOnlyList<WinAcmeScheduledTaskInfo> Tasks { get; init; } = [];
}

public sealed record ScheduledTaskReadiness
{
    public bool IsReady { get; init; }

    public string Summary { get; init; } = string.Empty;

    public IReadOnlyList<string> Issues { get; init; } = [];
}
