using System.Collections.ObjectModel;
using System.Net;

namespace Mstech.IisSslManager.Models;

public enum PreflightPhase
{
    PublicEnvironment,
    ElevatedLocalEnvironment,
    AcmeStaging
}

public enum CheckStatus
{
    Pending,
    Running,
    Passed,
    Warning,
    Failed,
    Skipped
}

public enum CertificateNameMode
{
    SingleDomain,
    SubjectAlternativeNames
}

public sealed record PreflightCheckResult
{
    public required string Id { get; init; }

    public required PreflightPhase Phase { get; init; }

    public required string Category { get; init; }

    public required string Title { get; init; }

    public required CheckStatus Status { get; init; }

    public required string Summary { get; init; }

    public string? Remediation { get; init; }

    public string? DomainName { get; init; }

    public bool IsRequired { get; init; } = true;

    public bool RequiresUserConfirmation { get; init; }

    public DateTimeOffset CheckedAt { get; init; } = DateTimeOffset.Now;

    public TimeSpan Duration { get; init; }

    public IReadOnlyDictionary<string, string> Details { get; init; } =
        new ReadOnlyDictionary<string, string>(new Dictionary<string, string>());

    public bool IsBlockingFailure => IsRequired && Status == CheckStatus.Failed;
}

public sealed record PreflightReport
{
    public required DateTimeOffset StartedAt { get; init; }

    public required DateTimeOffset CompletedAt { get; init; }

    public required IReadOnlyList<PreflightCheckResult> Checks { get; init; }

    public bool HasBlockingFailures => Checks.Any(check => check.IsBlockingFailure);

    public bool RequiresManualConfirmation => Checks.Any(
        check => check.Status == CheckStatus.Warning && check.RequiresUserConfirmation);

    /// <summary>
    /// Indicates that the public checks found no hard failure. Warnings that require
    /// confirmation must still be acknowledged by the UI before elevation.
    /// </summary>
    public bool CanRequestElevation => !HasBlockingFailures;

    public TimeSpan Duration => CompletedAt - StartedAt;
}

public sealed record PublicPreflightRequest
{
    public required IReadOnlyList<string> DomainNames { get; init; }

    public CertificateNameMode NameMode { get; init; } = CertificateNameMode.SingleDomain;

    public Uri ProductionAcmeDirectory { get; init; } =
        new("https://acme-v02.api.letsencrypt.org/directory");

    public Uri StagingAcmeDirectory { get; init; } =
        new("https://acme-staging-v02.api.letsencrypt.org/directory");

    public IReadOnlyList<IPAddress> ExpectedPublicAddresses { get; init; } = Array.Empty<IPAddress>();

    public TimeSpan PerCheckTimeout { get; init; } = TimeSpan.FromSeconds(15);

    public bool CheckStagingDirectory { get; init; } = true;
}
