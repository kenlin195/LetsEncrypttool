namespace Mstech.IisSslManager.Models;

/// <summary>
/// Serializable input passed to the elevated application instance. It intentionally
/// contains no administrator password, ACME account key, PFX password, or DNS token.
/// </summary>
public sealed record LocalPreflightRequest
{
    public long SelectedSiteId { get; init; }

    public string SelectedSiteName { get; init; } = string.Empty;

    public List<string> DomainNames { get; init; } = [];

    public string WinAcmePath { get; init; } = string.Empty;

    /// <summary>
    /// SHA-256 of the tested win-acme binary. Leave empty only when the user selects
    /// a manually supplied copy; the integrity check will then remain a warning.
    /// </summary>
    public string? ExpectedWinAcmeSha256 { get; init; }

    public int? RequiredRsaKeyBits { get; init; } = 2048;

    public bool RequireStartedSite { get; init; } = true;
}
