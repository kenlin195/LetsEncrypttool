using System.Text.Json;
using Mstech.IisSslManager.Infrastructure;
using Mstech.IisSslManager.Models;

namespace Mstech.IisSslManager.Services;

public sealed class ApplicationSettings
{
    public string? WinAcmePath { get; set; }

    public string ContactEmail { get; set; } = string.Empty;

    public long? SelectedSiteId { get; set; }

    public CertificateNameMode NameMode { get; set; } = CertificateNameMode.SingleDomain;

    public List<string> DomainNames { get; set; } = [];

    public bool TermsAccepted { get; set; }

    public bool CertificateTransparencyAcknowledged { get; set; }

    public bool KeepPreviousCertificate { get; set; } = true;

    public int PreviousCertificateRetentionDays { get; set; } = 30;

    public DateTimeOffset? LastPublicCheckAt { get; set; }

    public DateTimeOffset? LastStagingCheckAt { get; set; }
}

public sealed class ApplicationSettingsService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    public async Task<ApplicationSettings> LoadAsync(CancellationToken cancellationToken = default)
    {
        var path = AppPaths.SettingsFile;
        if (!File.Exists(path))
        {
            return new ApplicationSettings();
        }

        try
        {
            await using var stream = File.OpenRead(path);
            return await JsonSerializer.DeserializeAsync<ApplicationSettings>(stream, JsonOptions, cancellationToken)
                ?? new ApplicationSettings();
        }
        catch
        {
            return new ApplicationSettings();
        }
    }

    public async Task SaveAsync(ApplicationSettings settings, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(settings);

        var path = AppPaths.SettingsFile;
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);

        var temporaryPath = path + ".tmp";
        await using (var stream = new FileStream(
            temporaryPath,
            FileMode.Create,
            FileAccess.Write,
            FileShare.None,
            4096,
            FileOptions.WriteThrough))
        {
            await JsonSerializer.SerializeAsync(stream, settings, JsonOptions, cancellationToken);
            await stream.FlushAsync(cancellationToken);
        }

        File.Move(temporaryPath, path, true);
    }
}
