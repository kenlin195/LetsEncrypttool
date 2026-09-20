using System.Globalization;
using System.IO;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Mstech.IisSslManager.Infrastructure;

namespace Mstech.IisSslManager.Services;

/// <summary>
/// Produces unattended win-acme commands from validated values. Arguments remain
/// separate values all the way to ProcessStartInfo.ArgumentList; they are never
/// concatenated into a shell command.
/// </summary>
public sealed partial class WinAcmeCommandBuilder
{
    private const int MaximumSanNames = 100;

    public WinAcmeCommand BuildStagingValidation(WinAcmeCertificateRequest request)
    {
        var validated = Validate(request);
        var arguments = BuildCertificateArguments(validated, "MSTECH Staging");

        var stagingDirectory = Path.Combine(
            AppPaths.SecureStagingDirectory,
            Guid.NewGuid().ToString("N"));
        var randomPfxPassword = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

        // --test selects Let's Encrypt staging. The PFX is written to a unique
        // temporary directory and removed immediately after the run. The None
        // installation plugin guarantees that no IIS binding is created or changed.
        arguments.Insert(0, "--test");
        AddPair(arguments, "--store", "pfxfile");
        AddPair(arguments, "--pfxfilepath", stagingDirectory);
        AddPair(arguments, "--pfxpassword", randomPfxPassword);
        AddPair(arguments, "--installation", "none");
        arguments.Add("--notaskscheduler");
        arguments.Add("--closeonfinish");

        return WinAcmeCommand.Create(
            WinAcmeCommandKind.StagingValidation,
            arguments,
            requiresAdministrator: true,
            changesIisBindings: false,
            usesStagingEnvironment: true,
            completionOutputMarker: WinAcmeRecommendedRelease.StagingCompletionOutputMarker,
            temporaryDirectoriesToDelete: [stagingDirectory]);
    }

    public WinAcmeCommand BuildProductionIssuance(
        WinAcmeCertificateRequest request,
        string? certificateRetentionScriptPath = null)
    {
        var validated = Validate(request);
        var arguments = BuildCertificateArguments(validated, "MSTECH IIS SSL");

        AddPair(arguments, "--id", CreateProductionRenewalId(validated.SiteId));
        AddPair(arguments, "--baseuri", WinAcmeRecommendedRelease.ProductionBaseUri);
        AddPair(arguments, "--store", "certificatestore");
        AddPair(arguments, "--certificatestore", "WebHosting");
        arguments.Add("--nocache");
        arguments.Add("--keepexisting");
        var installation = string.IsNullOrWhiteSpace(certificateRetentionScriptPath)
            ? "iis"
            : "iis,script";
        AddPair(arguments, "--installation", installation);
        AddPair(arguments, "--installationsiteid", validated.SiteId.ToString(CultureInfo.InvariantCulture));
        AddPair(arguments, "--sslport", "443");
        AddPair(arguments, "--sslipaddress", "*");
        if (!string.IsNullOrWhiteSpace(certificateRetentionScriptPath))
        {
            var scriptPath = Path.GetFullPath(certificateRetentionScriptPath);
            AddPair(arguments, "--script", scriptPath);
            AddPair(
                arguments,
                "--scriptparameters",
                $"-OldThumbprint \"{{OldCertThumbprint}}\" -NewThumbprint \"{{CertThumbprint}}\" -RetentionDays {CertificateRetentionService.RetentionDays}");
        }

        // The elevated dispatcher creates/updates the SYSTEM task only after it
        // has independently verified the renewal file and every IIS binding.
        arguments.Add("--notaskscheduler");
        return WinAcmeCommand.Create(
            WinAcmeCommandKind.ProductionIssuance,
            arguments,
            requiresAdministrator: true,
            changesIisBindings: true,
            usesStagingEnvironment: false);
    }

    public string GetProductionRenewalId(WinAcmeCertificateRequest request)
    {
        var validated = Validate(request);
        return CreateProductionRenewalId(validated.SiteId);
    }

    public WinAcmeCommand BuildRenewalCheck(bool force = false, string? renewalId = null)
    {
        var arguments = new List<string> { "--renew" };
        if (force)
        {
            arguments.Add("--force");
        }

        if (!string.IsNullOrWhiteSpace(renewalId))
        {
            AddPair(arguments, "--id", ValidateOpaqueValue(renewalId, nameof(renewalId), 128));
        }

        arguments.Add("--verbose");
        return WinAcmeCommand.Create(
            force ? WinAcmeCommandKind.ForcedRenewal : WinAcmeCommandKind.RenewalCheck,
            arguments,
            requiresAdministrator: true,
            changesIisBindings: true);
    }

    public WinAcmeCommand BuildListRenewals() => WinAcmeCommand.Create(
        WinAcmeCommandKind.ListRenewals,
        ["--list"],
        requiresAdministrator: false);

    public WinAcmeCommand BuildSetupTaskScheduler() => WinAcmeCommand.Create(
        WinAcmeCommandKind.SetupTaskScheduler,
        ["--setuptaskscheduler"],
        requiresAdministrator: true);

    public WinAcmeCommand BuildVersionCheck() => WinAcmeCommand.Create(
        WinAcmeCommandKind.Version,
        ["--version"],
        requiresAdministrator: false);

    private static List<string> BuildCertificateArguments(
        ValidatedRequest request,
        string friendlyNamePrefix)
    {
        var arguments = new List<string>();
        // The manual source makes the requested identifier set explicit. This is
        // important when an IIS site uses a catch-all Port 80 binding or when the
        // HTTPS binding will be created for the first time. Installation remains
        // scoped to the selected IIS site through --installationsiteid.
        AddPair(arguments, "--source", "manual");
        AddPair(arguments, "--host", string.Join(',', request.HostNames));
        AddPair(arguments, "--commonname", request.CommonName);
        AddPair(arguments, "--validation", "selfhosting");
        AddPair(arguments, "--validationmode", "http-01");
        AddPair(arguments, "--order", "single");
        AddPair(arguments, "--csr", "rsa");
        AddPair(arguments, "--emailaddress", request.ContactEmail);
        arguments.Add("--accepttos");
        arguments.Add("--verbose");

        var friendlyName = request.FriendlyName ??
            $"{friendlyNamePrefix} - IIS {request.SiteId} - {request.CommonName}";
        AddPair(arguments, "--friendlyname", friendlyName);
        return arguments;
    }

    private static ValidatedRequest Validate(WinAcmeCertificateRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.SiteId <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request.SiteId), "IIS Site ID 必須大於 0。");
        }

        if (request.HostNames is null || request.HostNames.Count == 0)
        {
            throw new ArgumentException("至少需要一個網域名稱。", nameof(request.HostNames));
        }

        var hosts = request.HostNames
            .Select(NormalizeDnsName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (hosts.Length > MaximumSanNames)
        {
            throw new ArgumentException($"一張憑證最多可包含 {MaximumSanNames} 個名稱。", nameof(request.HostNames));
        }

        var commonName = string.IsNullOrWhiteSpace(request.CommonName)
            ? hosts[0]
            : NormalizeDnsName(request.CommonName);
        if (!hosts.Contains(commonName, StringComparer.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Common Name 必須包含在申請的網域清單中。", nameof(request.CommonName));
        }

        var email = ValidateEmail(request.ContactEmail);
        var friendlyName = string.IsNullOrWhiteSpace(request.FriendlyName)
            ? null
            : ValidateOpaqueValue(request.FriendlyName, nameof(request.FriendlyName), 200);

        return new ValidatedRequest(request.SiteId, hosts, commonName, email, friendlyName);
    }

    private static string NormalizeDnsName(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            throw new ArgumentException("網域名稱不可為空白。", nameof(input));
        }

        var trimmed = input.Trim().TrimEnd('.');
        if (trimmed.StartsWith("*.", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"{AppVersion.DisplayVersion} 僅支援一般網域與 SAN，不支援 Wildcard。",
                nameof(input));
        }

        string ascii;
        try
        {
            ascii = new IdnMapping().GetAscii(trimmed).ToLowerInvariant();
        }
        catch (ArgumentException exception)
        {
            throw new ArgumentException($"網域名稱格式錯誤：{input}", nameof(input), exception);
        }

        if (ascii.Length is < 1 or > 253 || !DnsNameRegex().IsMatch(ascii))
        {
            throw new ArgumentException($"網域名稱格式錯誤：{input}", nameof(input));
        }

        if (Uri.CheckHostName(ascii) != UriHostNameType.Dns || !ascii.Contains('.'))
        {
            throw new ArgumentException($"必須使用可公開解析的完整網域名稱：{input}", nameof(input));
        }

        return ascii;
    }

    private static string ValidateEmail(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            throw new ArgumentException("Let’s Encrypt 聯絡信箱不可為空白。", nameof(input));
        }

        var trimmed = input.Trim();
        try
        {
            var address = new MailAddress(trimmed);
            if (!string.Equals(address.Address, trimmed, StringComparison.OrdinalIgnoreCase) ||
                address.Host.Length == 0)
            {
                throw new FormatException();
            }

            return address.Address;
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("Let’s Encrypt 聯絡信箱格式不正確。", nameof(input), exception);
        }
    }

    private static string ValidateOpaqueValue(string value, string parameterName, int maximumLength)
    {
        var trimmed = value.Trim();
        if (trimmed.Length == 0 || trimmed.Length > maximumLength ||
            trimmed.Any(character => char.IsControl(character)))
        {
            throw new ArgumentException("參數包含不允許的字元或長度。", parameterName);
        }

        return trimmed;
    }

    private static void AddPair(List<string> arguments, string option, string value)
    {
        arguments.Add(option);
        arguments.Add(value);
    }

    private static string CreateProductionRenewalId(long siteId) =>
        $"mstech-iis-site-{siteId.ToString(CultureInfo.InvariantCulture)}";

    [GeneratedRegex(
        @"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
        RegexOptions.CultureInvariant)]
    private static partial Regex DnsNameRegex();

    private sealed record ValidatedRequest(
        long SiteId,
        IReadOnlyList<string> HostNames,
        string CommonName,
        string ContactEmail,
        string? FriendlyName);
}
