using System.Collections;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Mstech.IisSslManager.Core;

namespace Mstech.IisSslManager.Services;

public sealed record IisCertificateBindingVerificationResult
{
    public required bool Success { get; init; }

    public string? NewCertificateThumbprint { get; init; }

    public bool CertificateWasNew { get; init; }

    public required string Summary { get; init; }
}

/// <summary>
/// Verifies that a production issuance created a new WebHosting certificate and
/// that every requested host binding on the selected IIS site uses that exact
/// certificate with SNI enabled. Microsoft.Web.Administration is loaded from the
/// IIS installation at runtime so the application can still be built on a
/// workstation where IIS is not installed.
/// </summary>
public sealed class IisCertificateBindingVerifier
{
    private const int SniSslFlag = 1;
    private const string WebHostingStoreName = "WebHosting";

    public IReadOnlySet<string> SnapshotWebHostingThumbprints()
    {
        using var store = new X509Store(WebHostingStoreName, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        return store.Certificates
            .Select(certificate => NormalizeThumbprint(certificate.Thumbprint))
            .Where(thumbprint => thumbprint.Length > 0)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
    }

    public IisCertificateBindingVerificationResult VerifyAfterIssuance(
        long selectedSiteId,
        IReadOnlyList<string> expectedHostNames,
        IReadOnlySet<string> thumbprintsBeforeIssuance)
    {
        ArgumentNullException.ThrowIfNull(expectedHostNames);
        ArgumentNullException.ThrowIfNull(thumbprintsBeforeIssuance);

        var expectedHosts = expectedHostNames
            .Select(NormalizeHostName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (selectedSiteId <= 0 || expectedHosts.Length == 0)
        {
            return Failed("簽發後驗證缺少有效的 IIS Site ID 或網域名稱。");
        }

        var candidates = FindMatchingCertificates(expectedHosts);
        var newCandidates = candidates
            .Where(candidate => !thumbprintsBeforeIssuance.Contains(candidate.Thumbprint))
            .ToArray();
        if (newCandidates.Length > 1)
        {
            return Failed(
                "WebHosting 中同時出現多張符合本次申請名稱的新憑證；為避免將 IIS 綁到錯誤憑證，已停止並要求人工檢查。");
        }

        var bindings = ReadIisHttpsBindings(selectedSiteId);
        var boundThumbprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var host in expectedHosts)
        {
            var matches = bindings
                .Where(binding =>
                    binding.Port == 443 &&
                    binding.HostName.Equals(host, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            if (matches.Length == 0)
            {
                return Failed($"找不到預期的 IIS HTTPS Binding：{host}:443。");
            }

            foreach (var binding in matches)
            {
                if (binding.CertificateThumbprint.Length == 0)
                {
                    return Failed(
                        $"IIS HTTPS Binding {host}:443 沒有可驗證的憑證指紋。");
                }

                if (!string.Equals(
                        binding.CertificateStoreName,
                        WebHostingStoreName,
                        StringComparison.OrdinalIgnoreCase))
                {
                    return Failed(
                        $"IIS HTTPS Binding {host}:443 的憑證存放區不是 LocalMachine\\WebHosting。",
                        binding.CertificateThumbprint);
                }

                if ((binding.SslFlags & SniSslFlag) == 0)
                {
                    return Failed(
                        $"IIS HTTPS Binding {host}:443 未啟用 SNI。",
                        binding.CertificateThumbprint);
                }

                boundThumbprints.Add(binding.CertificateThumbprint);
            }
        }

        if (boundThumbprints.Count != 1)
        {
            return Failed(
                "所有預期 IIS HTTPS Binding 沒有共同綁定到同一張憑證，已拒絕接受不一致的狀態。");
        }

        var boundThumbprint = boundThumbprints.Single();
        var boundCandidate = candidates.SingleOrDefault(candidate =>
            candidate.Thumbprint.Equals(boundThumbprint, StringComparison.OrdinalIgnoreCase));
        if (boundCandidate is null)
        {
            return Failed(
                "IIS 綁定的憑證不是 WebHosting 中有效、含私鑰且 SAN 完整覆蓋本次申請名稱的候選。",
                boundThumbprint);
        }

        var certificateWasNew = newCandidates.Length == 1;
        if (certificateWasNew &&
            !newCandidates[0].Thumbprint.Equals(boundThumbprint, StringComparison.OrdinalIgnoreCase))
        {
            return Failed(
                "本次新增的憑證未被所有預期 IIS HTTPS Binding 使用，已拒絕接受既有憑證綁定。",
                newCandidates[0].Thumbprint);
        }

        return new IisCertificateBindingVerificationResult
        {
            Success = true,
            NewCertificateThumbprint = boundThumbprint,
            CertificateWasNew = certificateWasNew,
            Summary = certificateWasNew
                ? $"所有預期 IIS HTTPS Binding 均使用本次新憑證 {boundThumbprint}、WebHosting 存放區且已啟用 SNI。"
                : $"未發現唯一新增憑證；已安全確認所有預期 IIS HTTPS Binding 共同使用既有憑證 {boundThumbprint}、WebHosting 存放區且已啟用 SNI。"
        };
    }

    private static IReadOnlyList<WebHostingCertificateState> FindMatchingCertificates(
        IReadOnlyList<string> expectedHosts)
    {
        using var store = new X509Store(WebHostingStoreName, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

        var now = DateTime.UtcNow;
        var matches = new Dictionary<string, WebHostingCertificateState>(
            StringComparer.OrdinalIgnoreCase);
        foreach (var certificate in store.Certificates)
        {
            var thumbprint = NormalizeThumbprint(certificate.Thumbprint);
            if (thumbprint.Length == 0 ||
                !certificate.HasPrivateKey ||
                certificate.NotBefore.ToUniversalTime() > now ||
                certificate.NotAfter.ToUniversalTime() <= now)
            {
                continue;
            }

            var dnsNames = ReadDnsNames(certificate);
            if (expectedHosts.All(host => dnsNames.Contains(host)))
            {
                matches.TryAdd(thumbprint, new WebHostingCertificateState(thumbprint));
            }
        }

        return matches.Values.ToArray();
    }

    private static HashSet<string> ReadDnsNames(X509Certificate2 certificate)
    {
        var result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var extension = certificate.Extensions["2.5.29.17"];
        if (extension is null)
        {
            return result;
        }

        var subjectAlternativeName = extension as X509SubjectAlternativeNameExtension ??
            new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical);
        foreach (var dnsName in subjectAlternativeName.EnumerateDnsNames())
        {
            var normalized = NormalizeHostName(dnsName);
            if (normalized.Length > 0)
            {
                result.Add(normalized);
            }
        }

        return result;
    }

    private static IReadOnlyList<IisHttpsBindingState> ReadIisHttpsBindings(long selectedSiteId)
    {
        var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var assemblyPath = Path.Combine(
            windowsDirectory,
            "System32",
            "inetsrv",
            "Microsoft.Web.Administration.dll");
        if (!File.Exists(assemblyPath))
        {
            throw new FileNotFoundException(
                "找不到 Microsoft.Web.Administration.dll，無法驗證 IIS 憑證綁定。",
                assemblyPath);
        }

        var assembly = Assembly.LoadFrom(assemblyPath);
        var serverManagerType = assembly.GetType(
            "Microsoft.Web.Administration.ServerManager",
            throwOnError: true,
            ignoreCase: false)!;
        var serverManager = Activator.CreateInstance(serverManagerType)
            ?? throw new InvalidOperationException("無法建立 IIS ServerManager。");

        try
        {
            var sites = GetRequiredProperty(serverManager, "Sites") as IEnumerable
                ?? throw new InvalidOperationException("無法讀取 IIS Sites 集合。");
            foreach (var site in sites)
            {
                if (site is null ||
                    Convert.ToInt64(
                        GetRequiredProperty(site, "Id"),
                        CultureInfo.InvariantCulture) != selectedSiteId)
                {
                    continue;
                }

                var bindings = GetRequiredProperty(site, "Bindings") as IEnumerable
                    ?? throw new InvalidOperationException("無法讀取 IIS Bindings 集合。");
                var result = new List<IisHttpsBindingState>();
                foreach (var binding in bindings)
                {
                    if (binding is null ||
                        !string.Equals(
                            Convert.ToString(
                                GetRequiredProperty(binding, "Protocol"),
                                CultureInfo.InvariantCulture),
                            "https",
                            StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var bindingInformation = Convert.ToString(
                        GetRequiredProperty(binding, "BindingInformation"),
                        CultureInfo.InvariantCulture) ?? string.Empty;
                    var parsed = IisDiscoveryService.ParseBindings($"https/{bindingInformation}")
                        .SingleOrDefault()
                        ?? throw new InvalidOperationException(
                            $"無法解析 IIS HTTPS Binding：{bindingInformation}");
                    var certificateHash = GetPropertyValue(binding, "CertificateHash") as byte[];
                    var certificateStoreName = Convert.ToString(
                        GetPropertyValue(binding, "CertificateStoreName"),
                        CultureInfo.InvariantCulture);
                    var sslFlags = Convert.ToInt32(
                        GetRequiredProperty(binding, "SslFlags"),
                        CultureInfo.InvariantCulture);

                    result.Add(new IisHttpsBindingState(
                        parsed.Port,
                        NormalizeHostName(parsed.HostName),
                        certificateHash is null ? string.Empty : Convert.ToHexString(certificateHash),
                        certificateStoreName,
                        sslFlags));
                }

                return result;
            }

            throw new InvalidOperationException($"找不到 IIS Site ID {selectedSiteId}。");
        }
        finally
        {
            if (serverManager is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }

    private static object GetRequiredProperty(object instance, string propertyName) =>
        GetPropertyValue(instance, propertyName)
        ?? throw new InvalidOperationException(
            $"IIS 管理 API 屬性 {instance.GetType().FullName}.{propertyName} 沒有值。");

    private static object? GetPropertyValue(object instance, string propertyName)
    {
        var property = instance.GetType().GetProperty(
            propertyName,
            BindingFlags.Instance | BindingFlags.Public)
            ?? throw new InvalidOperationException(
                $"IIS 管理 API 缺少必要屬性 {instance.GetType().FullName}.{propertyName}。");
        return property.GetValue(instance);
    }

    private static string NormalizeThumbprint(string? value) =>
        string.Concat((value ?? string.Empty).Where(Uri.IsHexDigit)).ToUpperInvariant();

    private static string NormalizeHostName(string? value) =>
        (value ?? string.Empty).Trim().TrimEnd('.').ToLowerInvariant();

    private static IisCertificateBindingVerificationResult Failed(
        string summary,
        string? newThumbprint = null) => new()
        {
            Success = false,
            NewCertificateThumbprint = newThumbprint,
            Summary = summary
        };

    private sealed record WebHostingCertificateState(string Thumbprint);

    private sealed record IisHttpsBindingState(
        int Port,
        string HostName,
        string CertificateThumbprint,
        string? CertificateStoreName,
        int SslFlags);
}
