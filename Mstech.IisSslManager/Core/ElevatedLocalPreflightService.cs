using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text.Json;
using Mstech.IisSslManager.Models;

namespace Mstech.IisSslManager.Core;

public interface IElevatedLocalPreflightService
{
    Task<PreflightReport> RunAsync(
        LocalPreflightRequest request,
        IProgress<PreflightCheckResult>? progress = null,
        CancellationToken cancellationToken = default);
}

public sealed class ElevatedLocalPreflightService(IIisDiscoveryService iisDiscoveryService)
    : IElevatedLocalPreflightService
{
    public async Task<PreflightReport> RunAsync(
        LocalPreflightRequest request,
        IProgress<PreflightCheckResult>? progress = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        var startedAt = DateTimeOffset.Now;
        var checks = new List<PreflightCheckResult>();

        void Add(PreflightCheckResult result)
        {
            checks.Add(result);
            progress?.Report(result);
        }

        var isAdministrator = IsAdministrator();
        Add(LocalResult(
            id: "local-administrator",
            category: "權限",
            title: "Windows 系統管理員權限",
            status: isAdministrator ? CheckStatus.Passed : CheckStatus.Failed,
            summary: isAdministrator
                ? "目前程序已通過 Windows UAC，具備系統管理員權限。"
                : "目前程序沒有系統管理員權限，不能修改 IIS、憑證存放區或工作排程。",
            remediation: isAdministrator
                ? null
                : "請關閉此檢查，回到一般權限介面並透過 Windows UAC 重新執行；工具不會接收或保存管理員密碼。"));

        if (!isAdministrator)
        {
            return Report(startedAt, checks);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var inventory = await iisDiscoveryService.DiscoverAsync(cancellationToken).ConfigureAwait(false);
        Add(CheckIisInventory(inventory));

        var selectedSite = inventory.Sites.FirstOrDefault(site =>
            request.SelectedSiteId > 0
                ? site.Id == request.SelectedSiteId
                : site.Name.Equals(request.SelectedSiteName, StringComparison.OrdinalIgnoreCase));
        Add(CheckSelectedSite(request, selectedSite));

        foreach (var bindingCheck in CheckPort80Bindings(request, inventory, selectedSite))
        {
            Add(bindingCheck);
        }

        Add(CheckWindowsService("W3SVC", "IIS World Wide Web Publishing Service", requiredToBeRunning: true));
        Add(CheckWindowsService("HTTP", "Windows HTTP Service（HTTP.sys）", requiredToBeRunning: true));
        Add(CheckWindowsService("Schedule", "Windows Task Scheduler", requiredToBeRunning: true));
        Add(CheckWebHostingStore());
        Add(await CheckWinAcmeAsync(request, cancellationToken).ConfigureAwait(false));

        Add(new PreflightCheckResult
        {
            Id = "local-firewall-nat",
            Phase = PreflightPhase.ElevatedLocalEnvironment,
            Category = "網路",
            Title = "Windows Firewall／NAT／WAF 外部路徑",
            Status = CheckStatus.Warning,
            Summary = "本機檢查無法證明 Internet 的 TCP 80 一定會到達這台主機；NAT、Load Balancer、CDN 與外部防火牆可能位於伺服器之外。",
            Remediation = "請確認外部設備規則；正式簽發前必須通過 Let's Encrypt Staging HTTP-01，該外部驗證才是最終判定。",
            RequiresUserConfirmation = true,
            IsRequired = true
        });

        return Report(startedAt, checks);
    }

    private static PreflightCheckResult CheckIisInventory(IisInventory inventory)
    {
        if (!inventory.IsIisInstalled)
        {
            return LocalResult(
                id: "local-iis",
                category: "IIS",
                title: "IIS 管理工具",
                status: CheckStatus.Failed,
                summary: inventory.ErrorMessage ?? "未安裝 IIS。",
                remediation: "請安裝 IIS Web Server 與 IIS Management Tools（含 appcmd.exe）。");
        }

        if (inventory.ErrorMessage is not null)
        {
            return LocalResult(
                id: "local-iis",
                category: "IIS",
                title: "IIS 管理工具",
                status: CheckStatus.Failed,
                summary: inventory.ErrorMessage,
                remediation: "請確認 applicationHost.config 可讀，並檢查 IIS 管理設定。",
                details: new Dictionary<string, string> { ["AppCmd"] = inventory.AppCmdPath });
        }

        return LocalResult(
            id: "local-iis",
            category: "IIS",
            title: "IIS 管理工具",
            status: CheckStatus.Passed,
            summary: $"已讀取 IIS，共找到 {inventory.Sites.Count} 個網站。",
            details: new Dictionary<string, string> { ["AppCmd"] = inventory.AppCmdPath });
    }

    private static PreflightCheckResult CheckSelectedSite(
        LocalPreflightRequest request,
        IisSiteInfo? site)
    {
        if (site is null)
        {
            return LocalResult(
                id: "local-iis-site",
                category: "IIS",
                title: "選取的 IIS 網站",
                status: CheckStatus.Failed,
                summary: $"找不到 Site ID {request.SelectedSiteId}（{request.SelectedSiteName}）。",
                remediation: "IIS 設定可能已變更；請回到主畫面重新整理並重新選取網站。");
        }

        var status = request.RequireStartedSite && !site.IsStarted
            ? CheckStatus.Failed
            : CheckStatus.Passed;
        return LocalResult(
            id: "local-iis-site",
            category: "IIS",
            title: "選取的 IIS 網站",
            status: status,
            summary: status == CheckStatus.Passed
                ? $"網站 {site.Name}（ID {site.Id}）存在，狀態為 {site.State}。"
                : $"網站 {site.Name} 目前不是 Started 狀態。",
            remediation: status == CheckStatus.Passed ? null : "請先啟動網站，再重新執行檢查。",
            details: new Dictionary<string, string>
            {
                ["SiteId"] = site.Id.ToString(),
                ["SiteName"] = site.Name,
                ["State"] = site.State
            });
    }

    private static IReadOnlyList<PreflightCheckResult> CheckPort80Bindings(
        LocalPreflightRequest request,
        IisInventory inventory,
        IisSiteInfo? selectedSite)
    {
        var results = new List<PreflightCheckResult>();
        foreach (var rawDomain in request.DomainNames)
        {
            if (!DomainNameValidator.TryNormalize(rawDomain, out var domain, out var error))
            {
                results.Add(LocalResult(
                    id: $"local-binding:{rawDomain}",
                    category: "IIS Binding",
                    title: $"Port 80 Binding：{rawDomain}",
                    status: CheckStatus.Failed,
                    summary: error!,
                    remediation: "請修正網域清單後重新執行完整預檢。",
                    domainName: rawDomain));
                continue;
            }

            results.Add(CheckHttpsBinding(domain, inventory, selectedSite));

            var exactMatches = inventory.Sites
                .SelectMany(site => site.Bindings.Select(binding => (Site: site, Binding: binding)))
                .Where(item =>
                    item.Binding.Protocol.Equals("http", StringComparison.OrdinalIgnoreCase) &&
                    item.Binding.Port == 80 &&
                    item.Binding.HostName.Equals(domain, StringComparison.OrdinalIgnoreCase))
                .ToArray();
            var conflictingSites = exactMatches
                .Where(item => selectedSite is null || item.Site.Id != selectedSite.Id)
                .Select(item => $"{item.Site.Name} (ID {item.Site.Id})")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (conflictingSites.Length > 0)
            {
                results.Add(LocalResult(
                    id: $"local-binding:{domain}",
                    category: "IIS Binding",
                    title: $"Port 80 Binding：{domain}",
                    status: CheckStatus.Failed,
                    summary: $"相同 Host Header 已綁定至其他網站：{string.Join(", ", conflictingSites)}。",
                    remediation: "請先排除重複 Binding；工具不會自動刪除其他網站的設定。",
                    domainName: domain));
                continue;
            }

            var selectedExactMatch = exactMatches.Any(item =>
                selectedSite is not null && item.Site.Id == selectedSite.Id);
            var selectedCatchAll = selectedSite?.Bindings.Any(binding =>
                binding.Protocol.Equals("http", StringComparison.OrdinalIgnoreCase) &&
                binding.Port == 80 &&
                string.IsNullOrWhiteSpace(binding.HostName)) == true;

            if (selectedExactMatch || selectedCatchAll)
            {
                results.Add(LocalResult(
                    id: $"local-binding:{domain}",
                    category: "IIS Binding",
                    title: $"Port 80 Binding：{domain}",
                    status: CheckStatus.Passed,
                    summary: selectedExactMatch
                        ? "選取的網站具有相符的 Port 80 Host Header。"
                        : "選取的網站具有 Port 80 Catch-all Binding；仍須由 Staging 確認外部路由。",
                    domainName: domain));
            }
            else
            {
                results.Add(LocalResult(
                    id: $"local-binding:{domain}",
                    category: "IIS Binding",
                    title: $"Port 80 Binding：{domain}",
                    status: CheckStatus.Warning,
                    summary: "選取的網站沒有相符的 Port 80 Binding。win-acme SelfHosting 可能仍可驗證，但網站對應關係無法由 IIS 清單確認。",
                    remediation: "建議由使用者確認後建立 `*:80:<網域>` Binding，或保留現況並強制通過 Staging。",
                    domainName: domain,
                    requiresConfirmation: true));
            }
        }

        return results;
    }

    internal static PreflightCheckResult CheckHttpsBinding(
        string domain,
        IisInventory inventory,
        IisSiteInfo? selectedSite)
    {
        if (selectedSite is null)
        {
            return LocalResult(
                id: $"local-https-binding:{domain}",
                category: "IIS Binding",
                title: $"Port 443 Binding：{domain}",
                status: CheckStatus.Failed,
                summary: "無法確認 HTTPS Binding，因為選取的網站不存在。",
                domainName: domain);
        }

        var exactMatches = inventory.Sites
            .SelectMany(site => site.Bindings.Select(binding => (Site: site, Binding: binding)))
            .Where(item =>
                item.Binding.Protocol.Equals("https", StringComparison.OrdinalIgnoreCase) &&
                item.Binding.Port == 443 &&
                item.Binding.HostName.Equals(domain, StringComparison.OrdinalIgnoreCase))
            .ToArray();
        var otherSites = exactMatches
            .Where(item => item.Site.Id != selectedSite.Id)
            .Select(item => $"{item.Site.Name} (ID {item.Site.Id})")
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (otherSites.Length > 0)
        {
            return LocalResult(
                id: $"local-https-binding:{domain}",
                category: "IIS Binding",
                title: $"Port 443 Binding：{domain}",
                status: CheckStatus.Failed,
                summary: $"相同 HTTPS Host Header 已存在於其他網站：{string.Join(", ", otherSites)}。",
                remediation: "為避免 win-acme 更新到非選取站台，請先排除跨站台的相同 HTTPS Host Header。",
                domainName: domain);
        }

        var selectedBindings = exactMatches
            .Where(item => item.Site.Id == selectedSite.Id)
            .Select(item => item.Binding)
            .ToArray();
        var details = new Dictionary<string, string>
        {
            ["SiteId"] = selectedSite.Id.ToString(),
            ["SiteName"] = selectedSite.Name,
            ["SslFlags"] = selectedBindings.Length == 0
                ? "(新增 Binding)"
                : string.Join("；", selectedBindings.Select(binding =>
                    $"{binding.RawValue} = {binding.SslFlags?.ToString() ?? "未知"}"))
        };
        if (selectedBindings.Any(binding => binding.SslFlags is null or < 0))
        {
            if (!string.IsNullOrWhiteSpace(inventory.SslFlagsReadError))
            {
                details["ReadError"] = inventory.SslFlagsReadError;
            }

            return LocalResult(
                id: $"local-https-binding:{domain}",
                category: "IIS Binding",
                title: $"Port 443 Binding：{domain}",
                status: CheckStatus.Failed,
                summary: "無法確認既有 HTTPS Binding 的 SNI／CCS 設定，已停止後續申請。",
                remediation: "請確認 IIS 管理工具已安裝且管理員可讀取 IIS 設定，再重新執行本機檢查；若檢查期間 Binding 有變更，也必須重驗。",
                domainName: domain,
                details: details);
        }

        if (selectedBindings.Any(binding => (binding.SslFlags!.Value & 2) != 0))
        {
            return LocalResult(
                id: $"local-https-binding:{domain}",
                category: "IIS Binding",
                title: $"Port 443 Binding：{domain}",
                status: CheckStatus.Failed,
                summary: "既有 HTTPS Binding 使用 Central Certificate Store（CCS），不在本工具支援範圍。",
                remediation: "本工具只支援 LocalMachine\\WebHosting 憑證存放區。請由 IIS 管理員評估並手動調整此 Binding，確認服務正常後重新檢查；工具不會自動停用 CCS。",
                domainName: domain,
                details: details);
        }

        if (selectedBindings.Any(binding => (binding.SslFlags!.Value & 1) == 0))
        {
            return LocalResult(
                id: $"local-https-binding:{domain}",
                category: "IIS Binding",
                title: $"Port 443 Binding：{domain}",
                status: CheckStatus.Failed,
                summary: "既有 HTTPS Binding 尚未啟用 SNI，無法符合正式憑證安裝的驗證條件。",
                remediation: "請在 IIS 管理員確認此網域的 HTTPS 主機名稱，並手動啟用「需要伺服器名稱指示（SNI）」；確認服務正常後重新檢查，工具不會自動修改既有 SNI 設定。",
                domainName: domain,
                details: details);
        }

        var existsOnSelectedSite = selectedBindings.Length > 0;
        details["Action"] = existsOnSelectedSite ? "Update" : "Create";
        return LocalResult(
            id: $"local-https-binding:{domain}",
            category: "IIS Binding",
            title: $"Port 443 Binding：{domain}",
            status: CheckStatus.Warning,
            summary: existsOnSelectedSite
                ? "選取網站已有相符且啟用 SNI 的 HTTPS Binding，未使用 CCS；正式簽發會將它更新為新憑證。"
                : "選取網站尚無相符的 HTTPS Binding；正式簽發會建立新的 SNI Port 443 Binding。",
            remediation: "請在正式簽發預覽中確認站台、主機名稱與 Port 443 變更。",
            domainName: domain,
            requiresConfirmation: true,
            details: details);
    }

    private static PreflightCheckResult CheckWindowsService(
        string serviceName,
        string displayName,
        bool requiredToBeRunning)
    {
        var query = NativeServiceQuery.TryGetState(serviceName);
        if (query.ErrorMessage is not null)
        {
            return LocalResult(
                id: $"local-service:{serviceName}",
                category: "Windows 服務",
                title: displayName,
                status: CheckStatus.Failed,
                summary: query.ErrorMessage,
                remediation: $"請確認已安裝並可存取 {serviceName} 服務。",
                details: new Dictionary<string, string> { ["ServiceName"] = serviceName });
        }

        var passed = !requiredToBeRunning || query.State == ServiceCurrentState.Running;
        return LocalResult(
            id: $"local-service:{serviceName}",
            category: "Windows 服務",
            title: displayName,
            status: passed ? CheckStatus.Passed : CheckStatus.Failed,
            summary: passed
                ? $"{displayName} 正在執行。"
                : $"{displayName} 目前狀態為 {query.State}。",
            remediation: passed ? null : $"請將 {serviceName} 啟動類型設為可用並啟動服務。",
            details: new Dictionary<string, string>
            {
                ["ServiceName"] = serviceName,
                ["State"] = query.State.ToString()
            });
    }

    private static PreflightCheckResult CheckWebHostingStore()
    {
        try
        {
            using var store = new X509Store("WebHosting", StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            var count = store.Certificates.Count;
            return LocalResult(
                id: "local-certificate-store",
                category: "憑證",
                title: "LocalMachine\\WebHosting 存放區",
                status: CheckStatus.Passed,
                summary: "可用讀寫模式開啟 WebHosting 憑證存放區。",
                details: new Dictionary<string, string> { ["CertificateCount"] = count.ToString() });
        }
        catch (Exception exception) when (
            exception is CryptographicException or UnauthorizedAccessException)
        {
            return LocalResult(
                id: "local-certificate-store",
                category: "憑證",
                title: "LocalMachine\\WebHosting 存放區",
                status: CheckStatus.Failed,
                summary: $"無法以讀寫模式開啟憑證存放區：{exception.Message}",
                remediation: "請確認目前程序已提升權限，且群組原則未禁止寫入本機電腦憑證存放區。");
        }
    }

    private static async Task<PreflightCheckResult> CheckWinAcmeAsync(
        LocalPreflightRequest request,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(request.WinAcmePath))
        {
            return LocalResult(
                id: "local-win-acme",
                category: "win-acme",
                title: "wacs.exe 完整性",
                status: CheckStatus.Failed,
                summary: "尚未指定 wacs.exe。",
                remediation: "請下載工具建議版本，或選擇既有的 wacs.exe。不能從網路共用位置執行。" );
        }

        string path;
        try
        {
            path = Path.GetFullPath(request.WinAcmePath.Trim().Trim('"'));
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return LocalResult(
                id: "local-win-acme",
                category: "win-acme",
                title: "wacs.exe 完整性",
                status: CheckStatus.Failed,
                summary: $"wacs.exe 路徑無效：{exception.Message}");
        }

        if (path.StartsWith(@"\\", StringComparison.Ordinal) || !File.Exists(path))
        {
            return LocalResult(
                id: "local-win-acme",
                category: "win-acme",
                title: "wacs.exe 完整性",
                status: CheckStatus.Failed,
                summary: path.StartsWith(@"\\", StringComparison.Ordinal)
                    ? "安全考量下，不允許從 UNC 網路共用執行 wacs.exe。"
                    : "找不到指定的 wacs.exe。",
                remediation: "請將經驗證的 win-acme 放在本機固定目錄。",
                details: new Dictionary<string, string> { ["Path"] = path });
        }

        if (!Path.GetFileName(path).Equals("wacs.exe", StringComparison.OrdinalIgnoreCase))
        {
            return LocalResult(
                id: "local-win-acme",
                category: "win-acme",
                title: "wacs.exe 完整性",
                status: CheckStatus.Failed,
                summary: "選取的檔案名稱不是 wacs.exe。",
                remediation: "請選擇 win-acme 官方套件中的 wacs.exe。",
                details: new Dictionary<string, string> { ["Path"] = path });
        }

        try
        {
            await using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 64 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            var mz = new byte[2];
            if (await stream.ReadAsync(mz, cancellationToken).ConfigureAwait(false) != 2 ||
                mz[0] != (byte)'M' || mz[1] != (byte)'Z')
            {
                return LocalResult(
                    id: "local-win-acme",
                    category: "win-acme",
                    title: "wacs.exe 完整性",
                    status: CheckStatus.Failed,
                    summary: "檔案不是有效的 Windows PE 執行檔。",
                    details: new Dictionary<string, string> { ["Path"] = path });
            }

            stream.Position = 0;
            var hashBytes = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
            var actualHash = Convert.ToHexString(hashBytes);
            var expectedHash = NormalizeSha256(request.ExpectedWinAcmeSha256);
            var version = FileVersionInfo.GetVersionInfo(path);
            var details = new Dictionary<string, string>
            {
                ["Path"] = path,
                ["SHA256"] = actualHash,
                ["FileVersion"] = version.FileVersion ?? "(未知)",
                ["ProductName"] = version.ProductName ?? "(未知)"
            };

            if (!string.IsNullOrWhiteSpace(request.ExpectedWinAcmeSha256) && expectedHash is null)
            {
                return LocalResult(
                    id: "local-win-acme",
                    category: "win-acme",
                    title: "wacs.exe 完整性",
                    status: CheckStatus.Failed,
                    summary: "設定中的信任 SHA-256 格式無效，無法安全比對檔案。",
                    remediation: "請重新下載建議版本或修正應用程式的固定 SHA-256 設定。",
                    details: details);
            }

            if (expectedHash is not null && !actualHash.Equals(expectedHash, StringComparison.OrdinalIgnoreCase))
            {
                return LocalResult(
                    id: "local-win-acme",
                    category: "win-acme",
                    title: "wacs.exe 完整性",
                    status: CheckStatus.Failed,
                    summary: "wacs.exe 的 SHA-256 與工具信任的版本不符。",
                    remediation: "請勿執行此檔案；重新下載工具建議版本並再次驗證。",
                    details: details);
            }

            if (request.RequiredRsaKeyBits is { } requiredBits)
            {
                var settingsPath = Path.Combine(Path.GetDirectoryName(path)!, "settings.json");
                var configuredBits = TryReadRsaKeyBits(settingsPath);
                details["RsaKeyBits"] = configuredBits?.ToString() ?? "(未設定)";
                if (configuredBits != requiredBits)
                {
                    return LocalResult(
                        id: "local-win-acme",
                        category: "win-acme",
                        title: "wacs.exe 完整性與 RSA 設定",
                        status: CheckStatus.Failed,
                        summary: $"win-acme RSA 設定不是工具要求的 {requiredBits}-bit（目前：{configuredBits?.ToString() ?? "無法確認"}）。",
                        remediation: "請使用『下載建議版本』；工具管理版本會建立獨立 settings.json，不修改其他既有 win-acme 環境。",
                        details: details);
                }
            }

            return LocalResult(
                id: "local-win-acme",
                category: "win-acme",
                title: "wacs.exe 完整性",
                status: expectedHash is null ? CheckStatus.Warning : CheckStatus.Passed,
                summary: expectedHash is null
                    ? "檔案可讀且為 Windows 執行檔，但自行提供的版本沒有可信任 SHA-256 可供比對。"
                    : "wacs.exe 的 SHA-256 符合工具信任值。",
                remediation: expectedHash is null
                    ? "請由管理員核對官方來源與 SHA-256；建議改用工具下載的固定測試版本。"
                    : null,
                requiresConfirmation: expectedHash is null,
                details: details);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or CryptographicException)
        {
            return LocalResult(
                id: "local-win-acme",
                category: "win-acme",
                title: "wacs.exe 完整性",
                status: CheckStatus.Failed,
                summary: $"無法讀取或驗證 wacs.exe：{exception.Message}",
                remediation: "請檢查檔案權限、端點防護隔離狀態與磁碟內容。",
                details: new Dictionary<string, string> { ["Path"] = path });
        }
    }

    private static int? TryReadRsaKeyBits(string settingsPath)
    {
        try
        {
            if (!File.Exists(settingsPath))
            {
                return null;
            }

            using var document = JsonDocument.Parse(File.ReadAllText(settingsPath));
            return document.RootElement.GetProperty("Csr")
                .GetProperty("Rsa")
                .GetProperty("KeyBits")
                .GetInt32();
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or
            KeyNotFoundException or InvalidOperationException)
        {
            return null;
        }
    }

    private static bool IsAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static string? NormalizeSha256(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var normalized = value.Replace("-", string.Empty, StringComparison.Ordinal).Trim();
        return normalized.Length == 64 && normalized.All(Uri.IsHexDigit)
            ? normalized.ToUpperInvariant()
            : null;
    }

    private static PreflightReport Report(
        DateTimeOffset startedAt,
        IReadOnlyList<PreflightCheckResult> checks) => new()
    {
        StartedAt = startedAt,
        CompletedAt = DateTimeOffset.Now,
        Checks = checks
    };

    private static PreflightCheckResult LocalResult(
        string id,
        string category,
        string title,
        CheckStatus status,
        string summary,
        string? remediation = null,
        string? domainName = null,
        bool requiresConfirmation = false,
        IReadOnlyDictionary<string, string>? details = null) => new()
    {
        Id = id,
        Phase = PreflightPhase.ElevatedLocalEnvironment,
        Category = category,
        Title = title,
        Status = status,
        Summary = summary,
        Remediation = remediation,
        DomainName = domainName,
        RequiresUserConfirmation = requiresConfirmation,
        Details = details ?? new Dictionary<string, string>()
    };

    private enum ServiceCurrentState : uint
    {
        Unknown = 0,
        Stopped = 1,
        StartPending = 2,
        StopPending = 3,
        Running = 4,
        ContinuePending = 5,
        PausePending = 6,
        Paused = 7
    }

    private readonly record struct ServiceQueryResult(ServiceCurrentState State, string? ErrorMessage);

    private static class NativeServiceQuery
    {
        private const uint ScManagerConnect = 0x0001;
        private const uint ServiceQueryStatus = 0x0004;
        private const int ScStatusProcessInfo = 0;

        public static ServiceQueryResult TryGetState(string serviceName)
        {
            var manager = OpenSCManager(null, null, ScManagerConnect);
            if (manager == IntPtr.Zero)
            {
                return Failure("無法開啟 Windows Service Control Manager");
            }

            try
            {
                var service = OpenService(manager, serviceName, ServiceQueryStatus);
                if (service == IntPtr.Zero)
                {
                    return Failure($"找不到或無法開啟 {serviceName} 服務");
                }

                try
                {
                    var status = new ServiceStatusProcess();
                    if (!QueryServiceStatusEx(
                            service,
                            ScStatusProcessInfo,
                            ref status,
                            Marshal.SizeOf<ServiceStatusProcess>(),
                            out _))
                    {
                        return Failure($"無法查詢 {serviceName} 服務狀態");
                    }

                    return new ServiceQueryResult((ServiceCurrentState)status.CurrentState, null);
                }
                finally
                {
                    _ = CloseServiceHandle(service);
                }
            }
            finally
            {
                _ = CloseServiceHandle(manager);
            }
        }

        private static ServiceQueryResult Failure(string prefix)
        {
            var exception = new Win32Exception(Marshal.GetLastWin32Error());
            return new ServiceQueryResult(ServiceCurrentState.Unknown, $"{prefix}：{exception.Message}");
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceStatusProcess
        {
            public uint ServiceType;
            public uint CurrentState;
            public uint ControlsAccepted;
            public uint Win32ExitCode;
            public uint ServiceSpecificExitCode;
            public uint CheckPoint;
            public uint WaitHint;
            public uint ProcessId;
            public uint ServiceFlags;
        }

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenSCManager(
            string? machineName,
            string? databaseName,
            uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenService(
            IntPtr serviceControlManager,
            string serviceName,
            uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryServiceStatusEx(
            IntPtr service,
            int infoLevel,
            ref ServiceStatusProcess buffer,
            int bufferSize,
            out int bytesNeeded);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr serviceHandle);
    }
}
