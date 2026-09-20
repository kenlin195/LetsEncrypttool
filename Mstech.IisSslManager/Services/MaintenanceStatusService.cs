using System.Collections;
using System.Globalization;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using Mstech.IisSslManager.Core;

namespace Mstech.IisSslManager.Services;

public sealed record MaintenanceStatusSnapshot
{
    public DateTimeOffset CheckedAtUtc { get; init; }
    public bool IisReadSucceeded { get; init; }
    public string? IisError { get; init; }
    public IReadOnlyList<CertificateBindingMaintenanceStatus> Bindings { get; init; } = [];
    public bool TaskReadSucceeded { get; init; }
    public string? TaskError { get; init; }
    public IReadOnlyList<RenewalTaskMaintenanceStatus> RenewalTasks { get; init; } = [];
    public string Notice { get; init; } =
        "這是本機唯讀快照；憑證期限不代表公開 HTTPS 已驗證，排程程序成功也不代表本次已有憑證續期。";
}

public sealed record CertificateBindingMaintenanceStatus
{
    public long SiteId { get; init; }
    public string SiteName { get; init; } = string.Empty;
    public string HostName { get; init; } = string.Empty;
    public string BindingInformation { get; init; } = string.Empty;
    public string Thumbprint { get; init; } = string.Empty;
    public string? StoreName { get; init; }
    public DateTimeOffset? ExpiresAtUtc { get; init; }
    public int? DaysRemaining { get; init; }
    public string State { get; init; } = "未知";
    public string Summary { get; init; } = string.Empty;
}

public sealed record RenewalTaskMaintenanceStatus
{
    public required WinAcmeScheduledTaskInfo Task { get; init; }
    public required ScheduledTaskReadiness Readiness { get; init; }
    public string LastExecutionSummary { get; init; } = string.Empty;
}

/// <summary>
/// Reads local IIS bindings, certificate public metadata and Task Scheduler.
/// No certificate export/private-key access, renewal, directory creation, ACL
/// repair, task registration or IIS CommitChanges is performed by this service.
/// Run through the existing elevated worker to get explicit access errors.
/// </summary>
public sealed class MaintenanceStatusService
{
    public MaintenanceStatusSnapshot Read()
    {
        var now = DateTimeOffset.UtcNow;
        IReadOnlyList<CertificateBindingMaintenanceStatus> bindings = [];
        string? iisError = null;
        try
        {
            bindings = ReadBindings(now);
        }
        catch (Exception exception)
        {
            iisError = $"無法完整讀取 IIS 憑證綁定，狀態未知：{Unwrap(exception).Message}";
        }

        var tasks = new WinAcmeScheduledTaskService().ReadRenewalTasks(WinAcmeRecommendedRelease.ExecutablePath);
        return new MaintenanceStatusSnapshot
        {
            CheckedAtUtc = now,
            IisReadSucceeded = iisError is null,
            IisError = iisError,
            Bindings = bindings,
            TaskReadSucceeded = tasks.Succeeded,
            TaskError = tasks.ErrorMessage,
            RenewalTasks = tasks.Tasks.Select(task => new RenewalTaskMaintenanceStatus
            {
                Task = task,
                Readiness = WinAcmeScheduledTaskService.EvaluateReadiness(task, WinAcmeRecommendedRelease.ExecutablePath, now),
                LastExecutionSummary = WinAcmeScheduledTaskService.DescribeLastExecution(task)
            }).ToArray()
        };
    }

    private static IReadOnlyList<CertificateBindingMaintenanceStatus> ReadBindings(DateTimeOffset now)
    {
        if (!OperatingSystem.IsWindows())
            throw new PlatformNotSupportedException("只有 Windows IIS 可提供本機憑證清單。");

        var assemblyPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "System32", "inetsrv", "Microsoft.Web.Administration.dll");
        if (!File.Exists(assemblyPath))
            throw new FileNotFoundException("找不到或無權讀取 IIS 管理元件。", assemblyPath);
        var assembly = Assembly.LoadFrom(assemblyPath);
        var type = assembly.GetType("Microsoft.Web.Administration.ServerManager", throwOnError: true)!;
        var manager = Activator.CreateInstance(type) ?? throw new InvalidOperationException("無法建立 IIS ServerManager。");
        try
        {
            var result = new List<CertificateBindingMaintenanceStatus>();
            var sites = Required(manager, "Sites") as IEnumerable ?? throw new InvalidOperationException("無法讀取 IIS Sites。");
            foreach (var site in sites)
            {
                if (site is null) continue;
                var siteId = Convert.ToInt64(Required(site, "Id"), CultureInfo.InvariantCulture);
                var siteName = Convert.ToString(Required(site, "Name"), CultureInfo.InvariantCulture) ?? string.Empty;
                var bindings = Required(site, "Bindings") as IEnumerable ?? throw new InvalidOperationException("無法讀取 IIS Bindings。");
                foreach (var binding in bindings)
                {
                    if (binding is null || !string.Equals(Convert.ToString(Required(binding, "Protocol"), CultureInfo.InvariantCulture), "https", StringComparison.OrdinalIgnoreCase)) continue;
                    var information = Convert.ToString(Required(binding, "BindingInformation"), CultureInfo.InvariantCulture) ?? string.Empty;
                    var parsed = IisDiscoveryService.ParseBindings($"https/{information}").SingleOrDefault()
                        ?? throw new InvalidOperationException($"無法解析 IIS HTTPS Binding：{information}");
                    if (parsed.Port != 443) continue;
                    var row = new CertificateBindingMaintenanceStatus
                    {
                        SiteId = siteId,
                        SiteName = siteName,
                        HostName = parsed.HostName ?? string.Empty,
                        BindingInformation = information
                    };
                    try
                    {
                        var flags = Convert.ToInt32(Required(binding, "SslFlags"), CultureInfo.InvariantCulture);
                        var hash = Property(binding, "CertificateHash") as byte[];
                        row = row with
                        {
                            Thumbprint = hash is null ? string.Empty : Convert.ToHexString(hash),
                            StoreName = Convert.ToString(Property(binding, "CertificateStoreName"), CultureInfo.InvariantCulture)
                        };
                        result.Add((flags & 2) != 0
                            ? row with { State = "不支援的存放區", Summary = "此 Binding 使用 Central Certificate Store；本工具無法確認其憑證期限。" }
                            : ReadCertificate(row, now));
                    }
                    catch (Exception exception)
                    {
                        result.Add(row with { State = "未知", Summary = $"無法讀取此 Binding 或憑證：{Unwrap(exception).Message}" });
                    }
                }
            }
            return result.OrderBy(row => row.SiteId).ThenBy(row => row.HostName, StringComparer.OrdinalIgnoreCase).ToArray();
        }
        finally
        {
            (manager as IDisposable)?.Dispose();
        }
    }

    private static CertificateBindingMaintenanceStatus ReadCertificate(CertificateBindingMaintenanceStatus row, DateTimeOffset now)
    {
        if (string.IsNullOrWhiteSpace(row.Thumbprint))
            return row with { State = "未綁定憑證", Summary = "IIS HTTPS Binding 沒有憑證指紋。" };
        if (string.IsNullOrWhiteSpace(row.StoreName))
            return row with { State = "未知", Summary = "IIS 未回報憑證存放區，不能推測憑證是否存在。" };

        using var store = new X509Store(row.StoreName, StoreLocation.LocalMachine);
        store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
        var certificates = store.Certificates;
        try
        {
            var certificate = certificates.Cast<X509Certificate2>().FirstOrDefault(item =>
                string.Equals(item.Thumbprint, row.Thumbprint, StringComparison.OrdinalIgnoreCase));
            if (certificate is null)
                return row with { State = "找不到憑證", Summary = $"在 LocalMachine\\{row.StoreName} 找不到此 Binding 指紋。" };

            var expiresAt = new DateTimeOffset(certificate.NotAfter.ToUniversalTime());
            var validity = EvaluateCertificateValidity(new DateTimeOffset(certificate.NotBefore.ToUniversalTime()),
                expiresAt, certificate.HasPrivateKey, now);
            return row with
            {
                ExpiresAtUtc = expiresAt,
                DaysRemaining = validity.DaysRemaining,
                State = validity.State,
                Summary = validity.Summary
            };
        }
        finally
        {
            foreach (var certificate in certificates) certificate.Dispose();
        }
    }

    internal static (string State, string Summary, int DaysRemaining) EvaluateCertificateValidity(
        DateTimeOffset notBefore, DateTimeOffset expiresAt, bool hasPrivateKey, DateTimeOffset now)
    {
        var days = (int)Math.Floor((expiresAt - now).TotalDays);
        if (expiresAt <= now) return ("已到期", "憑證已超過有效期限，請檢查自動續期與 IIS 綁定。", days);
        if (notBefore > now) return ("尚未生效", "憑證尚未進入有效期間，請核對系統時間與憑證。", days);
        if (!hasPrivateKey) return ("缺少私鑰", "憑證中沒有可辨識的私鑰關聯；本次未嘗試開啟或匯出私鑰。", days);
        if (expiresAt - now <= TimeSpan.FromDays(30))
            return ("即將到期", "憑證將在 30 天內到期，建議確認續期排程與 win-acme 紀錄。", days);
        return ("有效期間內", "憑證在有效期間內；尚未驗證公開 HTTPS、完整信任鏈或實際續期結果。", days);
    }

    private static object Required(object value, string name) => Property(value, name)
        ?? throw new InvalidOperationException($"IIS 屬性 {name} 沒有值。");

    private static object? Property(object value, string name) =>
        (value.GetType().GetProperty(name, BindingFlags.Instance | BindingFlags.Public)
         ?? throw new InvalidOperationException($"IIS 管理 API 缺少 {name} 屬性。")).GetValue(value);

    private static Exception Unwrap(Exception exception) =>
        exception is TargetInvocationException { InnerException: { } inner } ? inner : exception;
}
