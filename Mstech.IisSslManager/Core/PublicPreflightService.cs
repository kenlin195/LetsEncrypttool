using System.Diagnostics;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text.Json;
using Microsoft.Win32;
using Mstech.IisSslManager.Models;

namespace Mstech.IisSslManager.Core;

public interface IPublicPreflightService
{
    Task<PreflightReport> RunAsync(
        PublicPreflightRequest request,
        IProgress<PreflightCheckResult>? progress = null,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Performs checks that do not require administrator privileges. These checks are
/// deliberately diagnostic: only an ACME staging challenge can conclusively prove
/// that Let's Encrypt can reach the temporary HTTP-01 listener from the Internet.
/// </summary>
public sealed class PublicPreflightService : IPublicPreflightService, IDisposable
{
    private const string LetsEncryptIssuerDomain = "letsencrypt.org";
    private readonly IDnsQueryClient _dnsClient;
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;

    public PublicPreflightService(IDnsQueryClient dnsClient, HttpClient? httpClient = null)
    {
        _dnsClient = dnsClient ?? throw new ArgumentNullException(nameof(dnsClient));
        _ownsHttpClient = httpClient is null;
        _httpClient = httpClient ?? CreateHttpClient();
    }

    public async Task<PreflightReport> RunAsync(
        PublicPreflightRequest request,
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

        Add(CheckOperatingSystem());
        Add(CheckNameMode(request));

        var normalizedNames = new List<string>();
        foreach (var rawName in request.DomainNames)
        {
            if (DomainNameValidator.TryNormalize(rawName, out var normalized, out var error))
            {
                normalizedNames.Add(normalized);
                Add(Result(
                    id: $"domain-format:{normalized}",
                    category: "網域",
                    title: $"網域格式：{normalized}",
                    status: CheckStatus.Passed,
                    summary: "網域名稱格式正確。",
                    domainName: normalized));
            }
            else
            {
                Add(Result(
                    id: $"domain-format:{rawName}",
                    category: "網域",
                    title: $"網域格式：{rawName}",
                    status: CheckStatus.Failed,
                    summary: error!,
                    remediation: "請輸入不含通訊協定、連接埠與路徑的公開完整網域名稱。",
                    domainName: rawName));
            }
        }

        var distinctNames = normalizedNames.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        if (distinctNames.Length != normalizedNames.Count)
        {
            Add(Result(
                id: "domain-duplicates",
                category: "網域",
                title: "重複的 SAN 名稱",
                status: CheckStatus.Warning,
                summary: "已忽略重複的網域名稱。",
                remediation: "建議從清單移除重複項目，以免操作人員誤判。"));
        }

        var endpointTasks = new List<Task<PreflightCheckResult>>
        {
            CheckAcmeDirectoryAsync(
                request.ProductionAcmeDirectory,
                "acme-production",
                "Let's Encrypt 正式環境",
                request.PerCheckTimeout,
                cancellationToken)
        };

        if (request.CheckStagingDirectory)
        {
            endpointTasks.Add(CheckAcmeDirectoryAsync(
                request.StagingAcmeDirectory,
                "acme-staging-directory",
                "Let's Encrypt Staging 環境",
                request.PerCheckTimeout,
                cancellationToken));
        }

        endpointTasks.Add(CheckSystemClockAsync(
            request.ProductionAcmeDirectory,
            request.PerCheckTimeout,
            cancellationToken));

        foreach (var endpointResult in await Task.WhenAll(endpointTasks).ConfigureAwait(false))
        {
            Add(endpointResult);
        }

        var domainTasks = distinctNames.Select(domain =>
            CheckDomainAsync(domain, request, cancellationToken));
        var domainResults = await Task.WhenAll(domainTasks).ConfigureAwait(false);
        foreach (var resultSet in domainResults)
        {
            foreach (var result in resultSet)
            {
                Add(result);
            }
        }

        Add(new PreflightCheckResult
        {
            Id = "acme-staging-challenge",
            Phase = PreflightPhase.AcmeStaging,
            Category = "ACME",
            Title = "Staging HTTP-01 外部驗證",
            Status = CheckStatus.Pending,
            Summary = "公開預檢完成後，仍須提升權限啟動臨時 HTTP-01 Listener，並由 Let's Encrypt Staging 從外部實際驗證。",
            Remediation = "Staging 驗證未成功前，不得啟用正式簽發按鈕。",
            IsRequired = true
        });

        return new PreflightReport
        {
            StartedAt = startedAt,
            CompletedAt = DateTimeOffset.Now,
            Checks = checks.ToArray()
        };
    }

    public void Dispose()
    {
        if (_ownsHttpClient)
        {
            _httpClient.Dispose();
        }
    }

    private async Task<IReadOnlyList<PreflightCheckResult>> CheckDomainAsync(
        string domain,
        PublicPreflightRequest request,
        CancellationToken cancellationToken)
    {
        var dnsTask = CheckAddressRecordsAsync(domain, request, cancellationToken);
        var caaTask = CheckCaaAsync(domain, request.PerCheckTimeout, cancellationToken);
        var httpTask = CheckHttpRouteAsync(domain, request.PerCheckTimeout, cancellationToken);

        await Task.WhenAll(dnsTask, caaTask, httpTask).ConfigureAwait(false);
        var results = new List<PreflightCheckResult>();
        results.AddRange(await dnsTask.ConfigureAwait(false));
        results.Add(await caaTask.ConfigureAwait(false));
        results.Add(await httpTask.ConfigureAwait(false));
        return results;
    }

    private async Task<IReadOnlyList<PreflightCheckResult>> CheckAddressRecordsAsync(
        string domain,
        PublicPreflightRequest request,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var aTask = _dnsClient.QueryAsync(
            domain,
            DnsRecordType.A,
            request.PerCheckTimeout,
            cancellationToken);
        var aaaaTask = _dnsClient.QueryAsync(
            domain,
            DnsRecordType.Aaaa,
            request.PerCheckTimeout,
            cancellationToken);
        var cnameTask = _dnsClient.QueryAsync(
            domain,
            DnsRecordType.CName,
            request.PerCheckTimeout,
            cancellationToken);

        await Task.WhenAll(aTask, aaaaTask, cnameTask).ConfigureAwait(false);
        var lookups = new[]
        {
            await aTask.ConfigureAwait(false),
            await aaaaTask.ConfigureAwait(false),
            await cnameTask.ConfigureAwait(false)
        };

        var addresses = lookups
            .SelectMany(lookup => lookup.Records)
            .Select(record => record.Address)
            .OfType<IPAddress>()
            .Distinct()
            .ToArray();
        var aliases = lookups
            .SelectMany(lookup => lookup.Records)
            .Select(record => record.CanonicalName)
            .Where(alias => !string.IsNullOrWhiteSpace(alias))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var publicResolverUnavailable = lookups.All(lookup =>
            lookup.ResponseCode == DnsResponseCode.Unknown && lookup.ErrorMessage is not null);
        if (publicResolverUnavailable)
        {
            var reason = string.Join(
                " | ",
                lookups.Select(lookup => lookup.ErrorMessage).Where(message => !string.IsNullOrWhiteSpace(message)).Distinct());
            return
            [
                Result(
                    id: $"dns-a:{domain}",
                    category: "DNS",
                    title: $"A 記錄：{domain}",
                    status: CheckStatus.Warning,
                    summary: $"公共 DNS Resolver 無法查詢 A 記錄：{reason}",
                    remediation: "企業防火牆可能封鎖對外 UDP／TCP 53；請人工確認公開 A 記錄，或允許查詢 1.1.1.1／8.8.8.8。",
                    domainName: domain,
                    duration: stopwatch.Elapsed,
                    requiresConfirmation: true),
                Result(
                    id: $"dns-aaaa:{domain}",
                    category: "DNS",
                    title: $"AAAA 記錄：{domain}",
                    status: CheckStatus.Warning,
                    summary: "公共 DNS Resolver 無法查詢 AAAA 記錄，工具無法排除錯誤 IPv6 指向。",
                    remediation: "請人工查詢並確認公開 AAAA；若不使用 IPv6，請確定沒有殘留的 AAAA 記錄。",
                    domainName: domain,
                    duration: stopwatch.Elapsed,
                    requiresConfirmation: true),
                Result(
                    id: $"dns-target:{domain}",
                    category: "DNS",
                    title: $"DNS 指向確認：{domain}",
                    status: CheckStatus.Warning,
                    summary: "因公共 DNS 查詢被阻擋，無法自動確認網域是否指向此 IIS／Proxy。",
                    remediation: "人工確認後仍必須以 Let's Encrypt Staging 做外部驗證。",
                    domainName: domain,
                    requiresConfirmation: true)
            ];
        }

        var hardError = lookups.FirstOrDefault(lookup =>
            lookup.ResponseCode is DnsResponseCode.ServerFailure or
                DnsResponseCode.Refused or
                DnsResponseCode.FormatError);
        if (hardError is not null)
        {
            return
            [
                Result(
                    id: $"dns-a:{domain}",
                    category: "DNS",
                    title: $"A 記錄：{domain}",
                    status: CheckStatus.Failed,
                    summary: hardError.ErrorMessage ?? "公開 DNS 查詢失敗。",
                    remediation: "請檢查權威 DNS、DNSSEC 與防火牆後重新測試。",
                    domainName: domain,
                    duration: stopwatch.Elapsed,
                    details: new Dictionary<string, string>
                    {
                        ["Resolver"] = hardError.Resolver.ToString(),
                        ["ResponseCode"] = hardError.ResponseCode.ToString()
                    })
            ];
        }

        if (addresses.Length == 0)
        {
            var error = lookups.FirstOrDefault(lookup => lookup.ResponseCode == DnsResponseCode.NameError)?.ErrorMessage;
            return
            [
                CreateAddressRecordResult(domain, DnsRecordType.A, lookups[0], Array.Empty<IPAddress>(), false, stopwatch.Elapsed),
                CreateAddressRecordResult(domain, DnsRecordType.Aaaa, lookups[1], Array.Empty<IPAddress>(), false, stopwatch.Elapsed),
                Result(
                    id: $"dns-address:{domain}",
                    category: "DNS",
                    title: $"公開 DNS：{domain}",
                    status: CheckStatus.Failed,
                    summary: error ?? "查不到可供 HTTP-01 連線的公開 A 或 AAAA 位址。",
                    remediation: "請新增或修正 A／AAAA／CNAME，並等待公開 DNS 傳播完成。",
                    domainName: domain,
                    duration: stopwatch.Elapsed,
                    details: new Dictionary<string, string>
                    {
                        ["CNAME"] = aliases.Length == 0 ? "(無)" : string.Join(", ", aliases)
                    })
            ];
        }

        var details = new Dictionary<string, string>
        {
            ["Addresses"] = string.Join(", ", addresses.Select(address => address.ToString())),
            ["CNAME"] = aliases.Length == 0 ? "(無)" : string.Join(", ", aliases),
            ["Resolver"] = string.Join(", ", lookups.Select(lookup => lookup.Resolver).Distinct())
        };
        var ipv4Addresses = addresses
            .Where(address => address.AddressFamily == AddressFamily.InterNetwork)
            .ToArray();
        var ipv6Addresses = addresses
            .Where(address => address.AddressFamily == AddressFamily.InterNetworkV6)
            .ToArray();
        var results = new List<PreflightCheckResult>
        {
            CreateAddressRecordResult(
                domain,
                DnsRecordType.A,
                lookups[0],
                ipv4Addresses,
                addresses.Length > 0,
                stopwatch.Elapsed),
            CreateAddressRecordResult(
                domain,
                DnsRecordType.Aaaa,
                lookups[1],
                ipv6Addresses,
                addresses.Length > 0,
                stopwatch.Elapsed),
            Result(
                id: $"dns-address-summary:{domain}",
                category: "DNS",
                title: $"公開 DNS：{domain}",
                status: CheckStatus.Passed,
                summary: "已從公開 DNS 查到可連線位址。",
                domainName: domain,
                duration: stopwatch.Elapsed,
                details: details)
        };

        if (request.ExpectedPublicAddresses.Count > 0)
        {
            var unexpected = addresses
                .Where(address => !request.ExpectedPublicAddresses.Contains(address))
                .ToArray();
            results.Add(Result(
                id: $"dns-target:{domain}",
                category: "DNS",
                title: $"DNS 指向確認：{domain}",
                status: unexpected.Length == 0 ? CheckStatus.Passed : CheckStatus.Failed,
                summary: unexpected.Length == 0
                    ? "所有公開位址皆符合本次設定的 IIS／Proxy 位址。"
                    : $"發現未列入允許清單的位址：{string.Join(", ", unexpected.Select(address => address.ToString()))}",
                remediation: unexpected.Length == 0
                    ? null
                    : "請修正 A／AAAA；錯誤的 AAAA 可能使 Let's Encrypt 優先連到錯誤的 IPv6 主機。",
                domainName: domain,
                details: details));
        }
        else
        {
            var hasIpv6 = addresses.Any(address => address.AddressFamily == AddressFamily.InterNetworkV6);
            results.Add(Result(
                id: $"dns-target:{domain}",
                category: "DNS",
                title: $"DNS 指向人工確認：{domain}",
                status: CheckStatus.Warning,
                summary: "工具查到公開位址，但尚無法只從本機判斷它們是否全都指向此 IIS、Load Balancer 或正確的 Proxy。",
                remediation: hasIpv6
                    ? "請特別確認列出的 A 與 AAAA 都能把 Port 80 導向驗證主機；Let’s Encrypt 可能優先使用 IPv6。"
                    : "請確認列出的 A 位址會把 Internet Port 80 導向驗證主機。",
                domainName: domain,
                requiresConfirmation: true,
                details: details));
        }

        return results;
    }

    private async Task<PreflightCheckResult> CheckCaaAsync(
        string domain,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var result = await _dnsClient.QueryEffectiveCaaAsync(domain, timeout, cancellationToken)
            .ConfigureAwait(false);

        if (result.ErrorMessage is not null)
        {
            return Result(
                id: $"dns-caa:{domain}",
                category: "CAA",
                title: $"CAA 授權：{domain}",
                status: result.IsTransportFailure ? CheckStatus.Warning : CheckStatus.Failed,
                summary: result.ErrorMessage,
                remediation: result.IsTransportFailure
                    ? "公共 Resolver 可能被防火牆封鎖；請人工確認有效 CAA，且後續必須以 Staging 驗證。"
                    : "請確認 DNSSEC 及權威 DNS 正常，再檢查 CAA 是否允許 letsencrypt.org。",
                domainName: domain,
                duration: stopwatch.Elapsed,
                requiresConfirmation: result.IsTransportFailure,
                details: new Dictionary<string, string> { ["Resolver"] = result.Resolver.ToString() });
        }

        if (result.Records.Count == 0)
        {
            return Result(
                id: $"dns-caa:{domain}",
                category: "CAA",
                title: $"CAA 授權：{domain}",
                status: CheckStatus.Passed,
                summary: "未設定有效 CAA 限制；Let's Encrypt 可依網域驗證結果簽發。",
                domainName: domain,
                duration: stopwatch.Elapsed,
                details: new Dictionary<string, string>
                {
                    ["Resolver"] = result.Resolver.ToString(),
                    ["EffectiveOwner"] = "(無)"
                });
        }

        var recordDescriptions = result.Records.Select(DescribeCaaRecord).ToArray();
        var details = new Dictionary<string, string>
        {
            ["Resolver"] = result.Resolver.ToString(),
            ["EffectiveOwner"] = result.RecordOwnerName ?? domain,
            ["Records"] = string.Join(" | ", recordDescriptions)
        };

        var unsupportedCriticalRecord = result.Records.FirstOrDefault(record =>
            (record.CaaFlags.GetValueOrDefault() & 0x80) != 0 &&
            !IsKnownCaaTag(record.CaaTag));
        if (unsupportedCriticalRecord is not null)
        {
            return Result(
                id: $"dns-caa:{domain}",
                category: "CAA",
                title: $"CAA 授權：{domain}",
                status: CheckStatus.Failed,
                summary: $"發現帶有 Critical flag 的未知 CAA 標籤：{unsupportedCriticalRecord.CaaTag}。",
                remediation: "請由 DNS 管理員移除或修正該 Critical CAA 記錄。",
                domainName: domain,
                duration: stopwatch.Elapsed,
                details: details);
        }

        var issueRecords = result.Records
            .Where(record => string.Equals(record.CaaTag, "issue", StringComparison.OrdinalIgnoreCase))
            .ToArray();

        // issuewild restricts only wildcard issuance. This tool requests explicit names, so
        // the absence of an issue property means non-wildcard issuance is unrestricted.
        if (issueRecords.Length == 0)
        {
            return Result(
                id: $"dns-caa:{domain}",
                category: "CAA",
                title: $"CAA 授權：{domain}",
                status: CheckStatus.Passed,
                summary: "CAA 未限制一般（非 Wildcard）憑證的簽發機構。",
                domainName: domain,
                duration: stopwatch.Elapsed,
                details: details);
        }

        var letsEncryptRecord = issueRecords.FirstOrDefault(record =>
            string.Equals(GetCaaIssuerDomain(record.CaaValue), LetsEncryptIssuerDomain, StringComparison.OrdinalIgnoreCase));
        if (letsEncryptRecord is null)
        {
            return Result(
                id: $"dns-caa:{domain}",
                category: "CAA",
                title: $"CAA 授權：{domain}",
                status: CheckStatus.Failed,
                summary: "CAA issue 記錄未允許 letsencrypt.org，正式簽發會被拒絕。",
                remediation: "請新增 `CAA 0 issue \"letsencrypt.org\"`，或由 DNS 管理員調整既有 CAA 政策。",
                domainName: domain,
                duration: stopwatch.Elapsed,
                details: details);
        }

        var hasParameters = letsEncryptRecord.CaaValue?.Contains(';', StringComparison.Ordinal) == true;
        return Result(
            id: $"dns-caa:{domain}",
            category: "CAA",
            title: $"CAA 授權：{domain}",
            status: hasParameters ? CheckStatus.Warning : CheckStatus.Passed,
            summary: hasParameters
                ? "CAA 已允許 Let's Encrypt，但包含帳號或驗證方式限制，仍需以 Staging 實測。"
                : "CAA 已允許 letsencrypt.org。",
            remediation: hasParameters
                ? "請確認 CAA 參數與 win-acme 使用的 ACME 帳號及 HTTP-01 驗證方式一致。"
                : null,
            domainName: domain,
            duration: stopwatch.Elapsed,
            requiresConfirmation: hasParameters,
            details: details);
    }

    private async Task<PreflightCheckResult> CheckHttpRouteAsync(
        string domain,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        var path = $"/.well-known/acme-challenge/mstech-preflight-{Guid.NewGuid():N}";
        var uri = new UriBuilder(Uri.UriSchemeHttp, domain, 80, path).Uri;

        try
        {
            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutSource.CancelAfter(timeout);
            using var message = new HttpRequestMessage(HttpMethod.Get, uri);
            message.Headers.CacheControl = new CacheControlHeaderValue { NoCache = true };
            using var response = await _httpClient.SendAsync(
                message,
                HttpCompletionOption.ResponseHeadersRead,
                timeoutSource.Token).ConfigureAwait(false);

            var statusCode = (int)response.StatusCode;
            var details = new Dictionary<string, string>
            {
                ["URL"] = uri.ToString(),
                ["HTTP"] = $"{statusCode} {response.ReasonPhrase}"
            };

            if (response.Headers.Location is not null)
            {
                var redirect = response.Headers.Location.IsAbsoluteUri
                    ? response.Headers.Location
                    : new Uri(uri, response.Headers.Location);
                details["Redirect"] = redirect.ToString();

                var schemeAllowed =
                    redirect.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase) ||
                    redirect.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
                var portAllowed = redirect.Port is 80 or 443;
                if (!schemeAllowed || !portAllowed)
                {
                    return Result(
                        id: $"http-route:{domain}",
                        category: "HTTP-01",
                        title: $"Port 80 驗證路徑：{domain}",
                        status: CheckStatus.Failed,
                        summary: "驗證路徑被導向 Let’s Encrypt 不接受的通訊協定或連接埠。",
                        remediation: "HTTP-01 重新導向僅可使用 HTTP／HTTPS，且目的 Port 必須為 80 或 443。",
                        domainName: domain,
                        duration: stopwatch.Elapsed,
                        details: details);
                }
            }

            if (statusCode is 401 or 403 or 407)
            {
                return Result(
                    id: $"http-route:{domain}",
                    category: "HTTP-01",
                    title: $"Port 80 驗證路徑：{domain}",
                    status: CheckStatus.Failed,
                    summary: "驗證路徑受到登入驗證、Proxy 或存取規則阻擋。",
                    remediation: "請放行 `/.well-known/acme-challenge/`，不要要求登入或限制 Let’s Encrypt 來源 IP。",
                    domainName: domain,
                    duration: stopwatch.Elapsed,
                    details: details);
            }

            if (statusCode >= 500)
            {
                return Result(
                    id: $"http-route:{domain}",
                    category: "HTTP-01",
                    title: $"Port 80 驗證路徑：{domain}",
                    status: CheckStatus.Failed,
                    summary: "Port 80 有回應，但目前是伺服器錯誤。",
                    remediation: "請排除 IIS、Reverse Proxy、WAF 或應用程式錯誤後重新測試。",
                    domainName: domain,
                    duration: stopwatch.Elapsed,
                    details: details);
            }

            return Result(
                id: $"http-route:{domain}",
                category: "HTTP-01",
                title: $"Port 80 驗證路徑：{domain}",
                status: CheckStatus.Passed,
                summary: statusCode == 404
                    ? "Port 80 可到達，測試 Token 尚不存在而回覆 404，這是預期結果。"
                    : "Port 80 的 HTTP-01 路徑可取得回應。",
                remediation: "此測試由本機送出；後續仍須通過 Let’s Encrypt Staging 的外部驗證。",
                domainName: domain,
                duration: stopwatch.Elapsed,
                details: details);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return HttpRouteIndeterminate(domain, uri, "連線逾時。可能是 Hairpin NAT 限制，也可能是外部 Port 80 未開放。", stopwatch.Elapsed);
        }
        catch (HttpRequestException exception)
        {
            return HttpRouteIndeterminate(domain, uri, exception.Message, stopwatch.Elapsed);
        }
    }

    private async Task<PreflightCheckResult> CheckAcmeDirectoryAsync(
        Uri directoryUri,
        string id,
        string title,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        try
        {
            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutSource.CancelAfter(timeout);
            using var response = await _httpClient.GetAsync(directoryUri, timeoutSource.Token).ConfigureAwait(false);
            var payload = await response.Content.ReadAsStringAsync(timeoutSource.Token).ConfigureAwait(false);

            if (!response.IsSuccessStatusCode)
            {
                return Result(
                    id: id,
                    category: "ACME",
                    title: title,
                    status: CheckStatus.Failed,
                    summary: $"ACME Directory 回覆 HTTP {(int)response.StatusCode}。",
                    remediation: "請確認伺服器可對外連線 TCP 443，並檢查 Proxy、TLS 與防火牆。",
                    duration: stopwatch.Elapsed,
                    details: new Dictionary<string, string> { ["URL"] = directoryUri.ToString() });
            }

            using var document = JsonDocument.Parse(payload);
            var root = document.RootElement;
            var requiredProperties = new[] { "newNonce", "newAccount", "newOrder" };
            if (root.ValueKind != JsonValueKind.Object ||
                requiredProperties.Any(property => !root.TryGetProperty(property, out _)))
            {
                return Result(
                    id: id,
                    category: "ACME",
                    title: title,
                    status: CheckStatus.Failed,
                    summary: "端點有回應，但內容不是有效的 ACME v2 Directory。",
                    remediation: "請檢查 HTTPS Proxy 是否替換或攔截回應內容。",
                    duration: stopwatch.Elapsed,
                    details: new Dictionary<string, string> { ["URL"] = directoryUri.ToString() });
            }

            var details = new Dictionary<string, string>
            {
                ["URL"] = directoryUri.ToString(),
                ["HTTP"] = $"{(int)response.StatusCode} {response.ReasonPhrase}"
            };
            var clockStatus = CheckStatus.Passed;
            var summary = "可連線至有效的 ACME v2 Directory。";
            var remediation = (string?)null;
            if (response.Headers.Date is { } serverDate)
            {
                var clockDifference = (DateTimeOffset.UtcNow - serverDate).Duration();
                details["ClockDifference"] = clockDifference.ToString("g");
                if (clockDifference > TimeSpan.FromMinutes(5))
                {
                    clockStatus = CheckStatus.Warning;
                    summary = "ACME 端點可連線，但本機時間與伺服器回覆時間相差超過 5 分鐘。";
                    remediation = "請確認 Windows Time 服務與 NTP 同步狀態。";
                }
            }

            return Result(
                id: id,
                category: "ACME",
                title: title,
                status: clockStatus,
                summary: summary,
                remediation: remediation,
                duration: stopwatch.Elapsed,
                requiresConfirmation: clockStatus == CheckStatus.Warning,
                details: details);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return AcmeEndpointFailure(id, title, directoryUri, "連線逾時。", stopwatch.Elapsed);
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException)
        {
            return AcmeEndpointFailure(id, title, directoryUri, exception.Message, stopwatch.Elapsed);
        }
    }

    private async Task<PreflightCheckResult> CheckSystemClockAsync(
        Uri referenceUri,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        var stopwatch = Stopwatch.StartNew();
        try
        {
            using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeoutSource.CancelAfter(timeout);
            using var request = new HttpRequestMessage(HttpMethod.Head, referenceUri);
            using var response = await _httpClient.SendAsync(
                request,
                HttpCompletionOption.ResponseHeadersRead,
                timeoutSource.Token).ConfigureAwait(false);

            var localTime = DateTimeOffset.UtcNow;
            var details = new Dictionary<string, string>
            {
                ["LocalUtc"] = localTime.ToString("O")
            };
            if (response.Headers.Date is not { } serverTime)
            {
                return Result(
                    id: "environment-clock",
                    category: "系統",
                    title: "系統日期與時間",
                    status: CheckStatus.Warning,
                    summary: "參考端點未提供 Date 標頭，無法自動比對系統時間。",
                    remediation: "請確認 Windows Time 服務與可信任的 NTP 來源同步。",
                    duration: stopwatch.Elapsed,
                    requiresConfirmation: true,
                    details: details);
            }

            var difference = (localTime - serverTime).Duration();
            details["ReferenceUtc"] = serverTime.ToString("O");
            details["Difference"] = difference.ToString("g");
            return Result(
                id: "environment-clock",
                category: "系統",
                title: "系統日期與時間",
                status: difference <= TimeSpan.FromMinutes(5) ? CheckStatus.Passed : CheckStatus.Failed,
                summary: difference <= TimeSpan.FromMinutes(5)
                    ? "系統 UTC 時間與網路參考時間相差未超過 5 分鐘。"
                    : "系統 UTC 時間偏差超過 5 分鐘，可能造成 ACME 簽章或 TLS 驗證失敗。",
                remediation: difference <= TimeSpan.FromMinutes(5)
                    ? null
                    : "請先修正 Windows Time／NTP 同步，再進行換證。",
                duration: stopwatch.Elapsed,
                details: details);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return SystemClockIndeterminate("取得網路參考時間逾時。", stopwatch.Elapsed);
        }
        catch (HttpRequestException exception)
        {
            return SystemClockIndeterminate(exception.Message, stopwatch.Elapsed);
        }
    }

    private static PreflightCheckResult CreateAddressRecordResult(
        string domain,
        DnsRecordType type,
        DnsLookupResult lookup,
        IReadOnlyList<IPAddress> addresses,
        bool hasAnyAddress,
        TimeSpan duration)
    {
        var label = type == DnsRecordType.A ? "A" : "AAAA";
        if (lookup.ResponseCode == DnsResponseCode.Unknown && lookup.ErrorMessage is not null)
        {
            return Result(
                id: $"dns-{label.ToLowerInvariant()}:{domain}",
                category: "DNS",
                title: $"{label} 記錄：{domain}",
                status: CheckStatus.Warning,
                summary: $"無法查詢 {label} 記錄：{lookup.ErrorMessage}",
                remediation: "請人工確認公開 DNS，並於後續執行 Staging 外部驗證。",
                domainName: domain,
                duration: duration,
                requiresConfirmation: true);
        }

        var isPresent = addresses.Count > 0;
        return Result(
            id: $"dns-{label.ToLowerInvariant()}:{domain}",
            category: "DNS",
            title: $"{label} 記錄：{domain}",
            status: isPresent || hasAnyAddress ? CheckStatus.Passed : CheckStatus.Failed,
            summary: isPresent
                ? $"公開 {label}：{string.Join(", ", addresses)}"
                : hasAnyAddress
                    ? $"未設定 {label}，但已有另一種 IP 位址可供驗證。"
                    : $"未查到 {label} 記錄。",
            remediation: type == DnsRecordType.Aaaa && !isPresent
                ? "AAAA 並非必要；若日後新增 IPv6，必須確保 Port 80 同樣可到達驗證主機。"
                : null,
            domainName: domain,
            duration: duration,
            details: new Dictionary<string, string>
            {
                ["Resolver"] = lookup.Resolver.ToString(),
                ["ResponseCode"] = lookup.ResponseCode.ToString()
            });
    }

    private static PreflightCheckResult SystemClockIndeterminate(string reason, TimeSpan duration) => Result(
        id: "environment-clock",
        category: "系統",
        title: "系統日期與時間",
        status: CheckStatus.Warning,
        summary: $"無法與網路時間比對：{reason}",
        remediation: "請人工確認 Windows Time／NTP 同步狀態。ACME 端點若也無法連線，該項會阻擋換證。",
        duration: duration,
        requiresConfirmation: true);

    private static PreflightCheckResult CheckOperatingSystem()
    {
        var details = new Dictionary<string, string>
        {
            ["OS"] = Environment.OSVersion.VersionString,
            ["ProcessArchitecture"] = Environment.Is64BitProcess ? "x64" : "x86",
            ["OSArchitecture"] = Environment.Is64BitOperatingSystem ? "x64" : "x86"
        };

        if (!OperatingSystem.IsWindows())
        {
            return Result(
                id: "environment-os",
                category: "系統",
                title: "Windows Server 版本",
                status: CheckStatus.Failed,
                summary: "此工具只能在 Windows Server 上執行。",
                details: details);
        }

        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 14393) ||
            !Environment.Is64BitOperatingSystem ||
            !Environment.Is64BitProcess)
        {
            return Result(
                id: "environment-os",
                category: "系統",
                title: "Windows Server 版本",
                status: CheckStatus.Failed,
                summary: "需要 Windows Server 2016 以上的 x64 系統與 x64 程序。",
                remediation: "請改在受支援的 Windows Server 2016／2019／2022／2025 x64 主機執行。",
                details: details);
        }

        var productName = GetWindowsProductName();
        if (!string.IsNullOrWhiteSpace(productName))
        {
            details["ProductName"] = productName;
        }

        var isServer = productName?.Contains("Server", StringComparison.OrdinalIgnoreCase) == true;
        return Result(
            id: "environment-os",
            category: "系統",
            title: "Windows Server 版本",
            status: isServer ? CheckStatus.Passed : CheckStatus.Warning,
            summary: isServer
                ? "作業系統符合 Windows Server 2016 以上 x64 要求。"
                : "Windows 版本與架構符合最低需求，但無法確認這是 Windows Server SKU。",
            remediation: isServer ? null : "正式環境只支援 Windows Server；桌面版 Windows 僅供開發測試。",
            requiresConfirmation: !isServer,
            details: details);
    }

    private static PreflightCheckResult CheckNameMode(PublicPreflightRequest request)
    {
        var count = request.DomainNames.Count;
        var valid = request.NameMode switch
        {
            CertificateNameMode.SingleDomain => count == 1,
            CertificateNameMode.SubjectAlternativeNames => count is >= 2 and <= 100,
            _ => false
        };

        var expected = request.NameMode == CertificateNameMode.SingleDomain
            ? "一般網域模式必須且只能輸入 1 個網域。"
            : "SAN 模式必須輸入 2 至 100 個明確網域；每個名稱都必須通過驗證。";

        return Result(
            id: "certificate-name-mode",
            category: "憑證",
            title: request.NameMode == CertificateNameMode.SingleDomain ? "一般網域模式" : "SAN 多網域模式",
            status: valid ? CheckStatus.Passed : CheckStatus.Failed,
            summary: valid ? expected : $"設定不符合模式要求：{expected}",
            remediation: valid ? null : "請調整模式或網域清單後重新執行預檢。",
            details: new Dictionary<string, string> { ["NameCount"] = count.ToString() });
    }

    private static PreflightCheckResult HttpRouteIndeterminate(
        string domain,
        Uri uri,
        string reason,
        TimeSpan duration) => Result(
            id: $"http-route:{domain}",
            category: "HTTP-01",
            title: $"Port 80 驗證路徑：{domain}",
            status: CheckStatus.Warning,
            summary: $"本機無法確認 HTTP-01 路徑：{reason}",
            remediation: "請確認 NAT、外部防火牆、WAF 與 Load Balancer，並在升權後以 Let's Encrypt Staging 做外部實測。",
            domainName: domain,
            duration: duration,
            requiresConfirmation: true,
            details: new Dictionary<string, string> { ["URL"] = uri.ToString() });

    private static PreflightCheckResult AcmeEndpointFailure(
        string id,
        string title,
        Uri uri,
        string reason,
        TimeSpan duration) => Result(
            id: id,
            category: "ACME",
            title: title,
            status: CheckStatus.Failed,
            summary: $"無法連線 ACME Directory：{reason}",
            remediation: "請允許對外 TCP 443，並檢查 Proxy、TLS 檢查設備與系統時間。",
            duration: duration,
            details: new Dictionary<string, string> { ["URL"] = uri.ToString() });

    private static PreflightCheckResult Result(
        string id,
        string category,
        string title,
        CheckStatus status,
        string summary,
        string? remediation = null,
        string? domainName = null,
        TimeSpan duration = default,
        bool requiresConfirmation = false,
        IReadOnlyDictionary<string, string>? details = null) => new()
    {
        Id = id,
        Phase = PreflightPhase.PublicEnvironment,
        Category = category,
        Title = title,
        Status = status,
        Summary = summary,
        Remediation = remediation,
        DomainName = domainName,
        Duration = duration,
        RequiresUserConfirmation = requiresConfirmation,
        Details = details ?? new Dictionary<string, string>()
    };

    private static string DescribeCaaRecord(DnsRecord record) =>
        $"{record.CaaFlags.GetValueOrDefault()} {record.CaaTag} \"{record.CaaValue}\"";

    private static string GetCaaIssuerDomain(string? value) =>
        (value ?? string.Empty).Split(';', 2)[0].Trim();

    private static bool IsKnownCaaTag(string? tag) =>
        tag is not null &&
        (tag.Equals("issue", StringComparison.OrdinalIgnoreCase) ||
         tag.Equals("issuewild", StringComparison.OrdinalIgnoreCase) ||
         tag.Equals("iodef", StringComparison.OrdinalIgnoreCase));

    private static string? GetWindowsProductName()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            return key?.GetValue("ProductName") as string;
        }
        catch
        {
            return null;
        }
    }

    private static HttpClient CreateHttpClient()
    {
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false,
            AutomaticDecompression = DecompressionMethods.All
        };
        var client = new HttpClient(handler)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
        client.DefaultRequestHeaders.UserAgent.ParseAdd("MSTECH-IIS-SSL-Manager/1.0");
        return client;
    }
}
