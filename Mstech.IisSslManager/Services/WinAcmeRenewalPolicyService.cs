using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using Mstech.IisSslManager.Core;
using Mstech.IisSslManager.Infrastructure;

namespace Mstech.IisSslManager.Services;

public sealed record WinAcmeRenewalPreview
{
    public required string RenewalId { get; init; }
    public bool ExistingRenewal { get; init; }
    public required string ExpectedStateSha256 { get; init; }
    public IReadOnlyList<string> ExistingHostNames { get; init; } = [];
    public IReadOnlyList<string> RequestedHostNames { get; init; } = [];
    public IReadOnlyList<string> AddedHostNames { get; init; } = [];
    public IReadOnlyList<string> RemovedHostNames { get; init; } = [];
    public bool RequiresRemovalConfirmation => RemovedHostNames.Count > 0;
}

/// <summary>
/// Schema and identifiers verified against win-acme source 3f6d83bbbfbecef94ee5049fa2859f6f2cf84a24
/// (references/win-acme-source-3f6d83b.zip, SHA256 A9DD434DA0A490435D2B50FAE65E850C507A33C6C6428C29233C1BBF62268E3F).
/// See DomainObjects/Renewal.cs and each plugin's Options/OptionsFactory/Plugin attribute.
/// DefaultAsNull deliberately omits WebHosting, * and 443; absence is not a policy violation.
/// </summary>
public sealed class WinAcmeRenewalPolicyService
{
    internal const string ManualPlugin = "e239db3b-b42f-48aa-b64f-46d4f3e9941b";
    internal const string HttpSelfHostingPlugin = "c7d5e050-9363-4ba1-b3a8-931b31c618b7";
    internal const string RsaPlugin = "b9060d4b-c2d3-49ac-b37f-962e7c3cbe9d";
    internal const string SingleOrderPlugin = "b705fa7c-1152-4436-8913-e433d7f84c82";
    internal const string CertificateStorePlugin = "e30adc8e-d756-4e16-a6f2-450f784b1a97";
    internal const string IisPlugin = "ea6a5be3-f8de-4d27-a6bd-750b619b2ee2";
    internal const string ScriptPlugin = "3bb22c70-358d-4251-86bd-11858363d913";
    private const int MaximumStateFileBytes = 4 * 1024 * 1024;

    internal static string RetentionScriptPath => Path.Combine(AppPaths.ProgramDataRoot, "Scripts", "CertificateRetention.ps1");
    internal static string RetentionParameters =>
        $"-OldThumbprint \"{{OldCertThumbprint}}\" -NewThumbprint \"{{CertThumbprint}}\" -RetentionDays {CertificateRetentionService.RetentionDays}";

    public WinAcmeRenewalPreview ReadPreview(WinAcmeCertificateRequest request)
    {
        var renewalId = new WinAcmeCommandBuilder().GetProductionRenewalId(request);
        var path = GetRenewalPath(renewalId);
        // These checks must not use ProgramDataSecurity.Ensure*/Validate*: those methods
        // intentionally repair ACLs. A preview is a strictly read-only worker operation.
        RejectSidecars(path);
        return CreatePreview(request, ReadControlledFile(path, allowMissing: true));
    }

    internal static WinAcmeRenewalPreview CreatePreview(WinAcmeCertificateRequest request, byte[]? existingContent)
    {
        var expected = ExpectedRequest(request);
        IReadOnlyList<string> existingNames = [];
        if (existingContent is not null)
        {
            using var document = Parse(existingContent);
            RequireString(document.RootElement, "Id", expected.RenewalId, StringComparison.Ordinal);
            existingNames = ReadTarget(document.RootElement, out _);
            var installations = RequiredArray(document.RootElement, "InstallationPluginOptions");
            var iisSteps = installations.EnumerateArray().Where(item =>
                string.Equals(OptionalString(item, "Plugin"), IisPlugin, StringComparison.OrdinalIgnoreCase)).ToArray();
            Require(iisSteps.Length == 1 && RequiredLong(iisSteps[0], "SiteId") == request.SiteId,
                "既有 renewal 的 IIS Site ID 不符，無法安全預覽取代範圍。");
        }

        return new WinAcmeRenewalPreview
        {
            RenewalId = expected.RenewalId,
            ExistingRenewal = existingContent is not null,
            ExpectedStateSha256 = StateHash(existingContent),
            ExistingHostNames = existingNames,
            RequestedHostNames = expected.HostNames,
            AddedHostNames = expected.HostNames.Except(existingNames, StringComparer.OrdinalIgnoreCase).ToArray(),
            RemovedHostNames = existingNames.Except(expected.HostNames, StringComparer.OrdinalIgnoreCase).ToArray()
        };
    }

    internal static void ValidatePreviewConsent(
        WinAcmeCertificateRequest request, byte[]? existingContent,
        string? expectedStateSha256, bool confirmRemovedRenewalNames)
    {
        var preview = CreatePreview(request, existingContent);
        Require(expectedStateSha256 is { Length: 64 } &&
            string.Equals(preview.ExpectedStateSha256, expectedStateSha256, StringComparison.OrdinalIgnoreCase),
            "續期設定已變更或尚未完成預覽；請重新查看網域差異後再申請。");
        Require(!preview.RequiresRemovalConfirmation || confirmRemovedRenewalNames,
            "本次申請會移除既有自動續期網域，必須先明確確認移除清單。");
    }

    internal static string StateHash(byte[]? content) => Convert.ToHexString(SHA256.HashData(
        content ?? Encoding.UTF8.GetBytes("MSTECH renewal absent v1")));

    internal static void VerifyCommittedContent(byte[] content, WinAcmeCertificateRequest request, string effectiveDefaultStore)
    {
        var expected = ExpectedRequest(request);
        using var document = Parse(content);
        var root = document.RootElement;
        RequireString(root, "Id", expected.RenewalId, StringComparison.Ordinal);
        var names = ReadTarget(root, out var commonName);
        Require(names.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(expected.HostNames),
            "renewal 的完整 SAN 清單與本次申請不一致。");
        Require(string.Equals(commonName, expected.CommonName, StringComparison.OrdinalIgnoreCase),
            "renewal 的 CommonName 與本次申請不一致。");

        var validation = Plugin(root, "ValidationPluginOptions", HttpSelfHostingPlugin);
        Require((OptionalLong(validation, "Port") is null or 80) && OptionalBool(validation, "Https") is not true,
            "renewal 必須使用 Port 80 的 HTTP-01 SelfHosting。");
        var csr = Plugin(root, "CsrPluginOptions", RsaPlugin);
        Require(OptionalBool(csr, "OcspMustStaple") is not true && OptionalBool(csr, "ReusePrivateKey") is not true,
            "renewal 的 RSA 選項與工具政策不一致。");
        _ = Plugin(root, "OrderPluginOptions", SingleOrderPlugin);

        var stores = RequiredArray(root, "StorePluginOptions");
        Require(stores.GetArrayLength() == 1, "renewal 必須只有一個 Windows 憑證存放區步驟。");
        var store = stores[0];
        RequireString(store, "Plugin", CertificateStorePlugin);
        Require(string.Equals(OptionalString(store, "StoreName") ?? effectiveDefaultStore,
            "WebHosting", StringComparison.OrdinalIgnoreCase), "renewal 未使用 WebHosting 存放區。");
        Require(OptionalBool(store, "KeepExisting") == true, "renewal 未設定保留舊憑證。");
        Require(IsEmptyOptionalArray(store, "AclFullControl") && IsEmptyOptionalArray(store, "AclRead"),
            "renewal 包含工具未授權的私鑰權限設定。");

        var installations = RequiredArray(root, "InstallationPluginOptions");
        Require(installations.GetArrayLength() == 2, "renewal 必須依序包含 IIS 與舊憑證保留腳本兩個安裝步驟。");
        var iis = installations[0];
        RequireString(iis, "Plugin", IisPlugin);
        Require(RequiredLong(iis, "SiteId") == request.SiteId, "renewal 的 IIS Site ID 與本次申請不一致。");
        Require((OptionalLong(iis, "NewBindingPort") is null or 443) &&
            (OptionalString(iis, "NewBindingIp") is null or "*"), "renewal 的 IIS Binding 必須使用 *:443。");
        var script = installations[1];
        RequireString(script, "Plugin", ScriptPlugin);
        var scriptPath = RequiredString(script, "Script");
        Require(Path.IsPathFullyQualified(scriptPath) && string.Equals(Path.GetFullPath(scriptPath),
            Path.GetFullPath(RetentionScriptPath), StringComparison.OrdinalIgnoreCase),
            "renewal 的舊憑證保留腳本不是工具管理的固定路徑。");
        RequireString(script, "ScriptParameters", RetentionParameters, StringComparison.Ordinal);
    }

    internal static string ReadEffectiveDefaultStore()
    {
        var bytes = ReadControlledFile(Path.Combine(AppPaths.WinAcmeDirectory, "settings.json"), allowMissing: false)!;
        using var document = Parse(bytes);
        var store = RequiredObject(RequiredObject(document.RootElement, "Store"), "CertificateStore");
        var configured = OptionalString(store, "DefaultStore");
        // Pinned CertificateStore.DefaultStore selects WebHosting on supported IIS 10
        // when this setting is null/empty. Production already reruns the IIS preflight.
        return string.IsNullOrWhiteSpace(configured) ? "WebHosting" : configured;
    }

    internal static string GetRenewalPath(string renewalId) => Path.Combine(
        AppPaths.WinAcmeConfigurationDirectory, new Uri(WinAcmeRecommendedRelease.ProductionBaseUri).Host,
        renewalId + ".renewal.json");

    internal static void RejectSidecars(string path)
    {
        foreach (var sidecar in new[] { path + ".new", path + ".previous" })
        {
            Require(!ControlledPathExists(sidecar), "renewal 留有未完成寫入的 sidecar，請先人工檢查。");
        }
    }

    private static byte[]? ReadControlledFile(string path, bool allowMissing)
    {
        if (!ControlledPathExists(path))
        {
            if (allowMissing) return null;
            throw new InvalidDataException("找不到受控的 win-acme 設定檔。");
        }
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        Require(stream.Length <= MaximumStateFileBytes, "win-acme 設定檔超過安全大小上限。");
        using var output = new MemoryStream((int)stream.Length);
        stream.CopyTo(output);
        return output.ToArray();
    }

    private static bool ControlledPathExists(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var productRoot = Path.GetFullPath(AppPaths.ProgramDataRoot);
        Require(fullPath.StartsWith(productRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase),
            "續期預覽路徑不在工具受控目錄。");
        var current = Path.GetPathRoot(fullPath)!;
        var segments = fullPath[current.Length..].Split(Path.DirectorySeparatorChar, StringSplitOptions.RemoveEmptyEntries);
        foreach (var segment in segments)
        {
            current = Path.Combine(current, segment);
            FileAttributes attributes;
            try { attributes = File.GetAttributes(current); }
            catch (FileNotFoundException) { return false; }
            catch (DirectoryNotFoundException) { return false; }
            Require(!attributes.HasFlag(FileAttributes.ReparsePoint), "續期預覽路徑包含 Reparse Point，已拒絕讀取。");
            if (!string.Equals(current, fullPath, StringComparison.OrdinalIgnoreCase))
                Require(attributes.HasFlag(FileAttributes.Directory), "續期預覽路徑被檔案占用。");
            if (current.Length >= productRoot.Length)
                ValidateReadOnlyAcl(current, attributes.HasFlag(FileAttributes.Directory));
        }
        return true;
    }

    private static void ValidateReadOnlyAcl(string path, bool directory)
    {
        FileSystemSecurity security = directory
            ? new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access)
            : new FileInfo(path).GetAccessControl(AccessControlSections.Owner | AccessControlSections.Access);
        var owner = (SecurityIdentifier?)security.GetOwner(typeof(SecurityIdentifier));
        Require(IsTrustedSid(owner), "續期預覽設定的擁有者不是 Administrators／SYSTEM。");
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (rule.AccessControlType == AccessControlType.Allow &&
                ProgramDataSecurity.GrantsDangerousWriteAccess(rule.FileSystemRights) &&
                !IsTrustedSid(rule.IdentityReference as SecurityIdentifier))
                throw new InvalidDataException("續期預覽設定包含非預期的寫入權限。");
        }
    }

    private static bool IsTrustedSid(SecurityIdentifier? sid) => sid is not null &&
        (sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) || sid.IsWellKnown(WellKnownSidType.LocalSystemSid));

    private static (string RenewalId, string[] HostNames, string CommonName) ExpectedRequest(WinAcmeCertificateRequest request)
    {
        var builder = new WinAcmeCommandBuilder();
        var command = builder.BuildProductionIssuance(request, RetentionScriptPath);
        string Option(string name) => command.Arguments[command.Arguments.ToList().IndexOf(name) + 1];
        return (Option("--id"), Option("--host").Split(','), Option("--commonname"));
    }

    private static IReadOnlyList<string> ReadTarget(JsonElement root, out string commonName)
    {
        var target = Plugin(root, "TargetPluginOptions", ManualPlugin);
        var names = RequiredArray(target, "AlternativeNames");
        Require(names.GetArrayLength() is >= 1 and <= 100, "renewal 的 SAN 清單數量無效。");
        var result = names.EnumerateArray().Select(item => NormalizeHost(item.GetString())).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        commonName = NormalizeHost(RequiredString(target, "CommonName"));
        Require(result.Contains(commonName, StringComparer.OrdinalIgnoreCase), "renewal 的 CommonName 不在 SAN 清單內。");
        return result;
    }

    private static string NormalizeHost(string? host)
    {
        Require(DomainNameValidator.TryNormalize(host ?? "", out var normalized, out _), "renewal 含有無效的網域名稱。");
        return normalized;
    }

    private static JsonDocument Parse(byte[] bytes)
    {
        Require(bytes.Length <= MaximumStateFileBytes, "renewal JSON 超過安全大小上限。");
        JsonDocument document;
        try { document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 64 }); }
        catch (JsonException) { throw new InvalidDataException("renewal／設定 JSON 格式無效，已停止操作。"); }
        try
        {
            Require(document.RootElement.ValueKind == JsonValueKind.Object, "renewal／設定 JSON 必須是物件。");
            RejectDuplicateProperties(document.RootElement);
            return document;
        }
        catch { document.Dispose(); throw; }
    }

    private static void RejectDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var property in element.EnumerateObject())
            {
                Require(names.Add(property.Name), "renewal／設定 JSON 包含重複欄位。");
                RejectDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (var item in element.EnumerateArray()) RejectDuplicateProperties(item);
    }

    private static JsonElement Plugin(JsonElement root, string name, string id)
    {
        var plugin = RequiredObject(root, name);
        RequireString(plugin, "Plugin", id);
        return plugin;
    }
    private static JsonElement RequiredObject(JsonElement parent, string name) => Required(parent, name, JsonValueKind.Object);
    private static JsonElement RequiredArray(JsonElement parent, string name) => Required(parent, name, JsonValueKind.Array);
    private static JsonElement Required(JsonElement parent, string name, JsonValueKind kind)
    {
        Require(parent.ValueKind == JsonValueKind.Object && parent.TryGetProperty(name, out _), $"renewal／設定缺少 {name}。");
        var value = parent.GetProperty(name);
        Require(value.ValueKind == kind, $"renewal／設定的 {name} 格式錯誤。");
        return value;
    }
    private static string RequiredString(JsonElement parent, string name) => Required(parent, name, JsonValueKind.String).GetString()!;
    private static string? OptionalString(JsonElement parent, string name)
    {
        if (parent.ValueKind == JsonValueKind.Object && (!parent.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null)) return null;
        return RequiredString(parent, name);
    }
    private static long RequiredLong(JsonElement parent, string name)
    {
        var value = Required(parent, name, JsonValueKind.Number);
        Require(value.TryGetInt64(out var number), $"renewal 的 {name} 必須是整數。");
        return number;
    }
    private static long? OptionalLong(JsonElement parent, string name) =>
        !parent.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null ? null : RequiredLong(parent, name);
    private static bool? OptionalBool(JsonElement parent, string name)
    {
        if (!parent.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return null;
        Require(value.ValueKind is JsonValueKind.True or JsonValueKind.False, $"renewal 的 {name} 必須是布林值。");
        return value.GetBoolean();
    }
    private static bool IsEmptyOptionalArray(JsonElement parent, string name) =>
        !parent.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null ||
        (value.ValueKind == JsonValueKind.Array && value.GetArrayLength() == 0);
    private static void RequireString(JsonElement parent, string name, string expected, StringComparison comparison = StringComparison.OrdinalIgnoreCase) =>
        Require(string.Equals(RequiredString(parent, name), expected, comparison), $"renewal 的 {name} 與本次申請政策不一致。");
    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidDataException(message);
    }
}
