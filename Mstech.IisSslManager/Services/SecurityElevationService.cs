using System.IO;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Mstech.IisSslManager.Core;
using Mstech.IisSslManager.Infrastructure;
using Mstech.IisSslManager.Models;

namespace Mstech.IisSslManager.Services;

public enum ElevatedWorkerAction
{
    LocalEnvironmentCheck,
    InstallWinAcme,
    RunWinAcme,
    ReadRenewalPreview,
    ReadMaintenanceStatus
}

public sealed record ReadRenewalPreviewPayload
{
    public required WinAcmeCertificateRequest CertificateRequest { get; init; }
}

public sealed record ReadMaintenanceStatusPayload;

public sealed record ElevatedWorkerRequest
{
    public int ProtocolVersion { get; init; } = ElevationService.WorkerProtocolVersion;

    public required ElevatedWorkerAction Action { get; init; }

    /// <summary>
    /// Action-specific JSON. It must never contain a Windows password.
    /// </summary>
    public required string PayloadJson { get; init; }
}

internal sealed record AuthenticatedElevatedWorkerResult
{
    public int ProtocolVersion { get; init; } = ElevationService.WorkerProtocolVersion;

    public required string ResultJson { get; init; }

    public required string AuthenticationTag { get; init; }
}

public sealed record ElevatedWorkerResult
{
    public required bool Success { get; init; }

    public int? ExitCode { get; init; }

    public string StdOut { get; init; } = string.Empty;

    public string StdErr { get; init; } = string.Empty;

    public string? ErrorMessage { get; init; }

    public string? PayloadJson { get; init; }
}

/// <summary>
/// Delegates administrator authentication to Windows UAC. This application never
/// asks for, receives, or stores a Windows administrator password.
/// </summary>
public sealed class ElevationService
{
    public const string WorkerSwitch = "--elevated-worker";
    public const int WorkerProtocolVersion = 2;
    private const int ErrorAlreadyExists = 183;
    private const int MaximumProtocolFileBytes = 2 * 1024 * 1024;
    private const int MaximumPayloadCharacters = 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 64,
        WriteIndented = false
    };

    private readonly IProcessRunner _processRunner;

    public ElevationService(IProcessRunner processRunner)
    {
        _processRunner = processRunner ?? throw new ArgumentNullException(nameof(processRunner));
    }

    public bool IsAdministrator => SecurityArgumentService.IsCurrentProcessAdministrator();

    public async Task<ElevatedWorkerResult> RunWorkerAsync(
        ElevatedWorkerAction action,
        string payloadJson,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        ValidatePayloadJson(payloadJson);
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable))
        {
            return Failure("無法判斷目前程式執行檔路徑。");
        }

        var exchangeDirectory = CreateSecureExchangeDirectory();
        var requestPath = Path.Combine(exchangeDirectory, "request.json");
        var resultPath = Path.Combine(exchangeDirectory, "result.json");

        try
        {
            var request = new ElevatedWorkerRequest
            {
                Action = action,
                PayloadJson = payloadJson
            };
            var requestBytes = JsonSerializer.SerializeToUtf8Bytes(request, JsonOptions);
            if (requestBytes.Length > MaximumProtocolFileBytes)
            {
                return Failure("提升權限 worker 請求內容過大。");
            }

            var requestSha256 = Convert.ToHexString(SHA256.HashData(requestBytes));
            var resultAuthenticationKey = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            await WriteBytesCreateNewAsync(requestPath, requestBytes, cancellationToken)
                .ConfigureAwait(false);

            var processResult = await RunAsAdministratorAsync(
                executable,
                [WorkerSwitch, requestPath, resultPath, requestSha256, resultAuthenticationKey],
                AppContext.BaseDirectory,
                timeout ?? TimeSpan.FromMinutes(30),
                cancellationToken).ConfigureAwait(false);

            if (processResult.ElevationWasCancelled)
            {
                return Failure("使用者取消了 Windows 管理員權限驗證。");
            }

            if (processResult.TimedOut)
            {
                return Failure("系統管理員操作逾時。", processResult.ExitCode);
            }

            if (processResult.WasCancelled)
            {
                return Failure("系統管理員操作已取消。", processResult.ExitCode);
            }

            if (!File.Exists(resultPath))
            {
                return Failure(
                    processResult.ErrorMessage ?? "提升權限的背景程序未產生結果。",
                    processResult.ExitCode);
            }

            var workerResult = await ReadWorkerResultAsync(
                    resultPath,
                    resultAuthenticationKey,
                    cancellationToken)
                .ConfigureAwait(false);
            if (processResult.ExitCode is not null && workerResult.ExitCode is null)
            {
                workerResult = workerResult with { ExitCode = processResult.ExitCode };
            }

            // A pre-created or replaced result file must never turn a worker that
            // exited with failure into a successful gate result.
            if (processResult.ExitCode is not null and not 0 && workerResult.Success)
            {
                workerResult = workerResult with
                {
                    Success = false,
                    ExitCode = processResult.ExitCode,
                    ErrorMessage = processResult.ErrorMessage ??
                        $"提升權限 worker 以錯誤碼 {processResult.ExitCode} 結束，結果不予採信。"
                };
            }

            return workerResult;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return Failure("系統管理員操作已取消。");
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or JsonException or
            InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return Failure(exception.Message);
        }
        finally
        {
            TryDeleteExchangeDirectory(exchangeDirectory);
        }
    }

    public Task<ProcessResult> RunAsAdministratorAsync(
        string executablePath,
        IReadOnlyList<string> arguments,
        string? workingDirectory = null,
        TimeSpan? timeout = null,
        CancellationToken cancellationToken = default)
    {
        var normalized = ValidateExecutable(executablePath);
        ArgumentNullException.ThrowIfNull(arguments);

        return _processRunner.RunAsync(new ProcessRequest
        {
            FileName = normalized,
            Arguments = arguments.ToArray(),
            WorkingDirectory = workingDirectory ?? Path.GetDirectoryName(normalized),
            Timeout = timeout ?? TimeSpan.FromMinutes(20),
            RunAsAdministrator = true,
            CreateNoWindow = false
        }, cancellationToken);
    }

    public Task<ProcessResult> RelaunchCurrentApplicationAsync(
        IReadOnlyList<string> arguments,
        CancellationToken cancellationToken = default)
    {
        var executable = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(executable))
        {
            throw new InvalidOperationException("無法判斷目前程式執行檔路徑。");
        }

        return RunAsAdministratorAsync(
            executable,
            arguments,
            AppContext.BaseDirectory,
            TimeSpan.FromMinutes(30),
            cancellationToken);
    }

    /// <summary>
    /// Called by the elevated application entry point. Request and result must be
    /// sibling files in the private exchange directory created by RunWorkerAsync.
    /// </summary>
    public static async Task<ElevatedWorkerRequest> ReadWorkerRequestAsync(
        string requestPath,
        string expectedSha256,
        CancellationToken cancellationToken = default)
    {
        var normalized = ValidateWorkerFilePath(requestPath, "request.json", mustExist: true);
        var expectedHash = ValidateSha256(expectedSha256);
        var bytes = await ReadProtocolBytesAsync(normalized, cancellationToken).ConfigureAwait(false);
        var actualHash = Convert.ToHexString(SHA256.HashData(bytes));
        if (!CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(actualHash),
                Convert.FromHexString(expectedHash)))
        {
            throw new InvalidDataException("提升權限 worker 請求在 UAC 啟動前後遭到變更，已拒絕執行。");
        }

        var result = JsonSerializer.Deserialize<ElevatedWorkerRequest>(bytes, JsonOptions)
            ?? throw new InvalidDataException("提升權限 worker 協定檔內容為空。");
        if (result.ProtocolVersion != WorkerProtocolVersion)
        {
            throw new InvalidDataException($"不支援的提升權限 worker 協定版本：{result.ProtocolVersion}");
        }

        ValidatePayloadJson(result.PayloadJson);
        return result;
    }

    /// <summary>
    /// Called by the elevated worker. Uses CreateNew so a caller cannot ask the
    /// administrator process to overwrite an existing file.
    /// </summary>
    public static Task WriteWorkerResultAsync(
        string resultPath,
        ElevatedWorkerResult result,
        string resultAuthenticationKey,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(result);
        var normalized = ValidateWorkerFilePath(resultPath, "result.json", mustExist: false);
        var envelopeBytes = Encoding.UTF8.GetBytes(
            CreateAuthenticatedResultEnvelope(result, resultAuthenticationKey));
        if (envelopeBytes.Length > MaximumProtocolFileBytes)
        {
            throw new InvalidDataException("提升權限 worker 結果內容過大。");
        }

        return WriteBytesCreateNewAsync(normalized, envelopeBytes, cancellationToken);
    }

    public static bool TryParseWorkerArguments(
        IReadOnlyList<string> arguments,
        out string requestPath,
        out string resultPath,
        out string requestSha256,
        out string resultAuthenticationKey)
    {
        requestPath = string.Empty;
        resultPath = string.Empty;
        requestSha256 = string.Empty;
        resultAuthenticationKey = string.Empty;
        if (arguments.Count != 5 ||
            !string.Equals(arguments[0], WorkerSwitch, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        try
        {
            requestPath = ValidateWorkerFilePath(arguments[1], "request.json", mustExist: true);
            resultPath = ValidateWorkerFilePath(arguments[2], "result.json", mustExist: false);
            requestSha256 = ValidateSha256(arguments[3]);
            resultAuthenticationKey = ValidateAuthenticationKey(arguments[4]);
            return string.Equals(
                Path.GetDirectoryName(requestPath),
                Path.GetDirectoryName(resultPath),
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (
            exception is ArgumentException or IOException or UnauthorizedAccessException)
        {
            requestPath = string.Empty;
            resultPath = string.Empty;
            requestSha256 = string.Empty;
            resultAuthenticationKey = string.Empty;
            return false;
        }
    }

    internal static string CreateAuthenticatedResultEnvelope(
        ElevatedWorkerResult result,
        string resultAuthenticationKey)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (result.PayloadJson is not null)
        {
            ValidatePayloadJson(result.PayloadJson);
        }

        var key = Convert.FromHexString(ValidateAuthenticationKey(resultAuthenticationKey));
        var resultJson = JsonSerializer.Serialize(result, JsonOptions);
        if (resultJson.Length > MaximumPayloadCharacters)
        {
            throw new InvalidDataException("提升權限 worker 結果 Payload 過大。");
        }

        var authenticationTag = Convert.ToHexString(
            HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(resultJson)));
        return JsonSerializer.Serialize(new AuthenticatedElevatedWorkerResult
        {
            ResultJson = resultJson,
            AuthenticationTag = authenticationTag
        }, JsonOptions);
    }

    internal static ElevatedWorkerResult ParseAuthenticatedResultEnvelope(
        string envelopeJson,
        string resultAuthenticationKey)
    {
        if (string.IsNullOrWhiteSpace(envelopeJson) ||
            envelopeJson.Length > MaximumProtocolFileBytes)
        {
            throw new InvalidDataException("提升權限 worker 結果封包為空或過大。");
        }

        var envelope = JsonSerializer.Deserialize<AuthenticatedElevatedWorkerResult>(
                envelopeJson,
                JsonOptions)
            ?? throw new InvalidDataException("提升權限 worker 結果封包為空。");
        if (envelope.ProtocolVersion != WorkerProtocolVersion)
        {
            throw new InvalidDataException(
                $"不支援的提升權限 worker 結果協定版本：{envelope.ProtocolVersion}");
        }

        if (string.IsNullOrWhiteSpace(envelope.ResultJson) ||
            envelope.ResultJson.Length > MaximumPayloadCharacters)
        {
            throw new InvalidDataException("提升權限 worker 結果內容為空或過大。");
        }

        var key = Convert.FromHexString(ValidateAuthenticationKey(resultAuthenticationKey));
        var expectedTag = Convert.FromHexString(ValidateSha256(envelope.AuthenticationTag));
        var actualTag = HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(envelope.ResultJson));
        if (!CryptographicOperations.FixedTimeEquals(actualTag, expectedTag))
        {
            throw new InvalidDataException(
                "提升權限 worker 結果驗證失敗，檔案可能在 UAC 執行後遭到置換。");
        }

        var result = JsonSerializer.Deserialize<ElevatedWorkerResult>(envelope.ResultJson, JsonOptions)
            ?? throw new InvalidDataException("提升權限 worker 結果內容為空。");
        if (result.PayloadJson is not null)
        {
            ValidatePayloadJson(result.PayloadJson);
        }

        return result;
    }

    private static string ValidateSha256(string value)
    {
        var normalized = (value ?? string.Empty).Trim().ToUpperInvariant();
        if (normalized.Length != 64 || normalized.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new ArgumentException("提升權限 worker 請求摘要格式錯誤。", nameof(value));
        }

        return normalized;
    }

    private static string ValidateAuthenticationKey(string value)
    {
        var normalized = (value ?? string.Empty).Trim().ToUpperInvariant();
        if (normalized.Length != 64 || normalized.Any(character => !Uri.IsHexDigit(character)))
        {
            throw new ArgumentException("提升權限 worker 結果驗證金鑰格式錯誤。", nameof(value));
        }

        return normalized;
    }

    private static string ValidateExecutable(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        var fullPath = Path.GetFullPath(executablePath.Trim().Trim('"'));
        if (!string.Equals(Path.GetExtension(fullPath), ".exe", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("只能透過 UAC 啟動 Windows 執行檔。", nameof(executablePath));
        }

        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("找不到要提升權限的執行檔。", fullPath);
        }

        return fullPath;
    }

    private static string CreateSecureExchangeDirectory()
    {
        var root = EnsureSecureExchangeRoot();
        var path = Path.Combine(root, Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        RejectReparsePointsBelowProgramData(path);

        try
        {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
            var currentSid = WindowsIdentity.GetCurrent().User
                ?? throw new InvalidOperationException("無法取得目前 Windows 使用者 SID。");
            security.AddAccessRule(new FileSystemAccessRule(
                currentSid,
                FileSystemRights.FullControl,
                inheritance,
                PropagationFlags.None,
                AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                FileSystemRights.FullControl,
                inheritance,
                PropagationFlags.None,
                AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl,
                inheritance,
                PropagationFlags.None,
                AccessControlType.Allow));
            new DirectoryInfo(path).SetAccessControl(security);
            RejectReparsePointsBelowProgramData(path);
            ValidateExchangeRootSecurity(new DirectoryInfo(root));
            ValidateExchangeDirectorySecurity(new DirectoryInfo(path));
            return path;
        }
        catch
        {
            TryDeleteExchangeDirectory(path);
            throw;
        }
    }

    private static string EnsureSecureExchangeRoot()
    {
        var root = Path.GetFullPath(AppPaths.ElevationExchangeDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        RejectReparsePointsBelowProgramData(root);

        var rootSecurity = CreateExchangeRootSecurity();
        if (!Directory.Exists(root))
        {
            CreateDirectoryWithSecurity(root, rootSecurity);
        }

        RejectReparsePointsBelowProgramData(root);
        var rootInfo = new DirectoryInfo(root);
        if (!rootInfo.Exists || rootInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new IOException("提升權限 worker 根交換目錄不存在或不安全。");
        }

        ValidateExchangeRootSecurity(rootInfo);
        return root;
    }

    private static DirectorySecurity CreateExchangeRootSecurity()
    {
        var currentSid = WindowsIdentity.GetCurrent().User
            ?? throw new InvalidOperationException("無法取得目前 Windows 使用者 SID。");
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var authenticatedUsers = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
        var ownerRights = new SecurityIdentifier("S-1-3-4");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(currentSid);

        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        security.AddAccessRule(new FileSystemAccessRule(
            administrators,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            system,
            FileSystemRights.FullControl,
            inheritance,
            PropagationFlags.None,
            AccessControlType.Allow));

        // This-folder-only permission lets a standard authenticated user create an
        // unpredictable private child before the over-the-shoulder UAC process starts.
        security.AddAccessRule(new FileSystemAccessRule(
            authenticatedUsers,
            ExchangeRootCreateRights,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow));

        // A newly created directory is owned by its standard-user creator. OWNER RIGHTS
        // replaces the owner's implicit READ_CONTROL/WRITE_DAC grant, so that creator
        // cannot later broaden the shared root ACL or access another user's GUID child.
        security.AddAccessRule(new FileSystemAccessRule(
            ownerRights,
            ExchangeRootOwnerRights,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow));
        return security;
    }

    private static void CreateDirectoryWithSecurity(string path, DirectorySecurity security)
    {
        var descriptor = security.GetSecurityDescriptorBinaryForm();
        var descriptorHandle = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
        try
        {
            var attributes = new SecurityAttributes
            {
                Length = Marshal.SizeOf<SecurityAttributes>(),
                SecurityDescriptor = descriptorHandle.AddrOfPinnedObject(),
                InheritHandle = false
            };
            if (CreateDirectoryNative(path, ref attributes))
            {
                return;
            }

            var error = Marshal.GetLastWin32Error();
            if (error != ErrorAlreadyExists)
            {
                throw new Win32Exception(error, $"無法建立安全的提升權限 worker 根交換目錄：{path}");
            }
        }
        finally
        {
            descriptorHandle.Free();
        }
    }

    private static string ValidateWorkerFilePath(string path, string expectedName, bool mustExist)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        if (!string.Equals(Path.GetFileName(fullPath), expectedName, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("提升權限 worker 檔案名稱不正確。", nameof(path));
        }

        var directory = Path.GetDirectoryName(fullPath)
            ?? throw new ArgumentException("提升權限 worker 路徑沒有父目錄。", nameof(path));
        var expectedRoot = Path.GetFullPath(AppPaths.ElevationExchangeDirectory)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var actualRoot = Path.GetDirectoryName(
            directory.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        if (!string.Equals(actualRoot, expectedRoot, StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("提升權限 worker 路徑不在受控交換目錄中。", nameof(path));
        }

        var leaf = Path.GetFileName(directory);
        if (leaf.Length != 32 || !Guid.TryParseExact(leaf, "N", out _))
        {
            throw new ArgumentException("提升權限 worker 交換目錄格式不正確。", nameof(path));
        }

        var rootInfo = new DirectoryInfo(expectedRoot);
        var directoryInfo = new DirectoryInfo(directory);
        if (!rootInfo.Exists || rootInfo.Attributes.HasFlag(FileAttributes.ReparsePoint) ||
            !directoryInfo.Exists || directoryInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new IOException("提升權限 worker 交換目錄不存在或不安全。");
        }

        RejectReparsePointsBelowProgramData(directory);

        ValidateExchangeRootSecurity(rootInfo);
        ValidateExchangeDirectorySecurity(directoryInfo);

        if (mustExist)
        {
            var fileInfo = new FileInfo(fullPath);
            if (!fileInfo.Exists || fileInfo.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw new IOException("提升權限 worker 請求檔不存在或不安全。");
            }
        }
        else if (File.Exists(fullPath) || Directory.Exists(fullPath))
        {
            throw new IOException("提升權限 worker 結果檔已存在，拒絕覆寫。");
        }

        return fullPath;
    }

    private const FileSystemRights ExchangeRootCreateRights =
        FileSystemRights.CreateDirectories |
        FileSystemRights.Traverse |
        FileSystemRights.ReadAttributes |
        FileSystemRights.ReadExtendedAttributes |
        FileSystemRights.ReadPermissions;

    private const FileSystemRights ExchangeRootOwnerRights =
        FileSystemRights.Traverse |
        FileSystemRights.ReadAttributes |
        FileSystemRights.ReadExtendedAttributes |
        FileSystemRights.ReadPermissions;

    private static void ValidateExchangeRootSecurity(DirectoryInfo directory)
    {
        var security = directory.GetAccessControl(
            AccessControlSections.Access | AccessControlSections.Owner);
        if (!security.AreAccessRulesProtected)
        {
            throw new UnauthorizedAccessException("提升權限 worker 根交換目錄未使用受保護的 ACL。");
        }

        _ = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier
            ?? throw new UnauthorizedAccessException("無法確認提升權限 worker 根交換目錄擁有者。");

        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var authenticatedUsers = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
        var ownerRights = new SecurityIdentifier("S-1-3-4");
        var rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            targetType: typeof(SecurityIdentifier));
        var hasAdministrators = false;
        var hasSystem = false;
        var hasAuthenticatedUsers = false;
        var hasOwnerRights = false;
        var inheritance = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;
        var limitedCreateRights = ExchangeRootCreateRights | FileSystemRights.Synchronize;
        var limitedOwnerRights = ExchangeRootOwnerRights | FileSystemRights.Synchronize;

        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.IsInherited || rule.AccessControlType != AccessControlType.Allow)
            {
                throw new UnauthorizedAccessException("提升權限 worker 根交換目錄包含非預期的繼承或拒絕 ACL。");
            }

            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (sid.Equals(administrators) || sid.Equals(system))
            {
                if ((rule.FileSystemRights & FileSystemRights.FullControl) != FileSystemRights.FullControl ||
                    rule.InheritanceFlags != inheritance ||
                    rule.PropagationFlags != PropagationFlags.None)
                {
                    throw new UnauthorizedAccessException("提升權限 worker 根交換目錄的系統 ACL 不完整。");
                }

                hasAdministrators |= sid.Equals(administrators);
                hasSystem |= sid.Equals(system);
                continue;
            }

            if (sid.Equals(authenticatedUsers))
            {
                if (rule.InheritanceFlags != InheritanceFlags.None ||
                    rule.PropagationFlags != PropagationFlags.None ||
                    (rule.FileSystemRights & ~limitedCreateRights) != 0 ||
                    (rule.FileSystemRights & ExchangeRootCreateRights) != ExchangeRootCreateRights)
                {
                    throw new UnauthorizedAccessException(
                        "Authenticated Users 在提升權限 worker 根交換目錄具有超出建立子目錄所需的權限。");
                }

                hasAuthenticatedUsers = true;
                continue;
            }

            if (sid.Equals(ownerRights))
            {
                if (rule.InheritanceFlags != InheritanceFlags.None ||
                    rule.PropagationFlags != PropagationFlags.None ||
                    (rule.FileSystemRights & ~limitedOwnerRights) != 0 ||
                    (rule.FileSystemRights & ExchangeRootOwnerRights) != ExchangeRootOwnerRights)
                {
                    throw new UnauthorizedAccessException(
                        "提升權限 worker 根交換目錄的 OWNER RIGHTS ACL 不安全。");
                }

                hasOwnerRights = true;
                continue;
            }

            throw new UnauthorizedAccessException(
                $"提升權限 worker 根交換目錄包含非預期的 ACL：{sid.Value}");
        }

        if (!hasAdministrators || !hasSystem || !hasAuthenticatedUsers || !hasOwnerRights)
        {
            throw new UnauthorizedAccessException("提升權限 worker 根交換目錄缺少必要 ACL。");
        }
    }

    private static void RejectReparsePointsBelowProgramData(string targetPath)
    {
        var programData = Path.GetFullPath(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData))
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var target = Path.GetFullPath(targetPath)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!target.StartsWith(programData + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new IOException("提升權限 worker 交換目錄不在 ProgramData 中。");
        }

        DirectoryInfo? current = new(target);
        var reachedBase = false;
        while (current is not null)
        {
            if (current.Exists && current.Attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw new IOException($"提升權限 worker 路徑包含 Reparse Point：{current.FullName}");
            }

            if (string.Equals(
                    current.FullName.TrimEnd(Path.DirectorySeparatorChar),
                    programData,
                    StringComparison.OrdinalIgnoreCase))
            {
                reachedBase = true;
                break;
            }

            current = current.Parent;
        }

        if (!reachedBase)
        {
            throw new IOException("無法驗證提升權限 worker 交換目錄的 ProgramData 邊界。");
        }
    }

    private static void ValidateExchangeDirectorySecurity(DirectoryInfo directory)
    {
        var security = directory.GetAccessControl(
            AccessControlSections.Access | AccessControlSections.Owner);
        if (!security.AreAccessRulesProtected)
        {
            throw new UnauthorizedAccessException("提升權限 worker 交換目錄未使用受保護的 ACL。");
        }

        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier
            ?? throw new UnauthorizedAccessException("無法確認提升權限 worker 交換目錄擁有者。");
        var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);
        var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
        var allowedWriters = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            owner.Value,
            administrators.Value,
            system.Value
        };
        var dangerousRights = FileSystemRights.Write | FileSystemRights.Modify |
                              FileSystemRights.FullControl | FileSystemRights.Delete |
                              FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership;
        var rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            targetType: typeof(SecurityIdentifier));
        var hasAdministrators = false;
        var hasSystem = false;
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow)
            {
                continue;
            }

            var sid = (SecurityIdentifier)rule.IdentityReference;
            hasAdministrators |= sid.Equals(administrators);
            hasSystem |= sid.Equals(system);
            if ((rule.FileSystemRights & dangerousRights) != 0 &&
                !allowedWriters.Contains(sid.Value))
            {
                throw new UnauthorizedAccessException("提升權限 worker 交換目錄允許非預期帳號寫入。");
            }
        }

        if (!hasAdministrators || !hasSystem)
        {
            throw new UnauthorizedAccessException("提升權限 worker 交換目錄缺少 Administrators 或 SYSTEM ACL。");
        }
    }

    private static void ValidatePayloadJson(string payloadJson)
    {
        if (string.IsNullOrWhiteSpace(payloadJson) || payloadJson.Length > MaximumPayloadCharacters)
        {
            throw new ArgumentException("提升權限 worker PayloadJson 為空或過大。", nameof(payloadJson));
        }

        using var _ = JsonDocument.Parse(payloadJson, new JsonDocumentOptions
        {
            AllowTrailingCommas = false,
            CommentHandling = JsonCommentHandling.Disallow,
            MaxDepth = 64
        });
    }

    private static async Task<T> ReadJsonAsync<T>(
        string path,
        CancellationToken cancellationToken)
    {
        var bytes = await ReadProtocolBytesAsync(path, cancellationToken).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(bytes, JsonOptions)
            ?? throw new InvalidDataException("提升權限 worker 協定檔內容為空。");
    }

    private static async Task<byte[]> ReadProtocolBytesAsync(
        string path,
        CancellationToken cancellationToken)
    {
        var info = new FileInfo(path);
        if (!info.Exists || info.Length is <= 0 or > MaximumProtocolFileBytes)
        {
            throw new InvalidDataException("提升權限 worker 協定檔不存在、為空或過大。");
        }

        await using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        using var buffer = new MemoryStream((int)info.Length);
        var chunk = new byte[64 * 1024];
        while (true)
        {
            var read = await stream.ReadAsync(chunk, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            if (buffer.Length + read > MaximumProtocolFileBytes)
            {
                throw new InvalidDataException("提升權限 worker 協定檔讀取時超過大小限制。");
            }

            await buffer.WriteAsync(chunk.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
        }

        if (buffer.Length is <= 0 or > MaximumProtocolFileBytes)
        {
            throw new InvalidDataException("提升權限 worker 協定檔讀取後大小異常。");
        }

        return buffer.ToArray();
    }

    private static async Task<ElevatedWorkerResult> ReadWorkerResultAsync(
        string path,
        string resultAuthenticationKey,
        CancellationToken cancellationToken)
    {
        var normalized = ValidateWorkerFilePath(path, "result.json", mustExist: true);
        var bytes = await ReadProtocolBytesAsync(normalized, cancellationToken).ConfigureAwait(false);
        return ParseAuthenticatedResultEnvelope(Encoding.UTF8.GetString(bytes), resultAuthenticationKey);
    }

    private static async Task WriteBytesCreateNewAsync(
        string path,
        ReadOnlyMemory<byte> bytes,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.WriteThrough);
        await stream.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private static ElevatedWorkerResult Failure(string message, int? exitCode = null) => new()
    {
        Success = false,
        ExitCode = exitCode,
        ErrorMessage = message
    };

    private static void TryDeleteExchangeDirectory(string path)
    {
        try
        {
            var parent = Path.GetFullPath(AppPaths.ElevationExchangeDirectory)
                .TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            var fullPath = Path.GetFullPath(path);
            if (fullPath.StartsWith(parent, StringComparison.OrdinalIgnoreCase) &&
                Path.GetFileName(fullPath).Length == 32 &&
                Guid.TryParseExact(Path.GetFileName(fullPath), "N", out _) &&
                Directory.Exists(fullPath) &&
                !File.GetAttributes(fullPath).HasFlag(FileAttributes.ReparsePoint))
            {
                // Only remove the two protocol files owned by this application.
                // Never recurse through content that another same-user process may
                // have placed in the exchange directory while UAC was visible.
                foreach (var fileName in new[] { "request.json", "result.json" })
                {
                    var filePath = Path.Combine(fullPath, fileName);
                    if (File.Exists(filePath) &&
                        !File.GetAttributes(filePath).HasFlag(FileAttributes.ReparsePoint))
                    {
                        File.Delete(filePath);
                    }
                }

                if (!Directory.EnumerateFileSystemEntries(fullPath).Any())
                {
                    Directory.Delete(fullPath, recursive: false);
                }
            }
        }
        catch
        {
            // Exchange data contains no Windows credential. Do not mask the original
            // worker result merely because best-effort cleanup failed.
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        public int Length;
        public IntPtr SecurityDescriptor;

        [MarshalAs(UnmanagedType.Bool)]
        public bool InheritHandle;
    }

    [DllImport(
        "kernel32.dll",
        EntryPoint = "CreateDirectoryW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryNative(
        string path,
        ref SecurityAttributes securityAttributes);
}
