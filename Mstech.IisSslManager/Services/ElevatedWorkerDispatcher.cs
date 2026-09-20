using System.Text.Json;
using System.Text.Json.Serialization;
using Mstech.IisSslManager.Core;
using Mstech.IisSslManager.Infrastructure;
using Mstech.IisSslManager.Models;

namespace Mstech.IisSslManager.Services;

public enum WinAcmeWorkerOperation
{
    StagingValidation,
    ProductionIssuance
}

public sealed record RunWinAcmeWorkerPayload
{
    public required WinAcmeWorkerOperation Operation { get; init; }

    public required string WinAcmePath { get; init; }

    public required string ExpectedExecutableSha256 { get; init; }

    public required WinAcmeCertificateRequest CertificateRequest { get; init; }

    public string? ExpectedRenewalStateSha256 { get; init; }

    public bool ConfirmRemovedRenewalNames { get; init; }
}

public sealed record RunWinAcmeWorkerOutput
{
    public required WinAcmeWorkerOperation Operation { get; init; }

    public required string SafeCommandLine { get; init; }

    public string? IisBackupName { get; init; }

    public bool IisBindingsVerified { get; init; }

    public string? NewCertificateThumbprint { get; init; }

    public string? BindingVerificationSummary { get; init; }

    public bool CertificateWasNew { get; init; }

    public string? RenewalId { get; init; }

    public bool RenewalStateRestored { get; init; }

    public string? RenewalStateSummary { get; init; }

    public bool RollbackAttempted { get; init; }

    public bool RollbackSucceeded { get; init; }

    public bool RenewalTaskReady { get; init; }

    public string? RenewalTaskSummary { get; init; }

    public bool TemporaryCleanupSucceeded { get; init; } = true;

    public IReadOnlyList<string> TemporaryCleanupErrors { get; init; } = [];
}

/// <summary>
/// Strict allow-list for the elevated process. No request can provide an arbitrary
/// executable or arbitrary command-line arguments: commands are rebuilt here from
/// typed certificate inputs and the wacs.exe hash is verified again after UAC.
/// </summary>
public sealed class ElevatedWorkerDispatcher
{
    private const int MaximumCapturedCharacters = 300_000;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 64
    };

    private readonly ProcessRunner _processRunner = new();

    public async Task<ElevatedWorkerResult> ExecuteAsync(
        ElevatedWorkerRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!SecurityArgumentService.IsCurrentProcessAdministrator())
        {
            return Failure("提升權限 worker 未取得系統管理員權限。");
        }

        return request.Action switch
        {
            ElevatedWorkerAction.LocalEnvironmentCheck =>
                await RunLocalPreflightAsync(request.PayloadJson, cancellationToken).ConfigureAwait(false),
            ElevatedWorkerAction.InstallWinAcme =>
                await InstallWinAcmeAsync(request.PayloadJson, cancellationToken).ConfigureAwait(false),
            ElevatedWorkerAction.RunWinAcme =>
                await RunWinAcmeAsync(request.PayloadJson, cancellationToken).ConfigureAwait(false),
            ElevatedWorkerAction.ReadRenewalPreview =>
                await ReadRenewalPreviewAsync(request.PayloadJson, cancellationToken).ConfigureAwait(false),
            ElevatedWorkerAction.ReadMaintenanceStatus =>
                await ReadMaintenanceStatusAsync(request.PayloadJson, cancellationToken).ConfigureAwait(false),
            _ => Failure("不支援的提升權限工作。")
        };
    }

    private static async Task<ElevatedWorkerResult> ReadRenewalPreviewAsync(
        string payloadJson, CancellationToken cancellationToken)
    {
        var payload = Deserialize<ReadRenewalPreviewPayload>(payloadJson);
        var preview = await Task.Run(() => new WinAcmeRenewalPolicyService().ReadPreview(payload.CertificateRequest),
            cancellationToken).ConfigureAwait(false);
        return new ElevatedWorkerResult
        {
            Success = true,
            ExitCode = 0,
            PayloadJson = JsonSerializer.Serialize(preview, JsonOptions)
        };
    }

    private static async Task<ElevatedWorkerResult> ReadMaintenanceStatusAsync(
        string payloadJson, CancellationToken cancellationToken)
    {
        _ = Deserialize<ReadMaintenanceStatusPayload>(payloadJson);
        var snapshot = await Task.Run(() => new MaintenanceStatusService().Read(), cancellationToken).ConfigureAwait(false);
        return new ElevatedWorkerResult
        {
            Success = true,
            ExitCode = 0,
            PayloadJson = JsonSerializer.Serialize(snapshot, JsonOptions)
        };
    }

    private async Task<ElevatedWorkerResult> RunLocalPreflightAsync(
        string payloadJson,
        CancellationToken cancellationToken)
    {
        var payload = Deserialize<LocalPreflightRequest>(payloadJson);
        var service = new ElevatedLocalPreflightService(new IisDiscoveryService(_processRunner));
        var report = await service.RunAsync(payload, cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        return new ElevatedWorkerResult
        {
            Success = true,
            ExitCode = 0,
            PayloadJson = JsonSerializer.Serialize(report, JsonOptions)
        };
    }

    private static async Task<ElevatedWorkerResult> InstallWinAcmeAsync(
        string payloadJson,
        CancellationToken cancellationToken)
    {
        // The payload is deliberately an empty object. Parsing with unmapped member
        // rejection prevents smuggling alternate URLs, hashes, or destinations.
        _ = Deserialize<InstallWinAcmePayload>(payloadJson);
        using var httpClient = new HttpClient(new HttpClientHandler
        {
            AllowAutoRedirect = true,
            AutomaticDecompression = System.Net.DecompressionMethods.All
        })
        {
            Timeout = TimeSpan.FromMinutes(10)
        };
        var installation = await new WinAcmeDownloadService(httpClient)
            .InstallRecommendedAsync(cancellationToken: cancellationToken)
            .ConfigureAwait(false);
        return new ElevatedWorkerResult
        {
            Success = installation.Exists && installation.IntegrityVerified,
            ExitCode = installation.Exists && installation.IntegrityVerified ? 0 : 1,
            ErrorMessage = installation.IntegrityVerified ? null : installation.StatusMessage,
            PayloadJson = JsonSerializer.Serialize(installation, JsonOptions)
        };
    }

    private async Task<ElevatedWorkerResult> RunWinAcmeAsync(
        string payloadJson,
        CancellationToken cancellationToken)
    {
        var payload = Deserialize<RunWinAcmeWorkerPayload>(payloadJson);
        if (!string.Equals(
                payload.ExpectedExecutableSha256,
                WinAcmeRecommendedRelease.ExecutableSha256,
                StringComparison.OrdinalIgnoreCase))
        {
            return Failure($"{AppVersion.DisplayVersion} 正式工作只允許執行工具固定並測試過的 win-acme SHA-256。請改用『下載建議版本』。");
        }

        if (!TryValidateManagedWinAcmePath(payload.WinAcmePath, out var managedPathError))
        {
            return Failure(managedPathError);
        }

        var locator = new WinAcmeLocator();
        var installation = await locator.InspectSelectedAsync(payload.WinAcmePath, cancellationToken)
            .ConfigureAwait(false);
        if (!installation.Exists || !installation.IntegrityVerified ||
            !string.Equals(
                installation.Sha256,
                payload.ExpectedExecutableSha256,
                StringComparison.OrdinalIgnoreCase))
        {
            return Failure("UAC 後重新驗證 wacs.exe 失敗；檔案不存在、已被替換或不是固定測試版本。");
        }

        try
        {
            var managedDirectory = Path.GetDirectoryName(installation.ExecutablePath)!;
            WinAcmeDownloadService.ApplyManagedDirectoryAcl(managedDirectory);
            WinAcmeDownloadService.ConfigureManagedSettings(managedDirectory);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return Failure($"無法建立或鎖定工具專用的 win-acme 設定：{exception.Message}");
        }

        var builder = new WinAcmeCommandBuilder();
        if (payload.Operation == WinAcmeWorkerOperation.StagingValidation)
        {
            var stagingCommand = builder.BuildStagingValidation(payload.CertificateRequest);
            AssertStagingInvariants(stagingCommand);
            var stagingResult = await new WinAcmeService(_processRunner)
                .ExecuteAsync(
                    installation.ExecutablePath,
                    stagingCommand,
                    requestElevationWhenRequired: false,
                    cancellationToken)
                .ConfigureAwait(false);
            var stagingOutput = new RunWinAcmeWorkerOutput
            {
                Operation = payload.Operation,
                SafeCommandLine = stagingResult.SafeCommandLine,
                IisBindingsVerified = false,
                RenewalTaskReady = false,
                TemporaryCleanupSucceeded = stagingResult.TemporaryCleanupSucceeded,
                TemporaryCleanupErrors = stagingResult.TemporaryCleanupResults
                    .Where(cleanup => !cleanup.Succeeded)
                    .Select(FormatCleanupFailure)
                    .ToArray()
            };
            return FromExecution(stagingResult, stagingOutput);
        }

        if (payload.Operation != WinAcmeWorkerOperation.ProductionIssuance)
        {
            return Failure("不支援的 win-acme 工作模式。");
        }

        return await RunProductionAsync(payload, installation, builder, cancellationToken)
            .ConfigureAwait(false);
    }

    private async Task<ElevatedWorkerResult> RunProductionAsync(
        RunWinAcmeWorkerPayload payload,
        WinAcmeInstallationInfo installation,
        WinAcmeCommandBuilder builder,
        CancellationToken cancellationToken)
    {
        var discovery = new IisDiscoveryService(_processRunner);
        var before = await discovery.DiscoverAsync(cancellationToken).ConfigureAwait(false);
        var selectedSite = before.Sites.FirstOrDefault(site =>
            site.Id == payload.CertificateRequest.SiteId);
        if (before.ErrorMessage is not null || selectedSite is null)
        {
            return Failure(before.ErrorMessage ?? "正式簽發前找不到選取的 IIS 網站。");
        }

        var freshLocalReport = await new ElevatedLocalPreflightService(discovery).RunAsync(
            new LocalPreflightRequest
            {
                SelectedSiteId = selectedSite.Id,
                SelectedSiteName = selectedSite.Name,
                DomainNames = payload.CertificateRequest.HostNames.ToList(),
                WinAcmePath = installation.ExecutablePath,
                ExpectedWinAcmeSha256 = WinAcmeRecommendedRelease.ExecutableSha256,
                RequiredRsaKeyBits = 2048,
                RequireStartedSite = true
            },
            cancellationToken: cancellationToken).ConfigureAwait(false);
        if (freshLocalReport.HasBlockingFailures)
        {
            var failures = freshLocalReport.Checks
                .Where(check => check.IsBlockingFailure)
                .Select(check => $"{check.Title}：{check.Summary}");
            return Failure("正式簽發前的本機條件已變更：" + string.Join("；", failures));
        }

        var renewalId = builder.GetProductionRenewalId(payload.CertificateRequest);
        WinAcmeRenewalStateTransaction renewalState;
        try
        {
            renewalState = WinAcmeRenewalStateTransaction.Capture(renewalId);
        }
        catch (Exception exception)
        {
            return Failure($"無法安全快照 renewal {renewalId}，正式簽發未開始：{exception.Message}");
        }

        using var renewalStateScope = renewalState;
        try
        {
            renewalState.ValidatePreviewConsent(payload.CertificateRequest,
                payload.ExpectedRenewalStateSha256, payload.ConfirmRemovedRenewalNames);
        }
        catch (Exception exception)
        {
            return Failure($"正式簽發未開始：{exception.Message}");
        }
        var bindingVerifier = new IisCertificateBindingVerifier();
        IReadOnlySet<string> webHostingThumbprintsBefore;
        try
        {
            webHostingThumbprintsBefore = bindingVerifier.SnapshotWebHostingThumbprints();
        }
        catch (Exception exception)
        {
            return Failure($"無法在正式簽發前快照 WebHosting 憑證存放區：{exception.Message}");
        }

        string retentionScript;
        WinAcmeCommand command;
        try
        {
            retentionScript = new CertificateRetentionService().Deploy();
            command = builder.BuildProductionIssuance(
                payload.CertificateRequest,
                retentionScript);
            AssertProductionInvariants(command, renewalId);
        }
        catch (Exception exception)
        {
            return Failure($"無法建立正式簽發命令或部署保留腳本：{exception.Message}");
        }

        var backupName = $"MSTECH-SSL-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}"[..43];
        var backup = await _processRunner.RunAsync(new ProcessRequest
        {
            FileName = before.AppCmdPath,
            Arguments = ["add", "backup", backupName],
            WorkingDirectory = Path.GetDirectoryName(before.AppCmdPath),
            Timeout = TimeSpan.FromMinutes(2),
            CreateNoWindow = true
        }, cancellationToken).ConfigureAwait(false);
        if (!backup.Succeeded)
        {
            return Failure($"無法建立 IIS 設定備份，已停止正式簽發：{FirstError(backup)}", backup.ExitCode);
        }

        try
        {
            renewalState.MarkExecutionStarted();
        }
        catch (Exception exception)
        {
            return Failure($"正式簽發未開始：{exception.Message}");
        }

        WinAcmeExecutionResult execution;
        try
        {
            execution = await new WinAcmeService(_processRunner)
                .ExecuteAsync(
                    installation.ExecutablePath,
                    command,
                    requestElevationWhenRequired: false,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            var renewalRestore = renewalState.Restore();
            var rollback = await RestoreIisBackupAsync(
                    before.AppCmdPath,
                    backupName,
                    CancellationToken.None)
                .ConfigureAwait(false);
            var safeCommandLine = SecurityArgumentService.ToSafeDisplayCommand(
                installation.ExecutablePath,
                command.Arguments);
            var output = new RunWinAcmeWorkerOutput
            {
                Operation = payload.Operation,
                SafeCommandLine = safeCommandLine,
                IisBackupName = backupName,
                IisBindingsVerified = false,
                RenewalId = renewalId,
                RenewalStateRestored = renewalRestore.Success,
                RenewalStateSummary = renewalRestore.Summary,
                RollbackAttempted = true,
                RollbackSucceeded = rollback.Succeeded && renewalRestore.Success,
                RenewalTaskReady = false
            };
            return new ElevatedWorkerResult
            {
                Success = false,
                ExitCode = 3,
                StdErr = Truncate(
                    $"win-acme 執行發生例外：{exception.Message}{Environment.NewLine}" +
                    $"renewal rollback: {renewalRestore.Summary}{Environment.NewLine}" +
                    $"IIS rollback: {FirstError(rollback)}"),
                ErrorMessage = rollback.Succeeded && renewalRestore.Success
                    ? "win-acme 正式簽發異常，renewal 與 IIS 設定均已復原。"
                    : "win-acme 正式簽發異常，且 renewal 或 IIS 復原未完整成功，請立即人工檢查。",
                PayloadJson = JsonSerializer.Serialize(output, JsonOptions)
            };
        }

        if (!execution.ProcessResult.Succeeded)
        {
            var renewalRestore = renewalState.Restore();
            var rollback = await RestoreIisBackupAsync(before.AppCmdPath, backupName, CancellationToken.None)
                .ConfigureAwait(false);
            var output = new RunWinAcmeWorkerOutput
            {
                Operation = payload.Operation,
                SafeCommandLine = execution.SafeCommandLine,
                IisBackupName = backupName,
                IisBindingsVerified = false,
                RenewalId = renewalId,
                RenewalStateRestored = renewalRestore.Success,
                RenewalStateSummary = renewalRestore.Summary,
                RollbackAttempted = true,
                RollbackSucceeded = rollback.Succeeded && renewalRestore.Success,
                RenewalTaskReady = false
            };
            return new ElevatedWorkerResult
            {
                Success = false,
                ExitCode = execution.ProcessResult.ExitCode,
                StdOut = Truncate(execution.ProcessResult.StandardOutput),
                StdErr = Truncate(execution.ProcessResult.StandardError +
                    Environment.NewLine + "renewal rollback: " + renewalRestore.Summary +
                    Environment.NewLine + "IIS rollback: " + FirstError(rollback)),
                ErrorMessage = rollback.Succeeded && renewalRestore.Success
                    ? "win-acme 正式簽發失敗，renewal 與 IIS 設定均已復原。"
                    : "win-acme 正式簽發失敗，且 renewal 或 IIS 復原未完整成功，請立即人工檢查。",
                PayloadJson = JsonSerializer.Serialize(output, JsonOptions)
            };
        }

        IisCertificateBindingVerificationResult bindingVerification;
        var renewalFileValid = renewalState.ValidateCommittedRenewal(payload.CertificateRequest, out var renewalFileError);
        try
        {
            bindingVerification = renewalFileValid
                ? bindingVerifier.VerifyAfterIssuance(
                    payload.CertificateRequest.SiteId,
                    payload.CertificateRequest.HostNames,
                    webHostingThumbprintsBefore)
                : new IisCertificateBindingVerificationResult
                {
                    Success = false,
                    Summary = $"renewal {renewalId} 寫入驗證失敗：{renewalFileError}"
                };
        }
        catch (Exception exception)
        {
            bindingVerification = new IisCertificateBindingVerificationResult
            {
                Success = false,
                Summary = $"讀取 IIS 或 WebHosting 驗證資料失敗：{exception.Message}"
            };
        }

        if (!bindingVerification.Success)
        {
            var renewalRestore = renewalState.Restore();
            var rollback = await RestoreIisBackupAsync(before.AppCmdPath, backupName, CancellationToken.None)
                .ConfigureAwait(false);
            var verificationOutput = new RunWinAcmeWorkerOutput
            {
                Operation = payload.Operation,
                SafeCommandLine = execution.SafeCommandLine,
                IisBackupName = backupName,
                IisBindingsVerified = false,
                NewCertificateThumbprint = bindingVerification.NewCertificateThumbprint,
                BindingVerificationSummary = bindingVerification.Summary,
                CertificateWasNew = bindingVerification.CertificateWasNew,
                RenewalId = renewalId,
                RenewalStateRestored = renewalRestore.Success,
                RenewalStateSummary = renewalRestore.Summary,
                RollbackAttempted = true,
                RollbackSucceeded = rollback.Succeeded && renewalRestore.Success,
                RenewalTaskReady = false
            };
            return new ElevatedWorkerResult
            {
                Success = false,
                ExitCode = 2,
                StdOut = Truncate(execution.ProcessResult.StandardOutput),
                StdErr = Truncate(
                    "win-acme 回報成功，但簽發後驗證失敗：" + bindingVerification.Summary +
                    Environment.NewLine + "renewal rollback: " + renewalRestore.Summary +
                    Environment.NewLine + "IIS rollback: " + FirstError(rollback)),
                ErrorMessage = rollback.Succeeded && renewalRestore.Success
                    ? "簽發後驗證失敗，renewal 與 IIS 設定均已復原。"
                    : "簽發後驗證失敗，且 renewal 或 IIS 設定復原未成功。",
                PayloadJson = JsonSerializer.Serialize(verificationOutput, JsonOptions)
            };
        }

        renewalState.Commit();
        var taskService = new WinAcmeScheduledTaskService();
        WinAcmeExecutionResult? taskSetupExecution = null;
        string? taskSetupException = null;
        try
        {
            taskSetupExecution = await new WinAcmeService(_processRunner)
                .ExecuteAsync(
                    installation.ExecutablePath,
                    builder.BuildSetupTaskScheduler(),
                    requestElevationWhenRequired: false,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (Exception exception)
        {
            taskSetupException = exception.Message;
        }

        var taskRead = taskService.ReadRenewalTasks(installation.ExecutablePath);
        var task = taskRead.Tasks
            .OrderByDescending(item => WinAcmeScheduledTaskService.EvaluateReadiness(item, installation.ExecutablePath).IsReady)
            .ThenBy(item => item.Name, StringComparer.CurrentCultureIgnoreCase)
            .FirstOrDefault();
        var taskSetupSucceeded = taskSetupExecution?.ProcessResult.Succeeded == true &&
            taskSetupException is null;
        var readiness = WinAcmeScheduledTaskService.EvaluateReadiness(task, installation.ExecutablePath);
        var taskReady = taskSetupSucceeded && taskRead.Succeeded && readiness.IsReady;
        var taskSetupError = taskSetupException ??
            (taskSetupExecution is null || taskSetupExecution.ProcessResult.Succeeded
                ? null
                : FirstError(taskSetupExecution.ProcessResult));
        var outputResult = new RunWinAcmeWorkerOutput
        {
            Operation = payload.Operation,
            SafeCommandLine = execution.SafeCommandLine,
            IisBackupName = backupName,
            IisBindingsVerified = true,
            NewCertificateThumbprint = bindingVerification.NewCertificateThumbprint,
            BindingVerificationSummary = bindingVerification.Summary,
            CertificateWasNew = bindingVerification.CertificateWasNew,
            RenewalId = renewalId,
            RenewalStateRestored = false,
            RenewalStateSummary = $"renewal {renewalId} 已驗證並提交。",
            RollbackAttempted = false,
            RollbackSucceeded = false,
            RenewalTaskReady = taskReady,
            RenewalTaskSummary = taskSetupError is not null
                ? $"建立續期排程失敗：{taskSetupError}"
                : !taskRead.Succeeded
                    ? taskRead.ErrorMessage ?? "無法讀取續期排程，狀態未知。"
                    : readiness.Summary
        };
        return new ElevatedWorkerResult
        {
            Success = true,
            ExitCode = execution.ProcessResult.ExitCode,
            StdOut = Truncate(execution.ProcessResult.StandardOutput),
            StdErr = Truncate(string.Join(
                Environment.NewLine,
                new[]
                {
                    execution.ProcessResult.StandardError,
                    taskSetupExecution?.ProcessResult.StandardError,
                    taskSetupException
                }.Where(value => !string.IsNullOrWhiteSpace(value)))),
            ErrorMessage = taskReady ? null : "憑證與 IIS Binding 已完成，但 SYSTEM 自動續期排程驗證未通過。",
            PayloadJson = JsonSerializer.Serialize(outputResult, JsonOptions)
        };
    }

    private async Task<ProcessResult> RestoreIisBackupAsync(
        string appCmdPath,
        string backupName,
        CancellationToken cancellationToken) =>
        await _processRunner.RunAsync(new ProcessRequest
        {
            FileName = appCmdPath,
            Arguments = ["restore", "backup", backupName],
            WorkingDirectory = Path.GetDirectoryName(appCmdPath),
            Timeout = TimeSpan.FromMinutes(3),
            CreateNoWindow = true
        }, cancellationToken).ConfigureAwait(false);

    private static void AssertStagingInvariants(WinAcmeCommand command)
    {
        var arguments = command.Arguments;
        if (!command.UsesStagingEnvironment || command.ChangesIisBindings ||
            !arguments.Contains("--test", StringComparer.OrdinalIgnoreCase) ||
            !string.Equals(
                command.CompletionOutputMarker,
                WinAcmeRecommendedRelease.StagingCompletionOutputMarker,
                StringComparison.Ordinal) ||
            !HasOptionValue(arguments, "--installation", "none") ||
            !HasOptionValue(arguments, "--store", "pfxfile") ||
            !arguments.Contains("--notaskscheduler", StringComparer.OrdinalIgnoreCase) ||
            HasOptionValue(arguments, "--installation", "iis") ||
            HasOptionValue(arguments, "--store", "certificatestore"))
        {
            throw new InvalidOperationException("Staging 命令未符合『不安裝、不修改 IIS、不建立排程』安全條件。");
        }
    }

    private static void AssertProductionInvariants(WinAcmeCommand command, string renewalId)
    {
        var arguments = command.Arguments;
        if (command.UsesStagingEnvironment || !command.ChangesIisBindings ||
            command.CompletionOutputMarker is not null ||
            arguments.Contains("--test", StringComparer.OrdinalIgnoreCase) ||
            !arguments.Contains("--notaskscheduler", StringComparer.OrdinalIgnoreCase) ||
            !arguments.Contains("--nocache", StringComparer.OrdinalIgnoreCase) ||
            !HasOptionValue(arguments, "--id", renewalId) ||
            !HasOptionValue(
                arguments,
                "--baseuri",
                WinAcmeRecommendedRelease.ProductionBaseUri) ||
            !HasOptionValue(arguments, "--store", "certificatestore") ||
            !HasOptionValue(arguments, "--certificatestore", "WebHosting") ||
            !HasOptionValue(arguments, "--installation", "iis,script"))
        {
            throw new InvalidOperationException(
                "Production 命令未符合『固定 renewal、不使用 cache、延後建立排程』安全條件。");
        }
    }

    private static bool TryValidateManagedWinAcmePath(string? candidate, out string error)
    {
        error = string.Empty;
        string actual;
        string expected;
        try
        {
            actual = Path.GetFullPath(candidate?.Trim().Trim('"') ?? string.Empty);
            expected = Path.GetFullPath(AppPaths.WinAcmeExecutable);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            error = $"wacs.exe 路徑無效：{exception.Message}";
            return false;
        }

        if (!string.Equals(actual, expected, StringComparison.OrdinalIgnoreCase))
        {
            error = $"{AppVersion.DisplayVersion} 的提升權限工作只允許執行工具下載到受保護管理目錄的 win-acme；自行選取的檔案僅供診斷。";
            return false;
        }

        try
        {
            if (!File.Exists(actual) ||
                File.GetAttributes(actual).HasFlag(FileAttributes.ReparsePoint))
            {
                error = "管理版 wacs.exe 不存在或是重新解析連結，已拒絕執行。";
                return false;
            }

            var root = Path.GetFullPath(AppPaths.ProgramDataRoot)
                .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var current = new DirectoryInfo(Path.GetDirectoryName(actual)!);
            var reachedRoot = false;
            while (current is not null &&
                   current.FullName.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                if (current.Attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    error = $"管理版 win-acme 路徑包含重新解析目錄：{current.FullName}";
                    return false;
                }

                if (string.Equals(current.FullName.TrimEnd(Path.DirectorySeparatorChar), root,
                        StringComparison.OrdinalIgnoreCase))
                {
                    reachedRoot = true;
                    break;
                }

                current = current.Parent;
            }

            if (!reachedRoot)
            {
                error = "管理版 win-acme 路徑不在工具的 ProgramData 受控根目錄中。";
                return false;
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            error = $"無法驗證管理版 win-acme 路徑：{exception.Message}";
            return false;
        }

        return true;
    }

    private static bool HasOptionValue(
        IReadOnlyList<string> arguments,
        string option,
        string expectedValue)
    {
        for (var index = 0; index + 1 < arguments.Count; index++)
        {
            if (arguments[index].Equals(option, StringComparison.OrdinalIgnoreCase) &&
                arguments[index + 1].Equals(expectedValue, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static T Deserialize<T>(string json) where T : class =>
        JsonSerializer.Deserialize<T>(json, JsonOptions)
        ?? throw new InvalidDataException("提升權限工作內容為空。");

    private static ElevatedWorkerResult FromExecution(
        WinAcmeExecutionResult execution,
        RunWinAcmeWorkerOutput output)
    {
        var cleanupFailures = execution.TemporaryCleanupResults
            .Where(cleanup => !cleanup.Succeeded)
            .Select(FormatCleanupFailure)
            .ToList();
        var cleanupSucceeded = execution.TemporaryCleanupSucceeded;
        if (!cleanupSucceeded && cleanupFailures.Count == 0)
        {
            cleanupFailures.Add("暫存清理失敗：未收到所有預期暫存目錄的清理確認。");
        }

        var succeeded = execution.ProcessResult.Succeeded && cleanupSucceeded;
        var cleanupDetail = string.Join(Environment.NewLine, cleanupFailures);
        var standardError = string.Join(
            Environment.NewLine,
            new[] { execution.ProcessResult.StandardError, cleanupDetail }
                .Where(value => !string.IsNullOrWhiteSpace(value)));
        var processError = execution.ProcessResult.ErrorMessage ?? "win-acme 執行失敗。";
        const string cleanupError =
            "測試 PFX 暫存資料未能確認清除；正式簽發維持停用，請依錯誤路徑人工清理後重試。";

        return new ElevatedWorkerResult
        {
            Success = succeeded,
            ExitCode = execution.ProcessResult.Succeeded && !cleanupSucceeded
                ? 3
                : execution.ProcessResult.ExitCode,
            StdOut = Truncate(execution.ProcessResult.StandardOutput),
            StdErr = Truncate(standardError),
            ErrorMessage = !execution.ProcessResult.Succeeded
                ? cleanupSucceeded ? processError : $"{processError} 此外，{cleanupError}"
                : !cleanupSucceeded
                    ? $"Staging 驗證已完成，但{cleanupError}"
                    : null,
            PayloadJson = JsonSerializer.Serialize(output, JsonOptions)
        };
    }

    private static string FormatCleanupFailure(WinAcmeTemporaryCleanupResult cleanup) =>
        $"暫存清理失敗：{cleanup.DirectoryPath}：{cleanup.ErrorMessage ?? "未知錯誤"}";

    private static ElevatedWorkerResult Failure(string message, int? exitCode = null) => new()
    {
        Success = false,
        ExitCode = exitCode,
        ErrorMessage = message
    };

    private static string Truncate(string? value)
    {
        var normalized = value ?? string.Empty;
        return normalized.Length <= MaximumCapturedCharacters
            ? normalized
            : normalized[..MaximumCapturedCharacters] + Environment.NewLine + "[輸出已截斷]";
    }

    private static string FirstError(ProcessResult result) =>
        FirstNonEmpty(result.StandardError, result.ErrorMessage, result.StandardOutput, "未知錯誤");

    private static string FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))?.Trim() ?? string.Empty;

    private sealed record InstallWinAcmePayload;
}
