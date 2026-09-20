using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Threading;
using Microsoft.Win32;
using Mstech.IisSslManager.Core;
using Mstech.IisSslManager.Infrastructure;
using Mstech.IisSslManager.Models;
using Mstech.IisSslManager.Services;
using Mstech.IisSslManager.ViewModels;
using Mstech.IisSslManager.Views;

namespace Mstech.IisSslManager;

public partial class MainWindow : Window
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = false,
        MaxDepth = 64
    };

    private static readonly TimeSpan GateFreshness = TimeSpan.FromMinutes(30);

    private readonly ProcessRunner _processRunner = new();
    private readonly DnsQueryClient _dnsClient = new();
    private readonly WinAcmeLocator _winAcmeLocator = new();
    private readonly AutoStartService _autoStartService = new();
    private readonly ApplicationSettingsService _settingsService = new();
    private readonly AppLogService _appLogService = new();
    private readonly CancellationTokenSource _lifetime = new();
    private readonly DispatcherTimer _gateTimer = new() { Interval = TimeSpan.FromSeconds(15) };
    private readonly ElevationService _elevationService;
    private readonly IisDiscoveryService _iisDiscoveryService;
    private readonly PublicPreflightService _publicPreflightService;

    private ApplicationSettings _settings = new();
    private IisInventory? _iisInventory;
    private IReadOnlyList<PreflightCheckResult> _publicChecks = [];
    private IReadOnlyList<PreflightCheckResult> _localChecks = [];
    private PreflightCheckResult? _stagingCheck;
    private DateTimeOffset? _publicPassedAt;
    private DateTimeOffset? _localPassedAt;
    private DateTimeOffset? _stagingPassedAt;
    private string? _publicFingerprint;
    private string? _localFingerprint;
    private string? _stagingFingerprint;
    private bool _initialized;

    public MainViewModel ViewModel { get; } = new();

    public MainWindow()
    {
        _elevationService = new ElevationService(_processRunner);
        _iisDiscoveryService = new IisDiscoveryService(_processRunner);
        _publicPreflightService = new PublicPreflightService(_dnsClient);

        InitializeComponent();
        DataContext = ViewModel;

        ViewModel.RefreshSitesRequested += OnRefreshSitesRequested;
        ViewModel.RefreshMaintenanceRequested += OnRefreshMaintenanceRequested;
        ViewModel.BrowseWinAcmeRequested += OnBrowseWinAcmeRequested;
        ViewModel.DownloadWinAcmeRequested += OnDownloadWinAcmeRequested;
        ViewModel.RunPublicPreflightRequested += OnRunPublicPreflightRequested;
        ViewModel.RunLocalPreflightRequested += OnRunLocalPreflightRequested;
        ViewModel.RunPreflightRequested += OnRunPreflightRequested;
        ViewModel.RunStagingRequested += OnRunStagingRequested;
        ViewModel.RunProductionRequested += OnRunProductionRequested;
        ViewModel.OpenLogFolderRequested += OnOpenLogFolderRequested;
        ViewModel.StartWithWindowsChanged += OnStartWithWindowsChanged;
        Loaded += OnLoaded;
        Closing += OnClosing;
        Closed += OnClosed;
        _gateTimer.Tick += (_, _) =>
        {
            if (ViewModel.IsBusy) return;
            var now = DateTimeOffset.Now;
            if (_publicPassedAt is { } publicAt && now - publicAt > GateFreshness) ViewModel.PublicPreflightPassed = false;
            if (_localPassedAt is { } localAt && now - localAt > GateFreshness) ViewModel.LocalPreflightPassed = false;
            if (_stagingPassedAt is { } stagingAt && now - stagingAt > GateFreshness) ViewModel.StagingPassed = false;
        };
        _gateTimer.Start();
    }

    private async void OnLoaded(object sender, RoutedEventArgs e)
    {
        if (_initialized)
        {
            return;
        }

        _initialized = true;
        await RunOperationAsync("正在載入 IIS 與設定…", InitializeAsync);
    }

    private async Task InitializeAsync()
    {
        _settings = await _settingsService.LoadAsync(_lifetime.Token);
        ViewModel.ContactEmail = _settings.ContactEmail;
        ViewModel.AcceptTerms = _settings.TermsAccepted;
        ViewModel.AcknowledgeCertificateTransparency = _settings.CertificateTransparencyAcknowledged;
        ViewModel.SetRequestedDomains(_settings.NameMode, _settings.DomainNames);

        var autoStart = _autoStartService.GetStatus();
        ViewModel.SetStartWithWindowsSilently(autoStart.IsEnabled && autoStart.MatchesCurrentExecutable);
        if (!string.IsNullOrWhiteSpace(autoStart.ErrorMessage))
        {
            await LogAsync(AppLogLevel.Warning, $"無法讀取登入自動啟動狀態：{autoStart.ErrorMessage}");
        }

        await RefreshSitesAsync(showErrors: false);
        if (_settings.SelectedSiteId is { } selectedId)
        {
            ViewModel.SelectedSite = ViewModel.Sites.FirstOrDefault(site =>
                long.TryParse(site.Id, out var id) && id == selectedId) ?? ViewModel.SelectedSite;
        }

        var installations = await _winAcmeLocator.DiscoverAsync(
            _settings.WinAcmePath,
            _lifetime.Token);
        var selected = installations.FirstOrDefault(item =>
                           string.Equals(
                               item.ExecutablePath,
                               _settings.WinAcmePath,
                               StringComparison.OrdinalIgnoreCase))
                       ?? installations.FirstOrDefault(item => item.IntegrityVerified)
                       ?? installations.FirstOrDefault();
        if (selected is not null)
        {
            ViewModel.WinAcmePath = selected.ExecutablePath;
            await LogAsync(
                selected.IntegrityVerified ? AppLogLevel.Information : AppLogLevel.Warning,
                selected.StatusMessage);
        }

        ViewModel.OverallStatus = "就緒";
        ViewModel.OverallStatusDetail = "請完成申請設定，再依序執行公開、本機與 Staging 三階段驗證。";
        await LogAsync(AppLogLevel.Information, "程式初始化完成；尚未進行任何 IIS 或憑證變更。");
    }

    private async void OnRefreshSitesRequested(object? sender, EventArgs e) =>
        await RunOperationAsync("正在讀取 IIS 網站…", () => RefreshSitesAsync(showErrors: true));

    private async void OnRefreshMaintenanceRequested(object? sender, EventArgs e) =>
        await RunOperationAsync("正在唯讀查詢 IIS 憑證與續期排程…", ReadMaintenanceStatusCoreAsync);

    private async Task ReadMaintenanceStatusCoreAsync()
    {
        ViewModel.SelectedTabIndex = 0;
        ViewModel.MaintenanceCertificates.Clear();
        ViewModel.MaintenanceTasks.Clear();
        ViewModel.MaintenanceCheckedAt = "正在查詢，尚無新的狀態快照";
        ViewModel.MaintenanceSummary = "正在唯讀查詢；需要時請完成 Windows UAC 驗證。";
        var result = await RunElevatedActionAsync(
            ElevatedWorkerAction.ReadMaintenanceStatus,
            new ReadMaintenanceStatusPayload(), TimeSpan.FromMinutes(2));
        if (!result.Success || string.IsNullOrWhiteSpace(result.PayloadJson))
        {
            ViewModel.MaintenanceCheckedAt = "查詢未完成";
            ViewModel.MaintenanceSummary = "狀態未知，未沿用舊的成功結果。請重新整理或查看執行紀錄。";
            await ReportWorkerFailureAsync("狀態查詢未完成", result);
            return;
        }

        var snapshot = Deserialize<MaintenanceStatusSnapshot>(result.PayloadJson);
        ViewModel.MaintenanceCheckedAt = $"查詢時間：{snapshot.CheckedAtUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}（非持續監控）";
        var summary = new List<string>
        {
            snapshot.IisReadSucceeded
                ? snapshot.Bindings.Count == 0 ? "未找到 IIS HTTPS 443 Binding。" : $"已查詢 {snapshot.Bindings.Count} 個 HTTPS 443 Binding。"
                : $"IIS／憑證狀態未知：{snapshot.IisError}",
            snapshot.TaskReadSucceeded
                ? snapshot.RenewalTasks.Count == 0 ? "未找到本工具管理的續期排程；不能確認自動續期已就緒。" : $"已查詢 {snapshot.RenewalTasks.Count} 個工具管理排程，請確認下方檢查結果。"
                : $"續期排程狀態未知：{snapshot.TaskError}"
        };
        ViewModel.MaintenanceSummary = string.Join("\n", summary);
        foreach (var binding in snapshot.Bindings)
        {
            ViewModel.MaintenanceCertificates.Add(new MaintenanceCertificateRow
            {
                Site = $"{binding.SiteName}（ID {binding.SiteId}）",
                Host = string.IsNullOrWhiteSpace(binding.HostName) ? binding.BindingInformation : binding.HostName,
                Certificate = $"{binding.StoreName} · {binding.Thumbprint}",
                Expiry = binding.ExpiresAtUtc is { } expiry
                    ? $"{expiry.ToLocalTime():yyyy-MM-dd HH:mm}\n剩餘 {binding.DaysRemaining} 天" : "到期日未知",
                Summary = binding.Summary
            });
        }
        foreach (var task in snapshot.RenewalTasks)
        {
            ViewModel.MaintenanceTasks.Add(new MaintenanceTaskRow
            {
                Name = task.Task.Name,
                Schedule = $"上次執行：{task.Task.LastRunTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "尚無紀錄"}　下次執行：{task.Task.NextRunTime?.ToString("yyyy-MM-dd HH:mm:ss") ?? "未知"}",
                LastExecution = task.LastExecutionSummary,
                Summary = task.Readiness.Summary
            });
        }
        await LogAsync(AppLogLevel.Information, "憑證與續期狀態唯讀查詢完成；未執行簽發、續期或系統設定變更。");
    }

    private async Task RefreshSitesAsync(bool showErrors)
    {
        _iisInventory = await _iisDiscoveryService.DiscoverAsync(_lifetime.Token);
        if (!_iisInventory.IsIisInstalled || _iisInventory.ErrorMessage is not null)
        {
            ViewModel.ReplaceSites([]);
            var message = _iisInventory.ErrorMessage ?? "未偵測到 IIS。";
            await LogAsync(AppLogLevel.Warning, message);
            if (showErrors)
            {
                MessageBox.Show(
                    this,
                    message,
                    "IIS 讀取失敗",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }

            return;
        }

        ViewModel.ReplaceSites(_iisInventory.Sites.Select(site => new IisSiteOptionViewModel
        {
            Name = site.Name,
            Id = site.Id.ToString(),
            BindingsSummary = string.Join(", ", site.Bindings.Select(binding => binding.RawValue))
        }));
        await LogAsync(AppLogLevel.Information, $"已讀取 {_iisInventory.Sites.Count} 個 IIS 網站。");
    }

    private async void OnBrowseWinAcmeRequested(object? sender, EventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "選擇 win-acme 執行檔",
            Filter = "win-acme (wacs.exe)|wacs.exe|執行檔 (*.exe)|*.exe",
            CheckFileExists = true,
            Multiselect = false
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        await RunOperationAsync("正在驗證 wacs.exe…", async () =>
        {
            var inspection = await _winAcmeLocator.InspectSelectedAsync(dialog.FileName, _lifetime.Token);
            ViewModel.WinAcmePath = inspection.ExecutablePath;
            await LogAsync(
                inspection.IntegrityVerified ? AppLogLevel.Information : AppLogLevel.Warning,
                $"已選擇 win-acme：{inspection.ExecutablePath}；{inspection.StatusMessage}");

            if (!inspection.IntegrityVerified)
            {
                MessageBox.Show(
                    this,
                    $"此檔案不是 {Infrastructure.AppVersion.DisplayVersion} 固定測試版本，僅可供路徑診斷，不能執行 Staging 或正式簽發。\n\n版本：{inspection.FileVersion ?? "未知"}\nSHA-256：{inspection.Sha256 ?? "無法取得"}\n\n請使用「下載建議版本」。",
                    "未受信任的 win-acme",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }

            await SaveSettingsAsync();
        });
    }

    private async void OnDownloadWinAcmeRequested(object? sender, EventArgs e)
    {
        var confirmation = MessageBox.Show(
            this,
            $"將從 win-acme 官方 GitHub Release 下載並安裝固定測試版本。\n\n版本：{WinAcmeRecommendedRelease.Version} x64 trimmed\n位置：{WinAcmeRecommendedRelease.InstallDirectory}\nSHA-256：{WinAcmeRecommendedRelease.ArchiveSha256}\n\nWindows 將顯示 UAC 管理員驗證；本工具不會取得或儲存密碼。是否繼續？",
            "下載建議版本",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.No);
        if (confirmation != MessageBoxResult.Yes)
        {
            return;
        }

        await RunOperationAsync("正在下載、驗證並安裝 win-acme…", async () =>
        {
            var result = await RunElevatedActionAsync(
                ElevatedWorkerAction.InstallWinAcme,
                new { },
                TimeSpan.FromMinutes(15));
            if (!result.Success || string.IsNullOrWhiteSpace(result.PayloadJson))
            {
                await ReportWorkerFailureAsync("win-acme 安裝失敗", result);
                return;
            }

            var installation = Deserialize<WinAcmeInstallationInfo>(result.PayloadJson);
            ViewModel.WinAcmePath = installation.ExecutablePath;
            ViewModel.OverallStatus = "win-acme 已就緒";
            ViewModel.OverallStatusDetail = $"已驗證固定版本 {installation.FileVersion ?? WinAcmeRecommendedRelease.Version}。";
            await LogAsync(AppLogLevel.Information, installation.StatusMessage);
            await SaveSettingsAsync();
            MessageBox.Show(
                this,
                "win-acme 建議版本已下載並完成 SHA-256 驗證。",
                "安裝完成",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        });
    }

    private async void OnRunPublicPreflightRequested(object? sender, EventArgs e) =>
        await RunOperationAsync("正在檢查公開 DNS 與網路…", RunPublicPreflightCoreAsync);

    private async Task RunPublicPreflightCoreAsync()
    {
        ViewModel.PublicPreflightPassed = false;
        ViewModel.StagingPassed = false;
        _publicPassedAt = null;
        _stagingPassedAt = null;
        _stagingFingerprint = null;
        var request = new PublicPreflightRequest
        {
            DomainNames = ViewModel.GetRequestedDomains(),
            NameMode = ViewModel.IsSanMode
                ? CertificateNameMode.SubjectAlternativeNames
                : CertificateNameMode.SingleDomain,
            PerCheckTimeout = TimeSpan.FromSeconds(15),
            CheckStagingDirectory = true
        };
        var report = await _publicPreflightService.RunAsync(
            request,
            cancellationToken: _lifetime.Token);
        _publicChecks = report.Checks;
        RefreshDisplayedChecks();
        ViewModel.SelectedTabIndex = 2;

        var passed = !report.HasBlockingFailures && ConfirmRequiredWarnings("公開環境", report.Checks);
        ViewModel.PublicPreflightPassed = passed;
        if (passed)
        {
            _publicPassedAt = DateTimeOffset.Now;
            _publicFingerprint = BuildPublicFingerprint();
            ViewModel.OverallStatus = "公開環境已通過";
            ViewModel.OverallStatusDetail = "接著執行本機 IIS／權限檢查；該步驟會顯示 Windows UAC。";
            await LogAsync(AppLogLevel.Information, "公開環境預檢已通過（含使用者確認的黃色項目）。");
        }
        else
        {
            ViewModel.OverallStatus = "公開環境未通過";
            ViewModel.OverallStatusDetail = report.HasBlockingFailures
                ? "請依紅色項目修正後重新檢查。"
                : "黃色項目尚未獲得人工確認；請核對 DNS／NAT 轉送設定後重新檢查並確認。";
            await LogAsync(AppLogLevel.Warning, "公開環境預檢未通過或使用者未確認黃色項目。");
        }

        await SaveSettingsAsync();
    }

    private async void OnRunLocalPreflightRequested(object? sender, EventArgs e) =>
        await RunOperationAsync("正在檢查本機 IIS 與系統權限…", RunLocalPreflightCoreAsync);

    private async Task RunLocalPreflightCoreAsync()
    {
        if (!TryBuildLocalPreflightRequest(out var request, out var validationError))
        {
            MessageBox.Show(this, validationError, "無法執行本機檢查", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        ViewModel.LocalPreflightPassed = false;
        ViewModel.StagingPassed = false;
        _localPassedAt = null;
        _stagingPassedAt = null;
        _stagingFingerprint = null;

        if (!_elevationService.IsAdministrator)
        {
            var consent = MessageBox.Show(
                this,
                "接下來 Windows 會顯示 UAC 管理員驗證，用來確認您有權讀寫 IIS、LocalMachine\\WebHosting 與工作排程。\n\n帳號與密碼只由 Windows 處理，本工具不會接收或保存。",
                "需要管理員權限",
                MessageBoxButton.OKCancel,
                MessageBoxImage.Information,
                MessageBoxResult.Cancel);
            if (consent != MessageBoxResult.OK)
            {
                return;
            }
        }

        var result = await RunElevatedActionAsync(
            ElevatedWorkerAction.LocalEnvironmentCheck,
            request,
            TimeSpan.FromMinutes(5));
        if (!result.Success || string.IsNullOrWhiteSpace(result.PayloadJson))
        {
            await ReportWorkerFailureAsync("本機環境檢查失敗", result);
            return;
        }

        var report = Deserialize<PreflightReport>(result.PayloadJson);
        _localChecks = report.Checks;
        RefreshDisplayedChecks();
        ViewModel.SelectedTabIndex = 2;
        var passed = !report.HasBlockingFailures && ConfirmRequiredWarnings("本機環境", report.Checks);
        ViewModel.LocalPreflightPassed = passed;
        if (passed)
        {
            _localPassedAt = DateTimeOffset.Now;
            _localFingerprint = BuildLocalFingerprint();
            ViewModel.OverallStatus = "前兩階段已通過";
            ViewModel.OverallStatusDetail = ViewModel.PublicPreflightPassed
                ? "請先勾選 Let’s Encrypt 條款並填妥信箱，再執行 Staging 外部驗證。"
                : "仍需執行公開 DNS／網路檢查。";
            await LogAsync(AppLogLevel.Information, "本機 IIS／權限預檢已通過（含使用者確認的 Binding 預覽）。");
        }
        else
        {
            ViewModel.OverallStatus = "本機環境未通過";
            ViewModel.OverallStatusDetail = report.HasBlockingFailures
                ? "請依紅色項目修正後重新檢查。"
                : "黃色 Binding 變更項目尚未獲得人工確認，請重新檢查並確認。";
            await LogAsync(AppLogLevel.Warning, "本機 IIS／權限預檢未通過或黃色項目未獲確認。");
        }

        await SaveSettingsAsync();
    }

    private async void OnRunPreflightRequested(object? sender, EventArgs e) =>
        await RunOperationAsync("正在執行前兩階段環境檢查…", async () =>
        {
            await RunPublicPreflightCoreAsync();
            if (ViewModel.PublicPreflightPassed)
            {
                await RunLocalPreflightCoreAsync();
            }
        });

    private async void OnRunStagingRequested(object? sender, EventArgs e) =>
        await RunOperationAsync("正在執行 Let’s Encrypt Staging 外部驗證…", RunStagingCoreAsync);

    private async Task RunStagingCoreAsync()
    {
        if (!ViewModel.AcceptTerms)
        {
            MessageBox.Show(this, "Staging unattended 模式也需要建立 ACME 帳號；請先勾選 Let’s Encrypt 服務條款。", "尚未同意條款", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!TryBuildCertificateRequest(out var certificateRequest, out var validationError))
        {
            MessageBox.Show(this, validationError, "設定不完整", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!ArePreflightGatesCurrent(requireStaging: false, out var gateError))
        {
            ResetExpiredGates();
            MessageBox.Show(this, gateError, "請重新檢查", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var consent = MessageBox.Show(
            this,
            "Staging 會向 Let’s Encrypt 測試環境提出實際 HTTP-01 驗證。\n\n測試憑證只會寫入受限的隨機暫存目錄，完成後立即刪除；不會匯入 WebHosting、不會修改 IIS Binding，也不會建立續期排程。是否繼續？",
            "執行 Staging 外部驗證",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question,
            MessageBoxResult.No);
        if (consent != MessageBoxResult.Yes)
        {
            return;
        }

        ViewModel.StagingPassed = false;
        var result = await RunElevatedActionAsync(
            ElevatedWorkerAction.RunWinAcme,
            new RunWinAcmeWorkerPayload
            {
                Operation = WinAcmeWorkerOperation.StagingValidation,
                WinAcmePath = ViewModel.WinAcmePath,
                ExpectedExecutableSha256 = WinAcmeRecommendedRelease.ExecutableSha256,
                CertificateRequest = certificateRequest
            },
            TimeSpan.FromMinutes(30));
        _stagingCheck = new PreflightCheckResult
        {
            Id = "acme-staging-challenge",
            Phase = PreflightPhase.AcmeStaging,
            Category = "ACME",
            Title = "Staging HTTP-01 外部驗證",
            Status = result.Success ? CheckStatus.Passed : CheckStatus.Failed,
            Summary = result.Success
                ? "Let’s Encrypt Staging 已從外部完成所有網域的 HTTP-01 驗證；測試 PFX 已清除。"
                : result.ErrorMessage ?? "Let’s Encrypt Staging 驗證失敗。",
            Remediation = result.Success
                ? null
                : "請檢查錯誤輸出、TCP 80、NAT/WAF、DNS A/AAAA 與 HTTP Redirect，修正後重試。"
        };
        RefreshDisplayedChecks();
        await LogWorkerOutputAsync(result);
        if (!result.Success)
        {
            _stagingPassedAt = null;
            _stagingFingerprint = null;
            ViewModel.OverallStatus = "Staging 驗證失敗";
            ViewModel.OverallStatusDetail = "正式簽發仍維持停用；請依錯誤資訊修正後重試。";
            await ReportWorkerFailureAsync("Staging 驗證失敗", result);
            return;
        }

        ViewModel.StagingPassed = true;
        _stagingPassedAt = DateTimeOffset.Now;
        _stagingFingerprint = BuildStagingFingerprint();
        ViewModel.OverallStatus = "三階段驗證皆已通過";
        ViewModel.OverallStatusDetail = "可預覽正式 IIS Binding 變更並執行正式簽發。";
        await LogAsync(AppLogLevel.Information, "Let’s Encrypt Staging HTTP-01 外部驗證成功；未修改 IIS Binding。");
        await SaveSettingsAsync();
        MessageBox.Show(this, "Staging 外部驗證成功。測試憑證未安裝且已清除。", "驗證成功", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private async void OnRunProductionRequested(object? sender, EventArgs e) =>
        await RunOperationAsync("正在正式申請憑證並更新 IIS…", RunProductionCoreAsync);

    private async Task RunProductionCoreAsync()
    {
        if (!ViewModel.AcceptTerms || !ViewModel.AcknowledgeCertificateTransparency)
        {
            MessageBox.Show(this, "請先同意 Let’s Encrypt 服務條款並確認 Certificate Transparency 公開紀錄。", "尚未完成確認", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!ArePreflightGatesCurrent(requireStaging: true, out var gateError))
        {
            ResetExpiredGates();
            MessageBox.Show(this, gateError, "驗證已失效", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (!TryBuildCertificateRequest(out var certificateRequest, out var validationError))
        {
            MessageBox.Show(this, validationError, "設定不完整", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // Refresh only the preview inventory. Rebuilding the bound selection here
        // could reset the user's validated request while a production flow is active.
        _iisInventory = await _iisDiscoveryService.DiscoverAsync(_lifetime.Token);
        if (!_iisInventory.IsIisInstalled || _iisInventory.ErrorMessage is not null ||
            !_iisInventory.Sites.Any(site => site.Id == certificateRequest.SiteId))
        {
            throw new InvalidOperationException(_iisInventory.ErrorMessage ?? "選取的 IIS 網站已不存在，請重新檢查。");
        }
        var previewResult = await RunElevatedActionAsync(
            ElevatedWorkerAction.ReadRenewalPreview,
            new ReadRenewalPreviewPayload { CertificateRequest = certificateRequest },
            TimeSpan.FromMinutes(2));
        if (!previewResult.Success || string.IsNullOrWhiteSpace(previewResult.PayloadJson))
        {
            await ReportWorkerFailureAsync("無法安全讀取既有續期設定", previewResult);
            return;
        }
        var renewalPreview = Deserialize<WinAcmeRenewalPreview>(previewResult.PayloadJson);
        var removalConfirmed = false;
        if (renewalPreview.RequiresRemovalConfirmation)
        {
            removalConfirmed = MessageBox.Show(this,
                "下列網域將不再包含於這個網站的續期設定：\n\n" +
                string.Join("\n", renewalPreview.RemovedHostNames) +
                "\n\n原有 Binding 不會因此自動刪除，但這些網域後續可能無法透過本設定續期。若不是刻意移除，請取消並把網域加回申請清單。確定要縮減？",
                "確認移除續期網域", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No) == MessageBoxResult.Yes;
            if (!removalConfirmed) return;
        }
        var confirmation = MessageBox.Show(
            this,
            BuildProductionPreview(certificateRequest, renewalPreview),
            "正式簽發與 IIS Binding 變更預覽",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning,
            MessageBoxResult.No);
        if (confirmation != MessageBoxResult.Yes)
        {
            await LogAsync(AppLogLevel.Information, "使用者取消正式簽發預覽。");
            return;
        }

        // The preview and UAC can remain open beyond the gate lifetime.
        if (!ArePreflightGatesCurrent(requireStaging: true, out gateError))
        {
            ResetExpiredGates();
            MessageBox.Show(this, gateError, "驗證已失效", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var result = await RunElevatedActionAsync(
            ElevatedWorkerAction.RunWinAcme,
            new RunWinAcmeWorkerPayload
            {
                Operation = WinAcmeWorkerOperation.ProductionIssuance,
                ExpectedRenewalStateSha256 = renewalPreview.ExpectedStateSha256,
                ConfirmRemovedRenewalNames = removalConfirmed,
                WinAcmePath = ViewModel.WinAcmePath,
                ExpectedExecutableSha256 = WinAcmeRecommendedRelease.ExecutableSha256,
                CertificateRequest = certificateRequest
            },
            TimeSpan.FromMinutes(35));
        await LogWorkerOutputAsync(result);
        RunWinAcmeWorkerOutput? output = null;
        if (!string.IsNullOrWhiteSpace(result.PayloadJson))
        {
            output = Deserialize<RunWinAcmeWorkerOutput>(result.PayloadJson);
        }

        if (!result.Success)
        {
            ViewModel.OverallStatus = "正式簽發失敗";
            ViewModel.OverallStatusDetail = output?.RollbackAttempted == true
                ? output.RollbackSucceeded
                    ? "IIS 設定已由備份復原；請查看 Log 後再重試。"
                    : "IIS 自動復原未成功，請立即人工檢查 IIS。"
                : "未進行 IIS 變更或變更前即停止。";
            await ReportWorkerFailureAsync("正式簽發失敗", result);
            return;
        }

        ViewModel.OverallStatus = output?.RenewalTaskReady == true
            ? "正式憑證已安裝並啟用自動續期"
            : "憑證已安裝，但排程需人工確認";
        ViewModel.OverallStatusDetail = output?.RenewalTaskReady == true
            ? $"IIS Binding 已驗證；舊憑證保留 {CertificateRetentionService.RetentionDays} 天後僅在未綁定時清理。"
            : result.ErrorMessage ?? "找不到可驗證的 SYSTEM 續期排程。";
        await LogAsync(
            output?.RenewalTaskReady == true ? AppLogLevel.Information : AppLogLevel.Warning,
            $"正式簽發成功；IIS backup={output?.IisBackupName ?? "(未知)"}；{output?.RenewalTaskSummary ?? result.ErrorMessage}");
        ViewModel.StagingPassed = false;
        _stagingPassedAt = null;
        _stagingFingerprint = null;
        await RefreshSitesAsync(showErrors: false);
        await SaveSettingsAsync();
        ViewModel.MaintenanceCertificates.Clear();
        ViewModel.MaintenanceTasks.Clear();
        ViewModel.MaintenanceCheckedAt = "正式操作後狀態已變更，請重新整理";
        ViewModel.MaintenanceSummary = "憑證安裝已完成；可到本頁重新讀取目前的憑證與續期排程快照。";
        MessageBox.Show(
            this,
            output?.RenewalTaskReady == true
                ? "正式憑證已寫入 LocalMachine\\WebHosting、IIS HTTPS Binding 已驗證，win-acme SYSTEM 每日續期排程已就緒。"
                : "正式憑證與 IIS Binding 已完成，但無法確認 SYSTEM 續期排程。請開啟工作排程器人工確認。",
            "正式簽發完成",
            MessageBoxButton.OK,
            output?.RenewalTaskReady == true ? MessageBoxImage.Information : MessageBoxImage.Warning);
    }

    private async Task<ElevatedWorkerResult> RunElevatedActionAsync(
        ElevatedWorkerAction action,
        object payload,
        TimeSpan timeout)
    {
        var payloadJson = JsonSerializer.Serialize(payload, JsonOptions);
        if (_elevationService.IsAdministrator)
        {
            return await new ElevatedWorkerDispatcher().ExecuteAsync(new ElevatedWorkerRequest
            {
                Action = action,
                PayloadJson = payloadJson
            }, _lifetime.Token);
        }

        return await _elevationService.RunWorkerAsync(
            action,
            payloadJson,
            timeout,
            _lifetime.Token);
    }

    private bool TryBuildLocalPreflightRequest(out LocalPreflightRequest request, out string error)
    {
        request = new LocalPreflightRequest();
        error = string.Empty;
        if (ViewModel.SelectedSite is null ||
            !long.TryParse(ViewModel.SelectedSite.Id, out var siteId) || siteId <= 0)
        {
            error = "請先選擇有效的 IIS 網站。";
            return false;
        }

        var domains = ViewModel.GetRequestedDomains();
        if (domains.Count == 0)
        {
            error = "請至少輸入一個網域名稱。";
            return false;
        }

        if (string.IsNullOrWhiteSpace(ViewModel.WinAcmePath))
        {
            error = "請先下載建議版本或選擇 wacs.exe。";
            return false;
        }

        try
        {
            var selectedWinAcme = Path.GetFullPath(ViewModel.WinAcmePath.Trim().Trim('"'));
            var managedWinAcme = Path.GetFullPath(AppPaths.WinAcmeExecutable);
            if (!string.Equals(selectedWinAcme, managedWinAcme, StringComparison.OrdinalIgnoreCase))
            {
                error = $"{Infrastructure.AppVersion.DisplayVersion} 的本機檢查、Staging 與正式簽發只允許工具下載並保護的管理版 win-acme。『選擇檔案』僅供版本與雜湊診斷；請按『下載建議版本』。";
                return false;
            }
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            error = $"wacs.exe 路徑無效：{exception.Message}";
            return false;
        }

        request = new LocalPreflightRequest
        {
            SelectedSiteId = siteId,
            SelectedSiteName = ViewModel.SelectedSite.Name,
            DomainNames = domains.ToList(),
            WinAcmePath = ViewModel.WinAcmePath,
            ExpectedWinAcmeSha256 = WinAcmeRecommendedRelease.ExecutableSha256,
            RequiredRsaKeyBits = 2048,
            RequireStartedSite = true
        };
        return true;
    }

    private bool TryBuildCertificateRequest(out WinAcmeCertificateRequest request, out string error)
    {
        request = null!;
        if (!TryBuildLocalPreflightRequest(out var local, out error))
        {
            return false;
        }

        try
        {
            request = new WinAcmeCertificateRequest
            {
                SiteId = local.SelectedSiteId,
                HostNames = local.DomainNames,
                CommonName = local.DomainNames[0],
                ContactEmail = ViewModel.ContactEmail,
                FriendlyName = $"MSTECH IIS SSL - {local.SelectedSiteName} - {local.DomainNames[0]}"
            };
            _ = new WinAcmeCommandBuilder().BuildStagingValidation(request);
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException)
        {
            error = exception.Message;
            request = null!;
            return false;
        }
    }

    private bool ConfirmRequiredWarnings(string phaseName, IEnumerable<PreflightCheckResult> checks)
    {
        var warnings = checks
            .Where(check => check.Status == CheckStatus.Warning && check.RequiresUserConfirmation)
            .ToArray();
        if (warnings.Length == 0)
        {
            return true;
        }

        var details = string.Join(
            Environment.NewLine + Environment.NewLine,
            warnings.Select(check => $"• {check.Title}\n  {check.Summary}"));
        return MessageBox.Show(
                   this,
                   $"{phaseName}有 {warnings.Length} 個黃色項目無法由本機完全證明：\n\n{details}\n\n您是否已人工確認並接受繼續？正式簽發前仍必須通過 Let’s Encrypt Staging。",
                   $"確認{phaseName}黃色項目",
                   MessageBoxButton.YesNo,
                   MessageBoxImage.Warning,
                   MessageBoxResult.No) == MessageBoxResult.Yes;
    }

    private bool ArePreflightGatesCurrent(bool requireStaging, out string error)
    {
        error = string.Empty;
        var publicFingerprint = BuildPublicFingerprint();
        var localFingerprint = BuildLocalFingerprint();
        var stagingFingerprint = BuildStagingFingerprint();
        if (!ViewModel.PublicPreflightPassed || _publicPassedAt is null ||
            !string.Equals(_publicFingerprint, publicFingerprint, StringComparison.Ordinal) ||
            DateTimeOffset.Now - _publicPassedAt > GateFreshness)
        {
            error = "公開環境檢查尚未通過、設定已變更，或結果已超過 30 分鐘。";
            return false;
        }

        if (!ViewModel.LocalPreflightPassed || _localPassedAt is null ||
            !string.Equals(_localFingerprint, localFingerprint, StringComparison.Ordinal) ||
            DateTimeOffset.Now - _localPassedAt > GateFreshness)
        {
            error = "本機 IIS／權限檢查尚未通過、設定已變更，或結果已超過 30 分鐘。";
            return false;
        }

        if (requireStaging &&
            (!ViewModel.StagingPassed || _stagingPassedAt is null ||
             !string.Equals(_stagingFingerprint, stagingFingerprint, StringComparison.Ordinal) ||
             DateTimeOffset.Now - _stagingPassedAt > GateFreshness))
        {
            error = "Staging 驗證尚未通過、設定已變更，或結果已超過 30 分鐘。";
            return false;
        }

        return true;
    }

    private void ResetExpiredGates()
    {
        var publicFingerprint = BuildPublicFingerprint();
        var localFingerprint = BuildLocalFingerprint();
        var stagingFingerprint = BuildStagingFingerprint();
        if (_publicPassedAt is null || DateTimeOffset.Now - _publicPassedAt > GateFreshness ||
            !string.Equals(_publicFingerprint, publicFingerprint, StringComparison.Ordinal))
        {
            ViewModel.PublicPreflightPassed = false;
        }

        if (_localPassedAt is null || DateTimeOffset.Now - _localPassedAt > GateFreshness ||
            !string.Equals(_localFingerprint, localFingerprint, StringComparison.Ordinal))
        {
            ViewModel.LocalPreflightPassed = false;
        }

        if (_stagingPassedAt is null || DateTimeOffset.Now - _stagingPassedAt > GateFreshness ||
            !string.Equals(_stagingFingerprint, stagingFingerprint, StringComparison.Ordinal))
        {
            ViewModel.StagingPassed = false;
        }
    }

    private string BuildPublicFingerprint()
    {
        var canonical = string.Join('|',
            ViewModel.IsSanMode ? "san" : "single",
            string.Join(',', ViewModel.GetRequestedDomains().OrderBy(name => name, StringComparer.OrdinalIgnoreCase)));
        return HashFingerprint(canonical);
    }

    private string BuildLocalFingerprint()
    {
        var canonical = string.Join('|',
            BuildPublicFingerprint(),
            ViewModel.SelectedSite?.Id ?? string.Empty,
            Path.GetFullPath(string.IsNullOrWhiteSpace(ViewModel.WinAcmePath)
                ? Path.Combine(AppContext.BaseDirectory, "missing-wacs.exe")
                : ViewModel.WinAcmePath),
            WinAcmeRecommendedRelease.ExecutableSha256);
        return HashFingerprint(canonical);
    }

    private string BuildStagingFingerprint()
    {
        var canonical = string.Join('|',
            BuildLocalFingerprint(),
            ViewModel.ContactEmail.Trim().ToLowerInvariant(),
            "http-01:selfhosting:manual-source:rsa");
        return HashFingerprint(canonical);
    }

    private static string HashFingerprint(string canonical) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));

    private string BuildProductionPreview(WinAcmeCertificateRequest request, WinAcmeRenewalPreview renewalPreview)
    {
        var site = _iisInventory?.Sites.FirstOrDefault(candidate => candidate.Id == request.SiteId);
        var lines = new List<string>
        {
            $"IIS 網站：{site?.Name ?? ViewModel.SelectedSite?.Name}（ID {request.SiteId}）",
            "憑證存放區：LocalMachine\\WebHosting",
            "私鑰：RSA（工具管理版本設定為 2048-bit）",
            $"續期設定：{renewalPreview.RenewalId}（{(renewalPreview.ExistingRenewal ? "更新既有設定" : "首次建立")}）",
            $"新增網域：{(renewalPreview.AddedHostNames.Count == 0 ? "無" : string.Join(", ", renewalPreview.AddedHostNames))}",
            $"移除網域：{(renewalPreview.RemovedHostNames.Count == 0 ? "無" : string.Join(", ", renewalPreview.RemovedHostNames))}",
            string.Empty,
            "Binding 預覽："
        };
        foreach (var host in request.HostNames)
        {
            var hasHttpExact = site?.Bindings.Any(binding =>
                binding.Protocol.Equals("http", StringComparison.OrdinalIgnoreCase) &&
                binding.Port == 80 &&
                binding.HostName.Equals(host, StringComparison.OrdinalIgnoreCase)) == true;
            var hasHttpCatchAll = site?.Bindings.Any(binding =>
                binding.Protocol.Equals("http", StringComparison.OrdinalIgnoreCase) &&
                binding.Port == 80 && string.IsNullOrWhiteSpace(binding.HostName)) == true;
            var hasHttps = site?.Bindings.Any(binding =>
                binding.Protocol.Equals("https", StringComparison.OrdinalIgnoreCase) &&
                binding.Port == 443 &&
                binding.HostName.Equals(host, StringComparison.OrdinalIgnoreCase)) == true;
            var httpState = hasHttpExact
                ? "Port 80 已有精確 Binding"
                : hasHttpCatchAll
                    ? "Port 80 使用 catch-all（不修改）"
                    : "Port 80 無 IIS Binding；已由 Staging SelfHosting 實測（不修改）";
            lines.Add($"• {host}：{httpState}；Port 443 將{(hasHttps ? "更新現有 Binding" : "建立 SNI Binding")}。");
        }

        lines.Add(string.Empty);
        lines.Add("正式執行前會建立 IIS appcmd 完整設定備份；win-acme 失敗或簽發後找不到預期 HTTPS Binding 時會自動復原。");
        lines.Add($"前一張憑證保留 {CertificateRetentionService.RetentionDays} 天，屆期僅在不再被任何 IIS HTTPS Binding 使用時移除。");
        lines.Add("成功後會確認 win-acme 每日 SYSTEM 自動續期排程。");
        lines.Add(string.Empty);
        lines.Add("這會向 Let’s Encrypt 正式環境送出申請並留下 CT 公開紀錄。確定繼續？");
        return string.Join(Environment.NewLine, lines);
    }

    private void RefreshDisplayedChecks()
    {
        var checks = _publicChecks
            .Where(check => check.Id != "acme-staging-challenge")
            .Concat(_localChecks)
            .ToList();
        checks.Add(_stagingCheck ?? new PreflightCheckResult
        {
            Id = "acme-staging-challenge",
            Phase = PreflightPhase.AcmeStaging,
            Category = "ACME",
            Title = "Staging HTTP-01 外部驗證",
            Status = CheckStatus.Pending,
            Summary = "前兩階段通過後，必須由 Let’s Encrypt Staging 從 Internet 實際驗證。",
            Remediation = "正式簽發按鈕會維持停用，直到 Staging 成功。"
        });
        ViewModel.ReplaceCheckResults(checks);
    }

    private async void OnStartWithWindowsChanged(object? sender, bool enabled)
    {
        var status = _autoStartService.SetEnabled(enabled);
        if (!string.IsNullOrWhiteSpace(status.ErrorMessage) ||
            status.IsEnabled != enabled || (enabled && !status.MatchesCurrentExecutable))
        {
            ViewModel.SetStartWithWindowsSilently(!enabled);
            var message = status.ErrorMessage ?? "Windows 登入自動啟動設定未能正確寫入。";
            await LogAsync(AppLogLevel.Warning, message);
            MessageBox.Show(this, message, "自動啟動設定失敗", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        await LogAsync(
            AppLogLevel.Information,
            enabled
                ? "已設定目前 Windows 使用者登入後開啟管理介面；憑證續期仍由獨立 SYSTEM 排程執行。"
                : "已取消目前 Windows 使用者登入後開啟管理介面。");
        await SaveSettingsAsync();
    }

    private void OnOpenLogFolderRequested(object? sender, EventArgs e)
    {
        try
        {
            Directory.CreateDirectory(AppPaths.LogsDirectory);
            Process.Start(new ProcessStartInfo
            {
                FileName = AppPaths.LogsDirectory,
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"無法開啟 Log 資料夾：\n{ex.Message}", "開啟失敗", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async Task RunOperationAsync(string busyMessage, Func<Task> operation)
    {
        if (ViewModel.IsBusy)
        {
            return;
        }

        ViewModel.BeginOperation(busyMessage);
        try
        {
            await operation();
        }
        catch (OperationCanceledException) when (_lifetime.IsCancellationRequested)
        {
            // Window is closing.
        }
        catch (Exception exception)
        {
            ViewModel.OverallStatus = "操作失敗";
            ViewModel.OverallStatusDetail = exception.Message;
            await LogAsync(AppLogLevel.Error, "操作發生未預期錯誤。", exception);
            MessageBox.Show(this, exception.Message, "操作失敗", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            ViewModel.EndOperation();
        }
    }

    private async Task ReportWorkerFailureAsync(string title, ElevatedWorkerResult result)
    {
        var message = result.ErrorMessage ?? FirstNonEmpty(result.StdErr, result.StdOut, "未知錯誤");
        await LogAsync(AppLogLevel.Error, $"{title}：{message}");
        MessageBox.Show(
            this,
            $"{message}\n\nExit code：{result.ExitCode?.ToString() ?? "(無)"}\n詳細輸出已寫入執行紀錄。",
            title,
            MessageBoxButton.OK,
            MessageBoxImage.Error);
    }

    private async Task LogWorkerOutputAsync(ElevatedWorkerResult result)
    {
        if (!string.IsNullOrWhiteSpace(result.StdOut))
        {
            await LogAsync(AppLogLevel.Information, "win-acme：" + TruncateForLog(result.StdOut));
        }

        if (!string.IsNullOrWhiteSpace(result.StdErr))
        {
            await LogAsync(AppLogLevel.Warning, "win-acme stderr：" + TruncateForLog(result.StdErr));
        }
    }

    private async Task LogAsync(AppLogLevel level, string message, Exception? exception = null)
    {
        ViewModel.AppendLog(level switch
        {
            AppLogLevel.Error => "錯誤",
            AppLogLevel.Warning => "警告",
            _ => "資訊"
        }, message.ReplaceLineEndings(" ").Trim());
        await _appLogService.WriteAsync(level, message, exception, _lifetime.Token);
    }

    private async Task SaveSettingsAsync()
    {
        _settings.WinAcmePath = ViewModel.WinAcmePath;
        _settings.ContactEmail = ViewModel.ContactEmail;
        _settings.SelectedSiteId = ViewModel.SelectedSite is not null &&
                                   long.TryParse(ViewModel.SelectedSite.Id, out var siteId)
            ? siteId
            : null;
        _settings.NameMode = ViewModel.IsSanMode
            ? CertificateNameMode.SubjectAlternativeNames
            : CertificateNameMode.SingleDomain;
        _settings.DomainNames = ViewModel.GetRequestedDomains().ToList();
        _settings.TermsAccepted = ViewModel.AcceptTerms;
        _settings.CertificateTransparencyAcknowledged = ViewModel.AcknowledgeCertificateTransparency;
        _settings.KeepPreviousCertificate = true;
        _settings.PreviousCertificateRetentionDays = CertificateRetentionService.RetentionDays;
        _settings.LastPublicCheckAt = _publicPassedAt;
        _settings.LastStagingCheckAt = _stagingPassedAt;
        await _settingsService.SaveAsync(_settings, _lifetime.Token);
    }

    private void OnClosing(object? sender, System.ComponentModel.CancelEventArgs e)
    {
        if (ViewModel.IsBusy)
        {
            e.Cancel = true;
            MessageBox.Show(
                this,
                "管理員或憑證操作仍在執行，請等候完成後再關閉，以免失去執行結果。",
                "操作尚未完成",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        try
        {
            Task.Run(async () => await SaveSettingsAsync()).GetAwaiter().GetResult();
        }
        catch
        {
            // Settings are convenience data; never trap the user in the window.
        }
    }

    private void OnClosed(object? sender, EventArgs e)
    {
        _gateTimer.Stop();
        _lifetime.Cancel();
        _publicPreflightService.Dispose();
        _lifetime.Dispose();
    }

    private void ModeHelpButton_OnClick(object sender, RoutedEventArgs e) => ShowModeHelp();

    private void ModeHelpMenuItem_OnClick(object sender, RoutedEventArgs e) => ShowModeHelp();

    private void ShowModeHelp() => new CertificateModeHelpWindow { Owner = this }.ShowDialog();

    private void AboutMenuItem_OnClick(object sender, RoutedEventArgs e) =>
        new AboutWindow { Owner = this }.ShowDialog();

    private void FixSuggestionButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: EnvironmentCheckItemViewModel item })
        {
            return;
        }

        MessageBox.Show(
            this,
            $"{item.Description}\n\n建議處理方式：\n{item.HowToFix}",
            $"如何修正：{item.Name}",
            MessageBoxButton.OK,
            item.Severity == CheckSeverity.Error ? MessageBoxImage.Error : MessageBoxImage.Information);
    }

    private void ExitMenuItem_OnClick(object sender, RoutedEventArgs e) => Close();

    private static T Deserialize<T>(string json) where T : class =>
        JsonSerializer.Deserialize<T>(json, JsonOptions)
        ?? throw new InvalidDataException("背景工作沒有回傳有效資料。");

    private static string FirstNonEmpty(params string?[] values) =>
        values.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value))?.Trim() ?? string.Empty;

    private static string TruncateForLog(string value) =>
        value.Length <= 5000 ? value : value[..5000] + " [輸出已截斷]";
}
