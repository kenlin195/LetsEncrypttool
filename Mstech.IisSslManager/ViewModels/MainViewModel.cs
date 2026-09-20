using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Net.Mail;
using System.Windows.Media;
using System.Windows.Input;
using Mstech.IisSslManager.Models;

namespace Mstech.IisSslManager.ViewModels;

public sealed class MainViewModel : ObservableObject
{
    private IisSiteOptionViewModel? _selectedSite;
    private CertificateRequestMode _requestMode = CertificateRequestMode.SingleDomain;
    private string _singleDomain = string.Empty;
    private DomainEntryViewModel? _selectedDomain;
    private string _contactEmail = string.Empty;
    private string _winAcmePath = string.Empty;
    private bool _acceptTerms;
    private bool _acknowledgeCt;
    private bool _startWithWindows;
    private bool _isBusy;
    private string _busyMessage = string.Empty;
    private string _overallStatus = "等待環境檢查";
    private string _overallStatusDetail = "完成設定後，請先執行環境檢查。";
    private bool _publicPreflightPassed;
    private bool _localPreflightPassed;
    private bool _stagingPassed;
    private int _selectedTabIndex;
    private bool _suppressStartWithWindowsChanged;
    private bool _refreshingSites;
    private IReadOnlyList<PreflightCheckResult> _displayedChecks = [];
    private string _maintenanceSummary = "尚未讀取。按「重新整理狀態」以唯讀方式查詢；需要時由 Windows UAC 驗證權限。";
    private string _maintenanceCheckedAt = "尚無狀態快照";

    public MainViewModel()
    {
        AddDomainCommand = new RelayCommand(AddDomain);
        RemoveDomainCommand = new RelayCommand<DomainEntryViewModel>(RemoveDomain, domain => domain is not null);
        RefreshSitesCommand = new RelayCommand(() => RefreshSitesRequested?.Invoke(this, EventArgs.Empty), () => !IsBusy);
        RefreshMaintenanceCommand = new RelayCommand(() => RefreshMaintenanceRequested?.Invoke(this, EventArgs.Empty), () => !IsBusy);
        BrowseWinAcmeCommand = new RelayCommand(() => BrowseWinAcmeRequested?.Invoke(this, EventArgs.Empty), () => !IsBusy);
        DownloadWinAcmeCommand = new RelayCommand(() => DownloadWinAcmeRequested?.Invoke(this, EventArgs.Empty), () => !IsBusy);
        RunPublicPreflightCommand = new RelayCommand(() => RunPublicPreflightRequested?.Invoke(this, EventArgs.Empty), CanRunPublicPreflight);
        RunLocalPreflightCommand = new RelayCommand(() => RunLocalPreflightRequested?.Invoke(this, EventArgs.Empty), CanRunLocalPreflight);
        RunPreflightCommand = new RelayCommand(() => RunPreflightRequested?.Invoke(this, EventArgs.Empty), CanRunPreflight);
        RunStagingCommand = new RelayCommand(() => RunStagingRequested?.Invoke(this, EventArgs.Empty), CanRunStaging);
        RunProductionCommand = new RelayCommand(() => RunProductionRequested?.Invoke(this, EventArgs.Empty), CanRunProduction);
        OpenLogFolderCommand = new RelayCommand(() => OpenLogFolderRequested?.Invoke(this, EventArgs.Empty));
        ClearLogCommand = new RelayCommand(() => Logs.Clear(), () => Logs.Count > 0);

        InitializeCheckItems();
        AddDomainEntry(new DomainEntryViewModel());
        AppendLog("資訊", "程式已啟動；尚未進行任何 IIS 或憑證變更。 ");
    }

    public ObservableCollection<IisSiteOptionViewModel> Sites { get; } = [];
    public ObservableCollection<DomainEntryViewModel> Domains { get; } = [];
    public ObservableCollection<EnvironmentCheckItemViewModel> CheckItems { get; } = [];
    public ObservableCollection<LogEntryViewModel> Logs { get; } = [];
    public ObservableCollection<MaintenanceCertificateRow> MaintenanceCertificates { get; } = [];
    public ObservableCollection<MaintenanceTaskRow> MaintenanceTasks { get; } = [];

    public string MaintenanceSummary
    {
        get => _maintenanceSummary;
        set => SetProperty(ref _maintenanceSummary, value);
    }

    public string MaintenanceCheckedAt
    {
        get => _maintenanceCheckedAt;
        set => SetProperty(ref _maintenanceCheckedAt, value);
    }

    public IisSiteOptionViewModel? SelectedSite
    {
        get => _selectedSite;
        set
        {
            var previousId = _selectedSite?.Id;
            if (SetProperty(ref _selectedSite, value))
            {
                if (!_refreshingSites && !string.Equals(previousId, value?.Id, StringComparison.Ordinal))
                {
                    LocalPreflightPassed = false;
                    StagingPassed = false;
                }
                RaiseCommandStates();
            }
        }
    }

    public CertificateRequestMode RequestMode
    {
        get => _requestMode;
        private set
        {
            if (SetProperty(ref _requestMode, value))
            {
                OnPropertyChanged(nameof(IsSingleDomain));
                OnPropertyChanged(nameof(IsSanMode));
                InvalidateAllValidation();
                RaiseCommandStates();
            }
        }
    }

    public bool IsSingleDomain
    {
        get => RequestMode == CertificateRequestMode.SingleDomain;
        set
        {
            if (value)
            {
                RequestMode = CertificateRequestMode.SingleDomain;
            }
        }
    }

    public bool IsSanMode
    {
        get => RequestMode == CertificateRequestMode.SubjectAlternativeNames;
        set
        {
            if (value)
            {
                RequestMode = CertificateRequestMode.SubjectAlternativeNames;
            }
        }
    }

    public string SingleDomain
    {
        get => _singleDomain;
        set
        {
            if (SetProperty(ref _singleDomain, value))
            {
                InvalidateAllValidation();
                RaiseCommandStates();
            }
        }
    }

    public DomainEntryViewModel? SelectedDomain
    {
        get => _selectedDomain;
        set => SetProperty(ref _selectedDomain, value);
    }

    public string ContactEmail
    {
        get => _contactEmail;
        set
        {
            if (SetProperty(ref _contactEmail, value))
            {
                StagingPassed = false;
                RaiseCommandStates();
            }
        }
    }

    public string WinAcmePath
    {
        get => _winAcmePath;
        set
        {
            if (SetProperty(ref _winAcmePath, value))
            {
                LocalPreflightPassed = false;
                StagingPassed = false;
                RaiseCommandStates();
            }
        }
    }

    public bool AcceptTerms
    {
        get => _acceptTerms;
        set
        {
            if (SetProperty(ref _acceptTerms, value))
            {
                RaiseCommandStates();
            }
        }
    }

    public bool AcknowledgeCertificateTransparency
    {
        get => _acknowledgeCt;
        set
        {
            if (SetProperty(ref _acknowledgeCt, value))
            {
                RaiseCommandStates();
            }
        }
    }

    public bool StartWithWindows
    {
        get => _startWithWindows;
        set
        {
            if (SetProperty(ref _startWithWindows, value))
            {
                if (!_suppressStartWithWindowsChanged)
                {
                    StartWithWindowsChanged?.Invoke(this, value);
                }
            }
        }
    }

    public bool IsBusy
    {
        get => _isBusy;
        set
        {
            if (SetProperty(ref _isBusy, value))
            {
                OnPropertyChanged(nameof(IsNotBusy));
                RaiseCommandStates();
            }
        }
    }

    public bool IsNotBusy => !IsBusy;

    public string BusyMessage
    {
        get => _busyMessage;
        set => SetProperty(ref _busyMessage, value);
    }

    public string OverallStatus
    {
        get => _overallStatus;
        set => SetProperty(ref _overallStatus, value);
    }

    public string OverallStatusDetail
    {
        get => _overallStatusDetail;
        set => SetProperty(ref _overallStatusDetail, value);
    }

    public bool PublicPreflightPassed
    {
        get => _publicPreflightPassed;
        set
        {
            if (SetProperty(ref _publicPreflightPassed, value))
            {
                if (!value)
                {
                    StagingPassed = false;
                }

                OnPropertyChanged(nameof(PreflightPassed));
                OnPropertyChanged(nameof(PublicPhaseStatusText));
                OnPropertyChanged(nameof(PublicPhaseStatusBrush));
                OnPropertyChanged(nameof(PublicPhaseStatusBackground));
                UpdateCheckAcknowledgements();
                RaiseCommandStates();
            }
        }
    }

    public bool LocalPreflightPassed
    {
        get => _localPreflightPassed;
        set
        {
            if (SetProperty(ref _localPreflightPassed, value))
            {
                if (!value)
                {
                    StagingPassed = false;
                }

                OnPropertyChanged(nameof(PreflightPassed));
                OnPropertyChanged(nameof(LocalPhaseStatusText));
                OnPropertyChanged(nameof(LocalPhaseStatusBrush));
                OnPropertyChanged(nameof(LocalPhaseStatusBackground));
                UpdateCheckAcknowledgements();
                RaiseCommandStates();
            }
        }
    }

    public bool StagingPassed
    {
        get => _stagingPassed;
        set
        {
            if (SetProperty(ref _stagingPassed, value))
            {
                OnPropertyChanged(nameof(StagingPhaseStatusText));
                OnPropertyChanged(nameof(StagingPhaseStatusBrush));
                OnPropertyChanged(nameof(StagingPhaseStatusBackground));
                RaiseCommandStates();
            }
        }
    }

    public bool PreflightPassed => PublicPreflightPassed && LocalPreflightPassed;

    public string PublicPhaseStatusText => PublicPreflightPassed ? "已通過" : "尚未通過";
    public string LocalPhaseStatusText => LocalPreflightPassed ? "已通過" : "尚未通過";
    public string StagingPhaseStatusText => StagingPassed ? "已通過" : "尚未通過";
    public Brush PublicPhaseStatusBrush => GetPhaseForeground(PublicPreflightPassed);
    public Brush LocalPhaseStatusBrush => GetPhaseForeground(LocalPreflightPassed);
    public Brush StagingPhaseStatusBrush => GetPhaseForeground(StagingPassed);
    public Brush PublicPhaseStatusBackground => GetPhaseBackground(PublicPreflightPassed);
    public Brush LocalPhaseStatusBackground => GetPhaseBackground(LocalPreflightPassed);
    public Brush StagingPhaseStatusBackground => GetPhaseBackground(StagingPassed);

    public int SelectedTabIndex
    {
        get => _selectedTabIndex;
        set => SetProperty(ref _selectedTabIndex, value);
    }

    public ICommand AddDomainCommand { get; }
    public ICommand RemoveDomainCommand { get; }
    public ICommand RefreshSitesCommand { get; }
    public ICommand RefreshMaintenanceCommand { get; }
    public ICommand BrowseWinAcmeCommand { get; }
    public ICommand DownloadWinAcmeCommand { get; }
    public ICommand RunPublicPreflightCommand { get; }
    public ICommand RunLocalPreflightCommand { get; }
    public ICommand RunPreflightCommand { get; }
    public ICommand RunStagingCommand { get; }
    public ICommand RunProductionCommand { get; }
    public ICommand OpenLogFolderCommand { get; }
    public ICommand ClearLogCommand { get; }

    public event EventHandler? RefreshSitesRequested;
    public event EventHandler? RefreshMaintenanceRequested;
    public event EventHandler? BrowseWinAcmeRequested;
    public event EventHandler? DownloadWinAcmeRequested;
    public event EventHandler? RunPublicPreflightRequested;
    public event EventHandler? RunLocalPreflightRequested;
    public event EventHandler? RunPreflightRequested;
    public event EventHandler? RunStagingRequested;
    public event EventHandler? RunProductionRequested;
    public event EventHandler? OpenLogFolderRequested;
    public event EventHandler<bool>? StartWithWindowsChanged;

    public IReadOnlyList<string> GetRequestedDomains()
    {
        if (IsSingleDomain)
        {
            return string.IsNullOrWhiteSpace(SingleDomain)
                ? []
                : [NormalizeHost(SingleDomain)];
        }

        return Domains
            .Select(domain => NormalizeHost(domain.HostName))
            .Where(host => !string.IsNullOrWhiteSpace(host))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public void ReplaceSites(IEnumerable<IisSiteOptionViewModel> sites)
    {
        var selectedId = SelectedSite?.Id;
        var replacements = sites.OrderBy(site => site.Name, StringComparer.CurrentCultureIgnoreCase).ToArray();
        _refreshingSites = true;
        try
        {
            // ComboBox.SelectedItem is two-way: CollectionChanged.Reset can write
            // null back while the same site is temporarily removed and re-added.
            Sites.Clear();
            foreach (var site in replacements) Sites.Add(site);
            SelectedSite = Sites.FirstOrDefault(site =>
                string.Equals(site.Id, selectedId, StringComparison.Ordinal)) ?? Sites.FirstOrDefault();
        }
        finally
        {
            _refreshingSites = false;
            if (!string.Equals(selectedId, SelectedSite?.Id, StringComparison.Ordinal))
            {
                LocalPreflightPassed = false;
                StagingPassed = false;
            }
            RaiseCommandStates();
        }
    }

    public void SetRequestedDomains(CertificateNameMode mode, IReadOnlyList<string> domains)
    {
        if (mode == CertificateNameMode.SubjectAlternativeNames)
        {
            IsSanMode = true;
            foreach (var existing in Domains)
            {
                existing.PropertyChanged -= DomainEntryOnPropertyChanged;
            }

            Domains.Clear();
            foreach (var domain in domains)
            {
                AddDomainEntry(new DomainEntryViewModel { HostName = domain });
            }

            if (Domains.Count == 0)
            {
                AddDomainEntry(new DomainEntryViewModel());
            }
        }
        else
        {
            IsSingleDomain = true;
            SingleDomain = domains.FirstOrDefault() ?? string.Empty;
        }

        InvalidateAllValidation();
        RaiseCommandStates();
    }

    public void SetStartWithWindowsSilently(bool enabled)
    {
        _suppressStartWithWindowsChanged = true;
        try
        {
            StartWithWindows = enabled;
        }
        finally
        {
            _suppressStartWithWindowsChanged = false;
        }
    }

    public void ReplaceCheckResults(IEnumerable<PreflightCheckResult> checks)
    {
        _displayedChecks = checks.ToArray();
        CheckItems.Clear();
        foreach (var check in _displayedChecks)
        {
            CheckItems.Add(new EnvironmentCheckItemViewModel
            {
                Id = check.Id,
                Name = check.Title,
                Description = string.IsNullOrWhiteSpace(check.DomainName)
                    ? check.Category
                    : $"{check.Category}・{check.DomainName}",
                IsRequired = check.IsRequired,
                Phase = check.Phase,
                RequiresUserConfirmation = check.RequiresUserConfirmation,
                Severity = MapSeverity(check.Status),
                StatusText = GetCheckStatusText(check, IsPhaseConfirmed(check.Phase)),
                Result = check.Summary,
                HowToFix = check.Remediation ?? string.Empty
            });
        }

        UpdateDomainStatuses(_displayedChecks);
    }

    private bool IsPhaseConfirmed(PreflightPhase phase) => phase switch
    {
        PreflightPhase.PublicEnvironment => PublicPreflightPassed,
        PreflightPhase.ElevatedLocalEnvironment => LocalPreflightPassed,
        _ => false
    };

    private void UpdateCheckAcknowledgements()
    {
        foreach (var item in CheckItems.Where(item => item.Severity == CheckSeverity.Warning))
        {
            item.StatusText = !item.RequiresUserConfirmation ? "提醒"
                : IsPhaseConfirmed(item.Phase) ? "已人工確認" : "需確認";
        }
        UpdateDomainStatuses(_displayedChecks);
    }

    internal static string GetCheckStatusText(PreflightCheckResult check, bool phaseConfirmed) =>
        check.Status != CheckStatus.Warning ? MapStatusText(check.Status)
            : !check.RequiresUserConfirmation ? "提醒"
            : phaseConfirmed ? "已人工確認" : "需確認";

    public void AppendLog(string level, string message)
    {
        Logs.Add(new LogEntryViewModel
        {
            Timestamp = DateTime.Now,
            Level = level,
            Message = message
        });

        while (Logs.Count > 1000)
        {
            Logs.RemoveAt(0);
        }

        (ClearLogCommand as RelayCommand)?.RaiseCanExecuteChanged();
    }

    public void BeginOperation(string message)
    {
        BusyMessage = message;
        IsBusy = true;
    }

    public void EndOperation()
    {
        IsBusy = false;
        BusyMessage = string.Empty;
    }

    private void AddDomain()
    {
        var entry = new DomainEntryViewModel();
        AddDomainEntry(entry);
        SelectedDomain = entry;
        InvalidateAllValidation();
    }

    private void RemoveDomain(DomainEntryViewModel? domain)
    {
        if (domain is null)
        {
            return;
        }

        domain.PropertyChanged -= DomainEntryOnPropertyChanged;
        Domains.Remove(domain);
        if (Domains.Count == 0)
        {
            AddDomainEntry(new DomainEntryViewModel());
        }

        InvalidateAllValidation();
    }

    private bool CanRunPublicPreflight() =>
        !IsBusy && GetRequestedDomains().Count > 0;

    private bool CanRunLocalPreflight() =>
        !IsBusy && SelectedSite is not null && GetRequestedDomains().Count > 0;

    private bool CanRunPreflight() =>
        !IsBusy && SelectedSite is not null && GetRequestedDomains().Count > 0;

    private bool CanRunStaging() =>
        !IsBusy && PublicPreflightPassed && LocalPreflightPassed &&
        AcceptTerms && IsValidEmail(ContactEmail);

    private bool CanRunProduction() =>
        !IsBusy && PublicPreflightPassed && LocalPreflightPassed && StagingPassed &&
        AcceptTerms && AcknowledgeCertificateTransparency &&
        IsValidEmail(ContactEmail);

    private void RaiseCommandStates()
    {
        (RefreshSitesCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (RefreshMaintenanceCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (BrowseWinAcmeCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (DownloadWinAcmeCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (RunPublicPreflightCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (RunLocalPreflightCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (RunPreflightCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (RunStagingCommand as RelayCommand)?.RaiseCanExecuteChanged();
        (RunProductionCommand as RelayCommand)?.RaiseCanExecuteChanged();
    }

    private void InitializeCheckItems()
    {
        CheckItems.Add(new EnvironmentCheckItemViewModel
        {
            Name = "作業系統與權限",
            Description = "Windows Server 2016 以上、x64；需管理動作時由 UAC 驗證。",
            HowToFix = "請使用受支援的 Windows Server，並以有系統管理員權限的帳號通過 UAC。"
        });
        CheckItems.Add(new EnvironmentCheckItemViewModel
        {
            Name = "IIS 網站與繫結",
            Description = "確認站台已啟動，所有網域都有不衝突的 Port 80 HTTP Binding。",
            HowToFix = "在 IIS 管理員加入正確的主機名稱繫結，或依工具提示建立。"
        });
        CheckItems.Add(new EnvironmentCheckItemViewModel
        {
            Name = "公開 DNS",
            Description = "逐一檢查 A、AAAA、CNAME 與 CAA；SAN 每個名稱都必須通過。",
            HowToFix = "請在 DNS 服務商修正記錄；若有不使用的錯誤 AAAA 記錄也要移除。"
        });
        CheckItems.Add(new EnvironmentCheckItemViewModel
        {
            Name = "HTTP-01 外部驗證",
            Description = "Internet 可透過 TCP 80 存取 /.well-known/acme-challenge/。",
            HowToFix = "開放防火牆/NAT 的 TCP 80，並確認 WAF、登入驗證或 Rewrite 未攔截該路徑。"
        });
        CheckItems.Add(new EnvironmentCheckItemViewModel
        {
            Name = "Let’s Encrypt 連線",
            Description = "伺服器可透過 TCP 443 連線 ACME API，日期與時間正確。",
            HowToFix = "檢查 Proxy、對外防火牆、TLS 設定與 Windows 時間同步。"
        });
        CheckItems.Add(new EnvironmentCheckItemViewModel
        {
            Name = "win-acme",
            Description = "確認 wacs.exe 版本、路徑與檔案完整性。",
            HowToFix = "使用「下載建議版本」或指定已核准的 wacs.exe。"
        });
        CheckItems.Add(new EnvironmentCheckItemViewModel
        {
            Name = "憑證與排程權限",
            Description = "可寫入 LocalMachine\\WebHosting、修改 IIS Binding 並建立 SYSTEM 排程。",
            HowToFix = "請用有本機系統管理員權限的帳號通過 UAC。"
        });
    }

    private static string NormalizeHost(string value) =>
        value.Trim().TrimEnd('.').ToLowerInvariant();

    private void UpdateDomainStatuses(IEnumerable<PreflightCheckResult> checks)
    {
        var grouped = checks
            .Where(check => !string.IsNullOrWhiteSpace(check.DomainName))
            .GroupBy(check => NormalizeHost(check.DomainName!), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(group => group.Key, group => group.ToArray(), StringComparer.OrdinalIgnoreCase);
        foreach (var domain in Domains)
        {
            if (!grouped.TryGetValue(NormalizeHost(domain.HostName), out var results))
            {
                domain.Status = CheckSeverity.Pending;
                domain.StatusText = "尚未檢查";
                domain.Detail = "尚無此網域的檢查結果";
                continue;
            }

            domain.Status = results.Any(result => result.Status == CheckStatus.Failed)
                ? CheckSeverity.Error
                : results.Any(result => result.Status == CheckStatus.Warning)
                    ? CheckSeverity.Warning
                    : results.All(result => result.Status is CheckStatus.Passed or CheckStatus.Skipped)
                        ? CheckSeverity.Success
                        : CheckSeverity.Pending;
            domain.StatusText = domain.Status switch
            {
                CheckSeverity.Error => "未通過",
                CheckSeverity.Warning => results.Any(result => result.Status == CheckStatus.Warning &&
                    result.RequiresUserConfirmation && !IsPhaseConfirmed(result.Phase)) ? "需確認" : "已檢查（含提醒）",
                CheckSeverity.Success => "已通過",
                _ => "檢查中"
            };
            domain.Detail = results.FirstOrDefault(result => result.Status == CheckStatus.Failed)?.Summary
                ?? results.FirstOrDefault(result => result.Status == CheckStatus.Warning)?.Summary
                ?? "網域相關檢查已完成";
        }
    }

    private static CheckSeverity MapSeverity(CheckStatus status) => status switch
    {
        CheckStatus.Passed => CheckSeverity.Success,
        CheckStatus.Warning => CheckSeverity.Warning,
        CheckStatus.Failed => CheckSeverity.Error,
        _ => CheckSeverity.Pending
    };

    private static string MapStatusText(CheckStatus status) => status switch
    {
        CheckStatus.Passed => "已通過",
        CheckStatus.Warning => "需確認",
        CheckStatus.Failed => "未通過",
        CheckStatus.Running => "檢查中",
        CheckStatus.Skipped => "已略過",
        _ => "等待檢查"
    };

    private static bool IsValidEmail(string value)
    {
        try
        {
            var address = new MailAddress(value.Trim());
            return string.Equals(address.Address, value.Trim(), StringComparison.OrdinalIgnoreCase) &&
                   !string.IsNullOrWhiteSpace(address.Host);
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        {
            return false;
        }
    }

    private void AddDomainEntry(DomainEntryViewModel entry)
    {
        entry.PropertyChanged += DomainEntryOnPropertyChanged;
        Domains.Add(entry);
    }

    private void DomainEntryOnPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(DomainEntryViewModel.HostName))
        {
            InvalidateAllValidation();
            RaiseCommandStates();
        }
    }

    private void InvalidateAllValidation()
    {
        PublicPreflightPassed = false;
        LocalPreflightPassed = false;
        StagingPassed = false;
    }

    private static Brush GetPhaseForeground(bool passed) => new SolidColorBrush(
        passed ? Color.FromRgb(20, 128, 74) : Color.FromRgb(91, 108, 122));

    private static Brush GetPhaseBackground(bool passed) => new SolidColorBrush(
        passed ? Color.FromRgb(229, 246, 236) : Color.FromRgb(237, 242, 246));
}
