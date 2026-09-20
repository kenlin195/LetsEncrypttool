using System.Windows.Media;

namespace Mstech.IisSslManager.ViewModels;

public enum CertificateRequestMode
{
    SingleDomain,
    SubjectAlternativeNames
}

public enum CheckSeverity
{
    Pending,
    Success,
    Warning,
    Error
}

public sealed class IisSiteOptionViewModel
{
    public required string Name { get; init; }
    public string Id { get; init; } = string.Empty;
    public string BindingsSummary { get; init; } = string.Empty;

    public string DisplayName => string.IsNullOrWhiteSpace(Id) ? Name : $"{Name}（ID {Id}）";
}

public sealed class DomainEntryViewModel : ObservableObject
{
    private string _hostName = string.Empty;
    private CheckSeverity _status = CheckSeverity.Pending;
    private string _statusText = "尚未檢查";
    private string _detail = "輸入網域後執行環境檢查";

    public string HostName
    {
        get => _hostName;
        set => SetProperty(ref _hostName, value);
    }

    public CheckSeverity Status
    {
        get => _status;
        set
        {
            if (SetProperty(ref _status, value))
            {
                OnPropertyChanged(nameof(StatusTextBrush));
                OnPropertyChanged(nameof(StatusBackground));
            }
        }
    }

    public string StatusText
    {
        get => _statusText;
        set => SetProperty(ref _statusText, value);
    }

    public string Detail
    {
        get => _detail;
        set => SetProperty(ref _detail, value);
    }

    public Brush StatusTextBrush => Status switch
    {
        CheckSeverity.Success => new SolidColorBrush(Color.FromRgb(20, 128, 74)),
        CheckSeverity.Warning => new SolidColorBrush(Color.FromRgb(169, 98, 0)),
        CheckSeverity.Error => new SolidColorBrush(Color.FromRgb(199, 56, 56)),
        _ => new SolidColorBrush(Color.FromRgb(91, 108, 122))
    };

    public Brush StatusBackground => Status switch
    {
        CheckSeverity.Success => new SolidColorBrush(Color.FromRgb(229, 246, 236)),
        CheckSeverity.Warning => new SolidColorBrush(Color.FromRgb(255, 244, 219)),
        CheckSeverity.Error => new SolidColorBrush(Color.FromRgb(255, 234, 234)),
        _ => new SolidColorBrush(Color.FromRgb(237, 242, 246))
    };
}

public sealed class EnvironmentCheckItemViewModel : ObservableObject
{
    private CheckSeverity _severity = CheckSeverity.Pending;
    private string _statusText = "等待檢查";
    private string _result = "尚未執行";
    private string _howToFix = string.Empty;

    public string Id { get; init; } = string.Empty;
    public required string Name { get; init; }
    public required string Description { get; init; }
    public bool IsRequired { get; init; } = true;
    public Models.PreflightPhase Phase { get; init; }
    public bool RequiresUserConfirmation { get; init; }

    public CheckSeverity Severity
    {
        get => _severity;
        set
        {
            if (SetProperty(ref _severity, value))
            {
                OnPropertyChanged(nameof(StatusBrush));
                OnPropertyChanged(nameof(StatusBackground));
                OnPropertyChanged(nameof(StatusIcon));
            }
        }
    }

    public string StatusText
    {
        get => _statusText;
        set => SetProperty(ref _statusText, value);
    }

    public string Result
    {
        get => _result;
        set => SetProperty(ref _result, value);
    }

    public string HowToFix
    {
        get => _howToFix;
        set
        {
            if (SetProperty(ref _howToFix, value))
            {
                OnPropertyChanged(nameof(HasFixSuggestion));
            }
        }
    }

    public bool HasFixSuggestion => !string.IsNullOrWhiteSpace(HowToFix);

    public Brush StatusBrush => Severity switch
    {
        CheckSeverity.Success => new SolidColorBrush(Color.FromRgb(20, 128, 74)),
        CheckSeverity.Warning => new SolidColorBrush(Color.FromRgb(169, 98, 0)),
        CheckSeverity.Error => new SolidColorBrush(Color.FromRgb(199, 56, 56)),
        _ => new SolidColorBrush(Color.FromRgb(91, 108, 122))
    };

    public Brush StatusBackground => Severity switch
    {
        CheckSeverity.Success => new SolidColorBrush(Color.FromRgb(229, 246, 236)),
        CheckSeverity.Warning => new SolidColorBrush(Color.FromRgb(255, 244, 219)),
        CheckSeverity.Error => new SolidColorBrush(Color.FromRgb(255, 234, 234)),
        _ => new SolidColorBrush(Color.FromRgb(237, 242, 246))
    };

    public string StatusIcon => Severity switch
    {
        CheckSeverity.Success => "✓",
        CheckSeverity.Warning => "!",
        CheckSeverity.Error => "×",
        _ => "•"
    };
}

public sealed record MaintenanceCertificateRow
{
    public required string Site { get; init; }
    public required string Host { get; init; }
    public required string Certificate { get; init; }
    public required string Expiry { get; init; }
    public required string Summary { get; init; }
}

public sealed record MaintenanceTaskRow
{
    public required string Name { get; init; }
    public required string Schedule { get; init; }
    public required string LastExecution { get; init; }
    public required string Summary { get; init; }
}

public sealed class LogEntryViewModel
{
    public DateTime Timestamp { get; init; } = DateTime.Now;
    public string Level { get; init; } = "資訊";
    public string Message { get; init; } = string.Empty;
    public string TimestampText => Timestamp.ToString("yyyy-MM-dd HH:mm:ss");
    public Brush LevelBrush => Level switch
    {
        "成功" => new SolidColorBrush(Color.FromRgb(20, 128, 74)),
        "警告" => new SolidColorBrush(Color.FromRgb(169, 98, 0)),
        "錯誤" => new SolidColorBrush(Color.FromRgb(199, 56, 56)),
        _ => new SolidColorBrush(Color.FromRgb(23, 104, 168))
    };
}
