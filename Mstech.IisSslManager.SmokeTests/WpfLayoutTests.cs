using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Mstech.IisSslManager;
using Mstech.IisSslManager.Infrastructure;
using Mstech.IisSslManager.Models;
using Mstech.IisSslManager.ViewModels;

/// <summary>
/// Offline XAML rendering only. Keep this last in the smoke runner because WPF
/// permits one Application per process. Never Show/Run/Close or pump a dispatcher:
/// MainWindow.Loaded reads the machine and Closed saves user settings.
/// </summary>
public static class WpfLayoutTests
{
    public static void Run()
    {
        Exception? failure = null;
        var worker = new Thread(() =>
        {
            try
            {
                RenderOffline();
            }
            catch (Exception exception)
            {
                failure = exception;
            }
        }) { IsBackground = true, Name = "Offline WPF layout smoke" };
        worker.SetApartmentState(ApartmentState.STA);
        worker.Start();
        if (!worker.Join(TimeSpan.FromSeconds(45)))
        {
            throw new TimeoutException("Offline WPF rendering exceeded 45 seconds.");
        }

        if (failure is not null)
        {
            ExceptionDispatchInfo.Capture(failure).Throw();
        }
    }

    private static void RenderOffline()
    {
        Assert(Application.Current is null, "offline renderer requires the only WPF Application in this process");
        var bindingErrors = new BindingErrorListener();
        var source = PresentationTraceSources.DataBindingSource;
        var previousLevel = source.Switch.Level;
        source.Listeners.Add(bindingErrors);
        source.Switch.Level = SourceLevels.Error;
        var previousRenderMode = RenderOptions.ProcessRenderMode;
        RenderOptions.ProcessRenderMode = RenderMode.SoftwareOnly;

        // Application's pending Startup callback and the window's timer must not
        // be dispatched. Layout/rendering below is synchronous and disconnected.
        using var processing = Dispatcher.CurrentDispatcher.DisableProcessing();
        try
        {
            var app = new App();
            app.InitializeComponent();
            SameSiteRefreshKeepsGatesWithTwoWayComboBox();
            var window = new MainWindow();
            var root = window.Content as FrameworkElement
                ?? throw new InvalidOperationException("MainWindow has no FrameworkElement content.");
            Assert(PresentationSource.FromVisual(root) is null && !window.IsLoaded && !root.IsLoaded,
                "offline content unexpectedly acquired a presentation source");
            var tabs = ((Grid)root).Children.OfType<TabControl>().Single();
            var headers = tabs.Items.Cast<TabItem>().Select(item => item.Header?.ToString()).ToArray();
            Assert(headers.SequenceEqual(new[] { "憑證與續期狀態", "1  申請設定", "2  環境檢查", "3  執行紀錄" }),
                "the four main tab headers changed or a tab is missing");
            Assert(AppVersion.DisplayVersion == "v1.3", "offline UI review must render v1.3");

            PopulateSamples(window.ViewModel);
            // A disconnected control may defer the initial selection until its
            // first template/layout pass. Do not pump DataBind/Loaded callbacks.
            root.Measure(new Size(1240, 780));
            root.Arrange(new Rect(0, 0, 1240, 780));
            root.UpdateLayout();
            var output = Path.Combine(AppContext.BaseDirectory, "ui-review");
            Directory.CreateDirectory(output);
            SelectTab(window.ViewModel, tabs, 0);
            Render(root, new Size(1240, 780), Path.Combine(output, "01-maintenance-wide.png"));
            Assert(VisualChildren<TextBlock>(root).Any(text =>
                    new TextRange(text.ContentStart, text.ContentEnd).Text.Contains("v1.3", StringComparison.Ordinal)),
                "visible version label is missing v1.3");
            Assert(VisualChildren<TextBlock>(root).Any(text => text.Text == "shop.example.com"),
                "maintenance certificate binding did not render sample data");
            var maintenanceScroll = (ScrollViewer)((TabItem)tabs.Items[0]).Content;
            Assert(maintenanceScroll.ScrollableHeight > 0,
                "long maintenance content did not produce a scrollable viewport");
            maintenanceScroll.ScrollToBottom();
            Render(root, new Size(1240, 780), Path.Combine(output, "02-maintenance-bottom.png"));
            Assert(maintenanceScroll.VerticalOffset > 0, "maintenance content could not scroll");
            Assert(VisualChildren<TextBlock>(root).Any(text => text.Text.Contains("Sample managed renewal", StringComparison.Ordinal)),
                "maintenance task binding did not render sample data");
            maintenanceScroll.ScrollToTop();
            Render(root, new Size(1080, 660), Path.Combine(output, "03-maintenance-minimum.png"));

            SelectTab(window.ViewModel, tabs, 2);
            Render(root, new Size(1240, 780), Path.Combine(output, "04-environment-confirmed.png"));
            Assert(window.ViewModel.CheckItems.Any(item => item.StatusText == "已人工確認"),
                "confirmed warning sample lost its acknowledged state");
            Assert(VisualChildren<TextBlock>(root).Any(text => text.Text == "已人工確認"),
                "confirmed warning status did not render in the environment list");

            SelectTab(window.ViewModel, tabs, 1);
            Render(root, new Size(1240, 780), Path.Combine(output, "05-request-settings.png"));
            SelectTab(window.ViewModel, tabs, 3);
            Render(root, new Size(1240, 780), Path.Combine(output, "06-execution-log.png"));

            Assert(!window.IsLoaded && !root.IsLoaded && PresentationSource.FromVisual(root) is null,
                "offline render unexpectedly loaded the production window");
            source.Flush();
            Assert(bindingErrors.Messages.Length == 0, "WPF binding errors: " + bindingErrors.Messages);
            Console.WriteLine("Offline WPF review PNGs: " + output);
            // Do not Close or shut down Application: that would raise the
            // production Closed handler. The isolated STA thread simply exits.
        }
        finally
        {
            source.Listeners.Remove(bindingErrors);
            source.Switch.Level = previousLevel;
            RenderOptions.ProcessRenderMode = previousRenderMode;
        }
    }

    private static void PopulateSamples(MainViewModel viewModel)
    {
        viewModel.ReplaceSites([new IisSiteOptionViewModel
        {
            Id = "101", Name = "範例網站 — 多語系網站與線上服務（離線排版測試）", BindingsSummary = "*:80:example.com"
        }]);
        viewModel.SingleDomain = "example.com";
        viewModel.ContactEmail = "admin@example.com";
        viewModel.WinAcmePath = @"C:\ProgramData\MSTECH-IisSslManager\win-acme\wacs.exe";
        viewModel.MaintenanceCheckedAt = "查詢時間：2026-09-20 12:34:56（離線合成資料；非持續監控）";
        viewModel.MaintenanceSummary = "離線排版資料：三個網站 Binding、兩筆續期排程。以下內容只測試長文字換行與捲動，不代表這台電腦的實際狀態。";
        foreach (var host in new[] { "example.com", "shop.example.com", "long-service-name-for-layout-review.example.com" })
        {
            viewModel.MaintenanceCertificates.Add(new MaintenanceCertificateRow
            {
                Site = "範例服務網站：測試較長公司名稱及網站名稱，確認最小視窗下仍能完整換行（ID 101）",
                Host = host,
                Certificate = "WebHosting · 0123456789ABCDEF0123456789ABCDEF01234567",
                Expiry = "2026-10-15 12:34\n剩餘 25 天",
                Summary = "憑證即將到期，請確認自動續期排程及 win-acme 執行紀錄；此段較長的提示應完整換行，不能遮住到期日或憑證指紋。"
            });
        }
        foreach (var index in new[] { 1, 2 })
        {
            viewModel.MaintenanceTasks.Add(new MaintenanceTaskRow
            {
                Name = $"Sample managed renewal {index} — example.com（離線測試資料）",
                Schedule = "上次執行：2026-09-19 09:00:00　下次執行：2026-09-20 09:00:00",
                LastExecution = "上次工作排程結束碼 0；這不代表當次有換發憑證，仍需比對到期日及詳細紀錄。",
                Summary = "已啟用、SYSTEM、每日觸發、單一受控執行動作；較長的排程說明也必須維持可讀。"
            });
        }
        viewModel.ReplaceCheckResults([
            new PreflightCheckResult
            {
                Id = "sample-dns-confirmation", Phase = PreflightPhase.PublicEnvironment, Category = "DNS",
                Title = "DNS 指向人工確認：example.com", DomainName = "example.com", Status = CheckStatus.Warning,
                Summary = "主機位於 NAT 後方；公開位址與本機私有位址不同，已人工確認外部 TCP 80 會轉送到選取主機。",
                Remediation = "請確認 NAT／前端設備的轉送設定，並完成 Let's Encrypt Staging 外部驗證。",
                RequiresUserConfirmation = true
            },
            new PreflightCheckResult
            {
                Id = "sample-sni", Phase = PreflightPhase.ElevatedLocalEnvironment, Category = "IIS Binding",
                Title = "Port 443 Binding：example.com", DomainName = "example.com", Status = CheckStatus.Warning,
                Summary = "既有 Binding 已啟用 SNI，未使用 CCS；正式簽發將更新為新憑證。",
                Remediation = "正式申請前請核對網站、主機名稱與既有續期網域清單。",
                RequiresUserConfirmation = true
            },
            new PreflightCheckResult
            {
                Id = "sample-caa", Phase = PreflightPhase.PublicEnvironment, Category = "CAA",
                Title = "CAA 授權：example.com", DomainName = "example.com", Status = CheckStatus.Passed,
                Summary = "允許 Let's Encrypt 簽發，待 Staging 完成實際外部驗證。"
            }
        ]);
        viewModel.PublicPreflightPassed = true;
        viewModel.LocalPreflightPassed = true;
        viewModel.OverallStatus = "離線 XAML 排版檢查 — 未讀取 IIS、憑證或工作排程";
        viewModel.Logs.Clear();
        viewModel.AppendLog("資訊", "離線合成資料：尚未執行任何實際簽發或系統變更。");
        viewModel.AppendLog("警告", "範例到期提醒：shop.example.com 剩餘 25 天，請核對續期紀錄。");
    }

    private static void SelectTab(MainViewModel viewModel, TabControl tabs, int index)
    {
        viewModel.SelectedTabIndex = index;
        tabs.GetBindingExpression(TabControl.SelectedIndexProperty)?.UpdateTarget();
        if (tabs.SelectedIndex != index)
        {
            // No presentation source/dispatcher exists in this renderer. Set the
            // selection for layout without removing the production binding.
            tabs.SetCurrentValue(TabControl.SelectedIndexProperty, index);
        }
        Assert(tabs.SelectedIndex == index && BindingOperations.IsDataBound(tabs, TabControl.SelectedIndexProperty),
            "offline tab selection failed or removed the production binding");
    }

    private static void SameSiteRefreshKeepsGatesWithTwoWayComboBox()
    {
        var viewModel = new MainViewModel();
        var original = new IisSiteOptionViewModel { Id = "1", Name = "Original example.com site" };
        viewModel.ReplaceSites([original]);
        var combo = new ComboBox { DisplayMemberPath = nameof(IisSiteOptionViewModel.DisplayName) };
        combo.SetBinding(ItemsControl.ItemsSourceProperty, new Binding(nameof(MainViewModel.Sites))
        {
            Source = viewModel,
            Mode = BindingMode.OneWay
        });
        var selectedBinding = combo.SetBinding(ComboBox.SelectedItemProperty, new Binding(nameof(MainViewModel.SelectedSite))
        {
            Source = viewModel,
            Mode = BindingMode.TwoWay,
            UpdateSourceTrigger = UpdateSourceTrigger.PropertyChanged
        });
        combo.Measure(new Size(500, 80));
        combo.Arrange(new Rect(0, 0, 500, 80));
        combo.UpdateLayout();
        combo.GetBindingExpression(ComboBox.SelectedItemProperty)!.UpdateTarget();
        Assert(selectedBinding.Status == BindingStatus.Active && ReferenceEquals(combo.SelectedItem, original),
            "regression ComboBox does not have an active two-way selected-site binding");

        viewModel.PublicPreflightPassed = true;
        viewModel.LocalPreflightPassed = true;
        viewModel.StagingPassed = true;
        var sawTemporaryNull = false;
        viewModel.PropertyChanged += (_, args) =>
        {
            if (args.PropertyName == nameof(MainViewModel.SelectedSite) && viewModel.SelectedSite is null)
            {
                sawTemporaryNull = true;
            }
        };
        var refreshed = new IisSiteOptionViewModel { Id = "1", Name = "Renamed example.com site" };
        viewModel.ReplaceSites([refreshed]);
        combo.GetBindingExpression(ComboBox.SelectedItemProperty)!.UpdateTarget();
        Assert(sawTemporaryNull, "ComboBox refresh did not exercise the Collection.Clear transient null regression");
        Assert(ReferenceEquals(viewModel.SelectedSite, refreshed) && ReferenceEquals(combo.SelectedItem, refreshed),
            "same-ID refresh did not select the replacement site object");
        Assert(viewModel.LocalPreflightPassed && viewModel.StagingPassed,
            "same-ID refresh invalidated gates through a two-way ComboBox transient null");

        var different = new IisSiteOptionViewModel { Id = "2", Name = "Different example.com site" };
        viewModel.ReplaceSites([different]);
        combo.GetBindingExpression(ComboBox.SelectedItemProperty)!.UpdateTarget();
        Assert(ReferenceEquals(combo.SelectedItem, different) && ReferenceEquals(viewModel.SelectedSite, different),
            "different-ID refresh did not replace the selected site");
        Assert(!viewModel.LocalPreflightPassed && !viewModel.StagingPassed,
            "different-ID refresh incorrectly preserved local or staging gates");
        Assert(!combo.IsLoaded && PresentationSource.FromVisual(combo) is null,
            "ComboBox regression unexpectedly attached a presentation source");
    }

    private static void Render(FrameworkElement root, Size size, string path)
    {
        root.Measure(size);
        root.Arrange(new Rect(new Point(), size));
        root.UpdateLayout();
        Assert(root.IsMeasureValid && root.IsArrangeValid && root.ActualWidth > 0 && root.ActualHeight > 0,
            "offline XAML layout did not complete");
        var bitmap = new RenderTargetBitmap((int)size.Width, (int)size.Height, 96, 96, PixelFormats.Pbgra32);
        bitmap.Render(root);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bitmap));
        using var stream = File.Create(path);
        encoder.Save(stream);
    }

    private static IEnumerable<T> VisualChildren<T>(DependencyObject parent) where T : DependencyObject
    {
        for (var index = 0; index < VisualTreeHelper.GetChildrenCount(parent); index++)
        {
            var child = VisualTreeHelper.GetChild(parent, index);
            if (child is T match) yield return match;
            foreach (var descendant in VisualChildren<T>(child)) yield return descendant;
        }
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed class BindingErrorListener : TraceListener
    {
        private readonly StringBuilder _messages = new();
        public string Messages => _messages.ToString();
        public override void Write(string? message) => _messages.Append(message);
        public override void WriteLine(string? message) => _messages.AppendLine(message);
    }
}
