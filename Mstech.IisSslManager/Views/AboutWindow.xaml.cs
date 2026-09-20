using System.Diagnostics;
using System.Windows;
using System.Windows.Documents;
using Mstech.IisSslManager.Infrastructure;

namespace Mstech.IisSslManager.Views;

public partial class AboutWindow : Window
{
    public string VersionText { get; }

    public AboutWindow()
    {
        VersionText = AppVersion.DisplayVersion;

        InitializeComponent();
        DataContext = this;
    }

    private void EmailHyperlink_OnClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Hyperlink)
        {
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "mailto:service@mstech.tw",
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"無法開啟預設郵件程式：\n{ex.Message}", "開啟失敗", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}
