using System.Windows;
using Mstech.IisSslManager.Services;

namespace Mstech.IisSslManager;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        var isWorkerInvocation = e.Args.Length > 0 &&
            string.Equals(e.Args[0], ElevationService.WorkerSwitch, StringComparison.OrdinalIgnoreCase);
        DispatcherUnhandledException += (_, args) =>
        {
            if (!isWorkerInvocation)
            {
                MessageBox.Show(
                    $"程式發生未預期的錯誤：\n\n{args.Exception.Message}",
                    "MSTECH IIS SSL 自動更新工具",
                    MessageBoxButton.OK,
                    MessageBoxImage.Error);
            }

            args.Handled = true;
        };

        if (isWorkerInvocation)
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            if (!ElevationService.TryParseWorkerArguments(
                    e.Args,
                    out var requestPath,
                    out var resultPath,
                    out var requestSha256,
                    out var resultAuthenticationKey))
            {
                Shutdown(2);
                return;
            }

            ElevatedWorkerResult result;
            try
            {
                var request = await ElevationService.ReadWorkerRequestAsync(requestPath, requestSha256);
                result = await new ElevatedWorkerDispatcher().ExecuteAsync(request);
            }
            catch (Exception exception)
            {
                result = new ElevatedWorkerResult
                {
                    Success = false,
                    ExitCode = 1,
                    ErrorMessage = exception.Message
                };
            }

            try
            {
                await ElevationService.WriteWorkerResultAsync(
                    resultPath,
                    result,
                    resultAuthenticationKey);
                Shutdown(result.Success ? 0 : 1);
            }
            catch
            {
                Shutdown(3);
            }

            return;
        }

        var window = new MainWindow();
        MainWindow = window;
        window.Show();
    }
}
