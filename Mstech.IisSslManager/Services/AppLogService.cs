using System.Diagnostics;
using System.Text;
using Mstech.IisSslManager.Infrastructure;

namespace Mstech.IisSslManager.Services;

public enum AppLogLevel
{
    Information,
    Warning,
    Error
}

public sealed class AppLogService
{
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    public event EventHandler<string>? EntryWritten;

    public async Task WriteAsync(
        AppLogLevel level,
        string message,
        Exception? exception = null,
        CancellationToken cancellationToken = default)
    {
        var normalized = message.ReplaceLineEndings(" ").Trim();
        var line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz} [{level}] {normalized}";
        if (exception is not null)
        {
            line += $" | {exception.GetType().Name}: {exception.Message.ReplaceLineEndings(" ")}";
        }

        await _writeLock.WaitAsync(cancellationToken);
        try
        {
            Directory.CreateDirectory(AppPaths.LogsDirectory);
            var logFile = Path.Combine(AppPaths.LogsDirectory, $"iis-ssl-manager-{DateTime.Today:yyyyMMdd}.log");
            await File.AppendAllTextAsync(logFile, line + Environment.NewLine, new UTF8Encoding(false), cancellationToken);
        }
        finally
        {
            _writeLock.Release();
        }

        EntryWritten?.Invoke(this, line);

        if (level is AppLogLevel.Warning or AppLogLevel.Error)
        {
            TryWriteWindowsEvent(level, normalized);
        }
    }

    private static void TryWriteWindowsEvent(AppLogLevel level, string message)
    {
        try
        {
            var type = level == AppLogLevel.Error ? "ERROR" : "WARNING";
            var safeMessage = message.Length > 3000 ? message[..3000] : message;
            safeMessage = safeMessage.Replace('"', '\'');

            var startInfo = new ProcessStartInfo
            {
                FileName = Path.Combine(Environment.SystemDirectory, "eventcreate.exe"),
                UseShellExecute = false,
                CreateNoWindow = true
            };
            startInfo.ArgumentList.Add("/L");
            startInfo.ArgumentList.Add("APPLICATION");
            startInfo.ArgumentList.Add("/T");
            startInfo.ArgumentList.Add(type);
            startInfo.ArgumentList.Add("/SO");
            startInfo.ArgumentList.Add("MSTECH IIS SSL Manager");
            startInfo.ArgumentList.Add("/ID");
            startInfo.ArgumentList.Add("100");
            startInfo.ArgumentList.Add("/D");
            startInfo.ArgumentList.Add(safeMessage);
            Process.Start(startInfo)?.WaitForExit(3000);
        }
        catch
        {
            // File logging remains the authoritative fallback when Event Log access is unavailable.
        }
    }
}
