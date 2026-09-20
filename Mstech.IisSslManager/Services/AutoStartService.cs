using System.IO;
using Microsoft.Win32;

namespace Mstech.IisSslManager.Services;

public sealed record AutoStartStatus
{
    public bool IsEnabled { get; init; }

    public bool MatchesCurrentExecutable { get; init; }

    public string? RegisteredCommand { get; init; }

    public string? ErrorMessage { get; init; }
}

/// <summary>
/// Controls login startup for the current Windows user only. Background
/// certificate renewal is a separate win-acme SYSTEM scheduled task and does not
/// depend on this GUI being open.
/// </summary>
public sealed class AutoStartService
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "MSTECH.IisSslManager";
    private const string AutoStartArgument = "--autostart";

    public AutoStartStatus GetStatus(string? executablePath = null)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new AutoStartStatus { ErrorMessage = "自動啟動僅支援 Windows。" };
        }

        try
        {
            using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: false);
            var command = key?.GetValue(ValueName, null, RegistryValueOptions.DoNotExpandEnvironmentNames)
                as string;
            if (string.IsNullOrWhiteSpace(command))
            {
                return new AutoStartStatus();
            }

            var expected = BuildCommand(executablePath ?? GetCurrentExecutablePath());
            return new AutoStartStatus
            {
                IsEnabled = true,
                MatchesCurrentExecutable = string.Equals(
                    command.Trim(),
                    expected,
                    StringComparison.OrdinalIgnoreCase),
                RegisteredCommand = command
            };
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException or IOException or System.Security.SecurityException)
        {
            return new AutoStartStatus { ErrorMessage = exception.Message };
        }
    }

    public AutoStartStatus SetEnabled(bool enabled, string? executablePath = null)
    {
        if (!OperatingSystem.IsWindows())
        {
            return new AutoStartStatus { ErrorMessage = "自動啟動僅支援 Windows。" };
        }

        try
        {
            using var key = Registry.CurrentUser.CreateSubKey(RunKeyPath, writable: true)
                ?? throw new InvalidOperationException("無法開啟目前使用者的自動啟動登錄位置。");

            if (enabled)
            {
                var command = BuildCommand(executablePath ?? GetCurrentExecutablePath());
                key.SetValue(ValueName, command, RegistryValueKind.String);
            }
            else
            {
                // Delete only the value owned by this application. Never modify other
                // login startup entries.
                key.DeleteValue(ValueName, throwOnMissingValue: false);
            }

            return GetStatus(executablePath);
        }
        catch (Exception exception) when (
            exception is UnauthorizedAccessException or IOException or
            System.Security.SecurityException or InvalidOperationException or ArgumentException)
        {
            return new AutoStartStatus { ErrorMessage = exception.Message };
        }
    }

    private static string BuildCommand(string executablePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        var fullPath = Path.GetFullPath(executablePath.Trim().Trim('"'));
        if (!string.Equals(Path.GetExtension(fullPath), ".exe", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("自動啟動目標必須是 .exe。", nameof(executablePath));
        }

        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException("找不到自動啟動程式。", fullPath);
        }

        // Windows paths cannot contain a quote. Quoting prevents spaces from
        // changing the executable selected by the Run key parser.
        return $"\"{fullPath}\" {AutoStartArgument}";
    }

    private static string GetCurrentExecutablePath() =>
        Environment.ProcessPath ??
        throw new InvalidOperationException("無法判斷目前程式執行檔路徑。");
}
