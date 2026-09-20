using System.Security.Principal;

namespace Mstech.IisSslManager.Infrastructure;

public static class AppPaths
{
    public const string VendorName = "MSTECH";
    public const string ProductFolderName = "IisSslManager";

    public static string ProgramDataRoot { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        $"{VendorName}-{ProductFolderName}");

    public static string UserDataRoot { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        VendorName,
        ProductFolderName);

    public static string SettingsFile => Path.Combine(GetWritableDataRoot(), "settings.json");

    public static string LogsDirectory => Path.Combine(GetWritableDataRoot(), "Logs");

    public static string WinAcmeDirectory => Path.Combine(ProgramDataRoot, "win-acme");

    public static string WinAcmeExecutable => Path.Combine(WinAcmeDirectory, "wacs.exe");

    public static string WinAcmeStateDirectory => Path.Combine(ProgramDataRoot, "win-acme-state");

    public static string WinAcmeConfigurationDirectory => Path.Combine(WinAcmeStateDirectory, "Configuration");

    public static string WinAcmeCacheDirectory => Path.Combine(WinAcmeStateDirectory, "Cache");

    public static string WinAcmeLogDirectory => Path.Combine(WinAcmeStateDirectory, "Logs");

    public static string WinAcmeSecretsFile => Path.Combine(WinAcmeStateDirectory, "secrets.json");

    public static string TemporaryDirectory => Path.Combine(Path.GetTempPath(), VendorName, ProductFolderName);

    public static string SecureTemporaryDirectory => Path.Combine(ProgramDataRoot, "Temporary");

    public static string SecureStagingDirectory => Path.Combine(SecureTemporaryDirectory, "Staging");

    // Keep the pre-UAC exchange outside the privileged product root. A standard
    // user must create its private GUID child before Windows can start the worker
    // under an over-the-shoulder administrator account.
    public static string ElevationExchangeDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        $"{VendorName}-{ProductFolderName}-Elevation");

    public static string GetWritableDataRoot()
    {
        // A medium-integrity process may have CreateDirectories on ProgramData.
        // Never let ordinary GUI startup pre-create the future privileged root as
        // a user-owned directory; use LocalAppData until the process is elevated.
        if (IsCurrentProcessAdministrator())
        {
            try
            {
                var securedRoot = ProgramDataSecurity.EnsureToolRoot();
                if (TryEnsureDirectory(securedRoot))
                {
                    return securedRoot;
                }
            }
            catch (Exception exception) when (
                exception is IOException or UnauthorizedAccessException or
                InvalidOperationException or System.ComponentModel.Win32Exception)
            {
                // Interface settings and ordinary logs are allowed to fall back;
                // privileged win-acme/state/script writers fail closed separately.
            }
        }

        Directory.CreateDirectory(UserDataRoot);
        return UserDataRoot;
    }

    public static bool TryEnsureDirectory(string path)
    {
        try
        {
            Directory.CreateDirectory(path);
            var probe = Path.Combine(path, $".write-probe-{Guid.NewGuid():N}");
            using (File.Create(probe, 1, FileOptions.DeleteOnClose))
            {
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool IsCurrentProcessAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
