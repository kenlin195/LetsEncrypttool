using System.Reflection;
using Mstech.IisSslManager.Infrastructure;

namespace Mstech.IisSslManager.Services;

/// <summary>
/// Installs the application-owned post-renewal script in ProgramData. win-acme
/// calls it after successful renewals to queue safe removal of the previous,
/// unbound WebHosting certificate after the configured retention period.
/// </summary>
public sealed class CertificateRetentionService
{
    public const int RetentionDays = 30;
    private const string ResourceSuffix = ".Scripts.CertificateRetention.ps1";

    public string Deploy()
    {
        var directory = ProgramDataSecurity.EnsureDirectory(
            Path.Combine(AppPaths.ProgramDataRoot, "Scripts"),
            ProgramDataAccess.UsersReadAndExecute);
        ProgramDataSecurity.ValidateTreeNoReparse(directory);
        var destination = ProgramDataSecurity.ValidateNoReparse(
            Path.Combine(directory, "CertificateRetention.ps1"),
            allowMissingLeaf: true);
        if (Directory.Exists(destination))
        {
            throw new IOException("憑證保留腳本目的地被目錄占用，已拒絕部署。");
        }

        var assembly = Assembly.GetExecutingAssembly();
        var resourceName = assembly.GetManifestResourceNames()
            .SingleOrDefault(name => name.EndsWith(ResourceSuffix, StringComparison.Ordinal))
            ?? throw new InvalidOperationException("找不到內嵌的憑證保留腳本。");
        using var input = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException("無法讀取內嵌的憑證保留腳本。");

        // Windows PowerShell 5.1 treats UTF-8 text without a BOM as the active
        // ANSI code page. The script contains Traditional Chinese diagnostics,
        // so always deploy it as UTF-8 with exactly one BOM.
        using var resourceBuffer = new MemoryStream();
        input.CopyTo(resourceBuffer);
        var scriptBytes = resourceBuffer.ToArray();
        var utf8Preamble = System.Text.Encoding.UTF8.GetPreamble();
        var sourceOffset = scriptBytes.AsSpan().StartsWith(utf8Preamble)
            ? utf8Preamble.Length
            : 0;

        var temporary = Path.Combine(
            directory,
            $".CertificateRetention-{Guid.NewGuid():N}.tmp");
        try
        {
            using (var output = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       64 * 1024,
                       FileOptions.WriteThrough))
            {
                output.Write(utf8Preamble);
                output.Write(scriptBytes, sourceOffset, scriptBytes.Length - sourceOffset);
                output.Flush(flushToDisk: true);
            }

            ProgramDataSecurity.ApplyFileAcl(
                temporary,
                ProgramDataAccess.UsersReadAndExecute);
            ProgramDataSecurity.ValidateTreeNoReparse(directory);

            // This is a same-directory atomic rename, not a write through the
            // destination handle. If an old destination has other hard links,
            // those names retain the old bytes and are never modified.
            ProgramDataSecurity.ReplaceFileAtomically(
                temporary,
                destination,
                ProgramDataAccess.UsersReadAndExecute);
            ProgramDataSecurity.ValidateTreeNoReparse(directory);
            return destination;
        }
        finally
        {
            try
            {
                if (File.Exists(temporary))
                {
                    var controlledTemporary = ProgramDataSecurity.ValidateNoReparse(
                        temporary,
                        allowMissingLeaf: false);
                    File.Delete(controlledTemporary);
                }
            }
            catch
            {
                // Do not hide the deployment result because antivirus briefly kept
                // the application-owned temporary file open.
            }
        }
    }
}
