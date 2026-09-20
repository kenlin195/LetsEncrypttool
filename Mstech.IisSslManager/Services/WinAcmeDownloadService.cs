using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Mstech.IisSslManager.Infrastructure;

namespace Mstech.IisSslManager.Services;

/// <summary>
/// Downloads exactly one tested win-acme release, verifies the pinned SHA-256,
/// extracts it with zip-slip/zip-bomb protections, and installs it atomically.
/// The caller must elevate before writing to ProgramData when required.
/// </summary>
public sealed class WinAcmeDownloadService
{
    private const long MaximumExtractedBytes = 200L * 1024 * 1024;
    private const int MaximumArchiveEntries = 2_048;
    private readonly HttpClient _httpClient;
    private readonly WinAcmeLocator _locator;

    public WinAcmeDownloadService(HttpClient httpClient, WinAcmeLocator? locator = null)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _locator = locator ?? new WinAcmeLocator();
    }

    public async Task<WinAcmeInstallationInfo> InstallRecommendedAsync(
        IProgress<WinAcmeDownloadProgress>? progress = null,
        CancellationToken cancellationToken = default)
    {
        _ = ProgramDataSecurity.EnsureToolRoot();
        var destination = Path.GetFullPath(WinAcmeRecommendedRelease.InstallDirectory);
        var executable = Path.Combine(destination, "wacs.exe");
        ProgramDataSecurity.ValidateNoReparse(destination, allowMissingLeaf: true);
        if (File.Exists(destination))
        {
            throw new IOException("win-acme 管理目錄路徑已被一般檔案占用。");
        }

        if (Directory.Exists(destination))
        {
            ApplyManagedDirectoryAcl(destination);
            ProgramDataSecurity.ValidateTreeNoReparse(destination);
        }

        if (File.Exists(executable))
        {
            ProgramDataSecurity.ValidateNoReparse(executable, allowMissingLeaf: false);
            var current = await _locator.InspectAsync(
                executable,
                WinAcmeLocationSource.ManagedInstallation,
                cancellationToken).ConfigureAwait(false);

            if (current.IntegrityVerified)
            {
                ApplyManagedDirectoryAcl(destination);
                ConfigureManagedSettings(destination);
                progress?.Report(new WinAcmeDownloadProgress
                {
                    Stage = "建議版本已安裝",
                    BytesReceived = WinAcmeRecommendedRelease.ArchiveSizeBytes,
                    TotalBytes = WinAcmeRecommendedRelease.ArchiveSizeBytes
                });
                return current;
            }

            throw new InvalidOperationException(
                "管理目錄已有不同的 wacs.exe。為避免覆寫既有設定，請先由管理員移走該目錄，或改用『選擇現有 wacs.exe』。");
        }

        if (Directory.Exists(destination) && Directory.EnumerateFileSystemEntries(destination).Any())
        {
            throw new InvalidOperationException(
                "win-acme 管理目錄不是空的。工具不會自動覆寫或刪除現有資料。請由管理員確認後再處理。");
        }

        Directory.CreateDirectory(AppPaths.TemporaryDirectory);
        var archivePath = Path.Combine(
            AppPaths.TemporaryDirectory,
            $"win-acme-{Guid.NewGuid():N}.zip.partial");
        var parent = Directory.GetParent(destination)?.FullName
            ?? throw new InvalidOperationException("無法判斷 win-acme 安裝目錄的父目錄。");
        var stagingDirectory = destination + $".install-{Guid.NewGuid():N}";

        try
        {
            await DownloadArchiveAsync(archivePath, progress, cancellationToken).ConfigureAwait(false);

            progress?.Report(new WinAcmeDownloadProgress
            {
                Stage = "驗證 SHA-256",
                BytesReceived = WinAcmeRecommendedRelease.ArchiveSizeBytes,
                TotalBytes = WinAcmeRecommendedRelease.ArchiveSizeBytes
            });

            var archiveHash = await WinAcmeLocator.ComputeSha256Async(
                archivePath,
                cancellationToken).ConfigureAwait(false);
            if (!string.Equals(
                    archiveHash,
                    WinAcmeRecommendedRelease.ArchiveSha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException(
                    $"win-acme 下載檔 SHA-256 不符。預期 {WinAcmeRecommendedRelease.ArchiveSha256}，實際 {archiveHash}。檔案不會安裝。");
            }

            ProgramDataSecurity.ValidateNoReparse(parent, allowMissingLeaf: false);
            ApplyManagedDirectoryAcl(stagingDirectory);
            await ExtractSafelyAsync(archivePath, stagingDirectory, progress, cancellationToken)
                .ConfigureAwait(false);

            var stagedExecutable = Path.Combine(stagingDirectory, "wacs.exe");
            ProgramDataSecurity.ValidateNoReparse(stagedExecutable, allowMissingLeaf: false);
            if (!File.Exists(stagedExecutable))
            {
                throw new InvalidDataException("官方壓縮檔中找不到 wacs.exe。");
            }

            var executableHash = await WinAcmeLocator.ComputeSha256Async(
                stagedExecutable,
                cancellationToken).ConfigureAwait(false);
            if (!string.Equals(
                    executableHash,
                    WinAcmeRecommendedRelease.ExecutableSha256,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("解壓縮後的 wacs.exe 雜湊不符，檔案不會安裝。");
            }

            ConfigureManagedSettings(stagingDirectory);

            await WriteInstallReceiptAsync(
                stagingDirectory,
                archiveHash,
                executableHash,
                cancellationToken).ConfigureAwait(false);

            if (Directory.Exists(destination))
            {
                // Only an empty directory may reach this point; no user file is removed.
                ProgramDataSecurity.ValidateTreeNoReparse(destination);
                Directory.Delete(destination, recursive: false);
            }

            ProgramDataSecurity.ValidateTreeNoReparse(stagingDirectory);
            ProgramDataSecurity.ValidateNoReparse(destination, allowMissingLeaf: true);
            Directory.Move(stagingDirectory, destination);
            ApplyManagedDirectoryAcl(destination);
            ProgramDataSecurity.ValidateTreeNoReparse(destination);

            progress?.Report(new WinAcmeDownloadProgress
            {
                Stage = "安裝完成",
                BytesReceived = WinAcmeRecommendedRelease.ArchiveSizeBytes,
                TotalBytes = WinAcmeRecommendedRelease.ArchiveSizeBytes
            });

            return await _locator.InspectAsync(
                executable,
                WinAcmeLocationSource.ManagedInstallation,
                cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            TryDeleteFile(archivePath);
            TryDeleteOwnedStagingDirectory(stagingDirectory, destination);
        }
    }

    private async Task DownloadArchiveAsync(
        string archivePath,
        IProgress<WinAcmeDownloadProgress>? progress,
        CancellationToken cancellationToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, WinAcmeRecommendedRelease.DownloadUri);
        request.Headers.UserAgent.ParseAdd($"MSTECH-IisSslManager/{AppVersion.SemanticVersion}");

        using var response = await _httpClient.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken).ConfigureAwait(false);
        response.EnsureSuccessStatusCode();

        var finalUri = response.RequestMessage?.RequestUri;
        if (finalUri is null || !string.Equals(finalUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidDataException("win-acme 下載被重新導向到非 HTTPS 位置，已拒絕下載。");
        }

        var contentLength = response.Content.Headers.ContentLength;
        if (contentLength is > 50L * 1024 * 1024)
        {
            throw new InvalidDataException("win-acme 下載大小異常，已拒絕下載。");
        }

        await using var input = await response.Content.ReadAsStreamAsync(cancellationToken)
            .ConfigureAwait(false);
        await using var output = new FileStream(
            archivePath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.WriteThrough);

        var buffer = new byte[128 * 1024];
        long total = 0;
        while (true)
        {
            var read = await input.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            total += read;
            if (total > 50L * 1024 * 1024)
            {
                throw new InvalidDataException("win-acme 下載大小異常，已中止下載。");
            }

            await output.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            progress?.Report(new WinAcmeDownloadProgress
            {
                Stage = "下載官方 win-acme",
                BytesReceived = total,
                TotalBytes = contentLength ?? WinAcmeRecommendedRelease.ArchiveSizeBytes
            });
        }

        await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        if (total != WinAcmeRecommendedRelease.ArchiveSizeBytes)
        {
            throw new InvalidDataException(
                $"win-acme 下載大小不符。預期 {WinAcmeRecommendedRelease.ArchiveSizeBytes:N0} bytes，實際 {total:N0} bytes。");
        }
    }

    private static async Task ExtractSafelyAsync(
        string archivePath,
        string destination,
        IProgress<WinAcmeDownloadProgress>? progress,
        CancellationToken cancellationToken)
    {
        ProgramDataSecurity.ValidateTreeNoReparse(destination);
        await using var input = File.OpenRead(archivePath);
        using var archive = new ZipArchive(input, ZipArchiveMode.Read, leaveOpen: false);
        if (archive.Entries.Count > MaximumArchiveEntries)
        {
            throw new InvalidDataException("win-acme 壓縮檔包含異常數量的項目。");
        }

        var root = Path.GetFullPath(destination)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) +
            Path.DirectorySeparatorChar;
        long extractedBytes = 0;

        foreach (var entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            RejectSymbolicLink(entry);

            if (entry.Length < 0 || entry.Length > MaximumExtractedBytes - extractedBytes)
            {
                throw new InvalidDataException("win-acme 壓縮檔解壓縮大小異常。");
            }

            extractedBytes += entry.Length;
            var outputPath = Path.GetFullPath(Path.Combine(destination, entry.FullName));
            if (!outputPath.StartsWith(root, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException($"win-acme 壓縮檔包含不安全路徑：{entry.FullName}");
            }

            if (string.IsNullOrEmpty(entry.Name))
            {
                ProgramDataSecurity.EnsureDirectory(
                    outputPath,
                    ProgramDataAccess.UsersReadAndExecute);
                continue;
            }

            var outputDirectory = Path.GetDirectoryName(outputPath)
                ?? throw new InvalidDataException("壓縮檔項目沒有有效目錄。");
            ProgramDataSecurity.EnsureDirectory(
                outputDirectory,
                ProgramDataAccess.UsersReadAndExecute);
            ProgramDataSecurity.ValidateNoReparse(outputPath, allowMissingLeaf: true);

            await using var entryStream = entry.Open();
            await using var output = new FileStream(
                outputPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            await entryStream.CopyToAsync(output, cancellationToken).ConfigureAwait(false);

            progress?.Report(new WinAcmeDownloadProgress
            {
                Stage = "安全解壓縮",
                BytesReceived = extractedBytes,
                TotalBytes = Math.Max(extractedBytes, archive.Entries.Sum(item => Math.Max(0L, item.Length)))
            });
        }

        ProgramDataSecurity.ValidateTreeNoReparse(destination);
    }

    private static void RejectSymbolicLink(ZipArchiveEntry entry)
    {
        // Upper 16 bits carry Unix mode when the archive was made on Unix.
        const int unixFileTypeMask = 0xF000;
        const int unixSymbolicLink = 0xA000;
        var unixMode = (entry.ExternalAttributes >> 16) & unixFileTypeMask;
        if (unixMode == unixSymbolicLink)
        {
            throw new InvalidDataException($"win-acme 壓縮檔包含不允許的符號連結：{entry.FullName}");
        }
    }

    internal static void ConfigureManagedSettings(string stagingDirectory)
    {
        var managedDirectory = ProgramDataSecurity.EnsureDirectory(
            stagingDirectory,
            ProgramDataAccess.UsersReadAndExecute);
        ProgramDataSecurity.ValidateTreeNoReparse(managedDirectory);
        var defaultPath = ProgramDataSecurity.ValidateNoReparse(
            Path.Combine(managedDirectory, "settings_default.json"),
            allowMissingLeaf: false);
        var managedPath = ProgramDataSecurity.ValidateNoReparse(
            Path.Combine(managedDirectory, "settings.json"),
            allowMissingLeaf: true);
        if (!File.Exists(defaultPath))
        {
            throw new InvalidDataException("官方 win-acme 套件缺少 settings_default.json。");
        }

        // The managed copy is deliberately regenerated from the pinned release
        // defaults instead of preserving an arbitrary settings.json. win-acme can
        // execute pre/post scripts and can redirect ACME traffic through settings,
        // so formal operations must not inherit user-controlled configuration.
        var root = JsonNode.Parse(
            File.ReadAllText(defaultPath),
            documentOptions: new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 64
            }) as JsonObject ?? throw new InvalidDataException("win-acme 預設設定格式錯誤。");
        var client = root["Client"] as JsonObject
            ?? throw new InvalidDataException("win-acme 預設設定缺少 Client 區段。");
        client["ClientName"] = WinAcmeRecommendedRelease.ManagedClientName;
        client["ConfigurationPath"] = AppPaths.WinAcmeConfigurationDirectory;
        client["LogPath"] = AppPaths.WinAcmeLogDirectory;
        client["VersionCheck"] = false;

        var acme = root["Acme"] as JsonObject
            ?? throw new InvalidDataException("win-acme 預設設定缺少 Acme 區段。");
        acme["DefaultBaseUri"] = WinAcmeRecommendedRelease.ProductionBaseUri;
        acme["DefaultBaseUriTest"] = WinAcmeRecommendedRelease.StagingBaseUri;
        acme["ValidateServerCertificate"] = true;

        var execution = root["Execution"] as JsonObject
            ?? throw new InvalidDataException("win-acme 預設設定缺少 Execution 區段。");
        execution["DefaultPreExecutionScript"] = null;
        execution["DefaultPostExecutionScript"] = null;

        var proxy = root["Proxy"] as JsonObject
            ?? throw new InvalidDataException("win-acme 預設設定缺少 Proxy 區段。");
        proxy["Url"] = "[System]";
        proxy["UserName"] = null;
        proxy["Password"] = null;

        var csr = root["Csr"] as JsonObject
            ?? throw new InvalidDataException("win-acme 預設設定缺少 Csr 區段。");
        var rsa = csr["Rsa"] as JsonObject
            ?? throw new InvalidDataException("win-acme 預設設定缺少 Csr.Rsa 區段。");
        rsa["KeyBits"] = 2048;

        // Keep win-acme's own cache cleanup disabled. The renewal definition uses
        // --keepexisting and the application-owned script removes only an old,
        // unbound certificate after the 30-day retention window.
        if (root["Cache"] is JsonObject cache)
        {
            cache["Path"] = AppPaths.WinAcmeCacheDirectory;
            // Never reuse an order/certificate from an interrupted formal run.
            // The post-issuance verifier can still safely accept a previously
            // installed certificate when every requested IIS binding proves that
            // exact thumbprint, store and SNI state.
            cache["ReuseDays"] = 0;
            cache["DeleteStaleFiles"] = false;
        }

        if (root["Security"] is JsonObject security)
        {
            security["EncryptConfig"] = true;
        }

        if (root["Script"] is JsonObject script)
        {
            script["PowershellExecutablePath"] = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                "WindowsPowerShell",
                "v1.0",
                "powershell.exe");
        }

        if (root["Source"] is JsonObject source)
        {
            source["DefaultSource"] = "manual";
        }

        if (root["Secrets"] is JsonObject secrets && secrets["Json"] is JsonObject jsonSecrets)
        {
            jsonSecrets["FilePath"] = AppPaths.WinAcmeSecretsFile;
        }

        EnsurePrivateStateDirectories();

        var temporaryPath = Path.Combine(
            managedDirectory,
            $".settings-{Guid.NewGuid():N}.tmp");
        try
        {
            var bytes = Encoding.UTF8.GetBytes(
                root.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
            using (var output = new FileStream(
                       temporaryPath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       64 * 1024,
                       FileOptions.WriteThrough))
            {
                output.Write(bytes);
                output.Flush(flushToDisk: true);
            }

            ProgramDataSecurity.ReplaceFileAtomically(
                temporaryPath,
                managedPath,
                ProgramDataAccess.UsersReadAndExecute);
        }
        finally
        {
            TryDeleteControlledFile(temporaryPath);
        }
    }

    internal static void ApplyManagedDirectoryAcl(string path) =>
        ProgramDataSecurity.EnsureDirectory(path, ProgramDataAccess.UsersReadAndExecute);

    private static void EnsurePrivateStateDirectories()
    {
        foreach (var path in new[]
                 {
                     AppPaths.WinAcmeStateDirectory,
                     AppPaths.WinAcmeConfigurationDirectory,
                     AppPaths.WinAcmeCacheDirectory,
                     AppPaths.WinAcmeLogDirectory
                 })
        {
            ApplyPrivateDirectoryAcl(path);
        }

        ProgramDataSecurity.ValidateTreeNoReparse(AppPaths.WinAcmeStateDirectory);
        ProgramDataSecurity.ApplyTreeAcl(
            AppPaths.WinAcmeStateDirectory,
            ProgramDataAccess.MachinePrivate);
    }

    internal static void ApplyPrivateDirectoryAcl(string path) =>
        ProgramDataSecurity.EnsureDirectory(path, ProgramDataAccess.MachinePrivate);

    private static async Task WriteInstallReceiptAsync(
        string directory,
        string archiveHash,
        string executableHash,
        CancellationToken cancellationToken)
    {
        var receipt = new
        {
            Version = WinAcmeRecommendedRelease.Version,
            Source = WinAcmeRecommendedRelease.DownloadUri.AbsoluteUri,
            ArchiveSha256 = archiveHash,
            ExecutableSha256 = executableHash,
            InstalledAtUtc = DateTimeOffset.UtcNow
        };

        var path = ProgramDataSecurity.ValidateNoReparse(
            Path.Combine(directory, "mstech-install-receipt.json"),
            allowMissingLeaf: true);
        var json = JsonSerializer.Serialize(receipt, new JsonSerializerOptions { WriteIndented = true });
        var bytes = Encoding.UTF8.GetBytes(json);
        await using (var output = new FileStream(
                         path,
                         FileMode.CreateNew,
                         FileAccess.Write,
                         FileShare.None,
                         64 * 1024,
                         FileOptions.Asynchronous | FileOptions.WriteThrough))
        {
            await output.WriteAsync(bytes, cancellationToken).ConfigureAwait(false);
            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        ProgramDataSecurity.ApplyFileAcl(path, ProgramDataAccess.UsersReadAndExecute);
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch
        {
            // A .partial file contains no credential and can be removed by normal
            // temporary-file maintenance if another process still holds it.
        }
    }

    private static void TryDeleteControlledFile(string path)
    {
        try
        {
            if (!File.Exists(path) && !Directory.Exists(path))
            {
                return;
            }

            var actual = ProgramDataSecurity.ValidateNoReparse(path, allowMissingLeaf: false);
            if (Directory.Exists(actual))
            {
                return;
            }

            File.Delete(actual);
        }
        catch
        {
            // The random file is under a protected directory and contains no
            // credential. Leave it for administrator inspection if safety cannot
            // be proven instead of following or deleting an attacker-controlled path.
        }
    }

    private static void TryDeleteOwnedStagingDirectory(string stagingDirectory, string destination)
    {
        try
        {
            var expectedPrefix = Path.GetFullPath(destination) + ".install-";
            var actual = Path.GetFullPath(stagingDirectory);
            if (actual.StartsWith(expectedPrefix, StringComparison.OrdinalIgnoreCase) &&
                actual.Length == expectedPrefix.Length + 32 &&
                Guid.TryParseExact(actual[expectedPrefix.Length..], "N", out _) &&
                Directory.Exists(actual))
            {
                ProgramDataSecurity.ValidateTreeNoReparse(actual);
                Directory.Delete(actual, recursive: true);
            }
        }
        catch
        {
            // Never hide the original installation error because cleanup failed.
        }
    }
}
