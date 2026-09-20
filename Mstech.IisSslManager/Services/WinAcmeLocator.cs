using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using Mstech.IisSslManager.Infrastructure;

namespace Mstech.IisSslManager.Services;

/// <summary>
/// Finds win-acme installations without executing them. A user-selected copy is
/// allowed, but only the pinned executable hash is marked as integrity verified.
/// </summary>
public sealed class WinAcmeLocator
{
    private readonly string _applicationDirectory;

    public WinAcmeLocator(string? applicationDirectory = null)
    {
        _applicationDirectory = Path.GetFullPath(
            applicationDirectory ?? AppContext.BaseDirectory);
    }

    public async Task<IReadOnlyList<WinAcmeInstallationInfo>> DiscoverAsync(
        string? configuredPath = null,
        CancellationToken cancellationToken = default)
    {
        var candidates = GetCandidates(configuredPath);
        var installations = new List<WinAcmeInstallationInfo>(candidates.Count);

        foreach (var candidate in candidates)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!File.Exists(candidate.Path))
            {
                continue;
            }

            installations.Add(await InspectAsync(
                candidate.Path,
                candidate.Source,
                cancellationToken).ConfigureAwait(false));
        }

        return installations;
    }

    public Task<WinAcmeInstallationInfo> InspectSelectedAsync(
        string executablePath,
        CancellationToken cancellationToken = default) =>
        InspectAsync(executablePath, WinAcmeLocationSource.UserSelected, cancellationToken);

    public async Task<WinAcmeInstallationInfo> InspectAsync(
        string executablePath,
        WinAcmeLocationSource source,
        CancellationToken cancellationToken = default)
    {
        var normalizedPath = NormalizeExecutablePath(executablePath);
        if (!File.Exists(normalizedPath))
        {
            return new WinAcmeInstallationInfo
            {
                ExecutablePath = normalizedPath,
                Source = source,
                Exists = false,
                StatusMessage = "找不到 wacs.exe。"
            };
        }

        string? fileVersion = null;
        string? productVersion = null;
        try
        {
            var versionInfo = FileVersionInfo.GetVersionInfo(normalizedPath);
            fileVersion = versionInfo.FileVersion;
            productVersion = versionInfo.ProductVersion;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return new WinAcmeInstallationInfo
            {
                ExecutablePath = normalizedPath,
                Source = source,
                Exists = true,
                StatusMessage = $"無法讀取 win-acme 版本：{exception.Message}"
            };
        }

        var hash = await ComputeSha256Async(normalizedPath, cancellationToken).ConfigureAwait(false);
        var verified = string.Equals(
            hash,
            WinAcmeRecommendedRelease.ExecutableSha256,
            StringComparison.OrdinalIgnoreCase);

        var status = verified
            ? "已驗證為本工具測試過的官方 win-acme 版本。"
            : string.Equals(fileVersion, WinAcmeRecommendedRelease.Version, StringComparison.OrdinalIgnoreCase)
                ? "版本號相符，但檔案雜湊不同；可能是其他發行套件，請由管理員確認來源。"
                : $"偵測到 win-acme {fileVersion ?? "未知版本"}；不是本工具固定測試版本。";

        return new WinAcmeInstallationInfo
        {
            ExecutablePath = normalizedPath,
            Source = source,
            Exists = true,
            FileVersion = fileVersion,
            ProductVersion = productVersion,
            Sha256 = hash,
            IntegrityVerified = verified,
            StatusMessage = status
        };
    }

    public static string NormalizeExecutablePath(string executablePath)
    {
        if (string.IsNullOrWhiteSpace(executablePath))
        {
            throw new ArgumentException("wacs.exe 路徑不可為空白。", nameof(executablePath));
        }

        var fullPath = Path.GetFullPath(
            Environment.ExpandEnvironmentVariables(executablePath.Trim().Trim('"')));

        if (!string.Equals(Path.GetFileName(fullPath), "wacs.exe", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("請選擇 win-acme 的 wacs.exe。", nameof(executablePath));
        }

        return fullPath;
    }

    private List<(string Path, WinAcmeLocationSource Source)> GetCandidates(string? configuredPath)
    {
        var candidates = new List<(string Path, WinAcmeLocationSource Source)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string? path, WinAcmeLocationSource source)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            try
            {
                var normalized = NormalizeExecutablePath(path);
                if (seen.Add(normalized))
                {
                    candidates.Add((normalized, source));
                }
            }
            catch (ArgumentException)
            {
                // Invalid discovery candidates are ignored. A directly selected path is
                // instead validated by InspectSelectedAsync and reports the problem.
            }
        }

        Add(configuredPath, WinAcmeLocationSource.Configured);
        Add(AppPaths.WinAcmeExecutable, WinAcmeLocationSource.ManagedInstallation);
        Add(Path.Combine(_applicationDirectory, "win-acme", "wacs.exe"),
            WinAcmeLocationSource.ApplicationDirectory);
        Add(Path.Combine(_applicationDirectory, "wacs.exe"),
            WinAcmeLocationSource.ApplicationDirectory);

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        if (!string.IsNullOrWhiteSpace(programFiles))
        {
            Add(Path.Combine(programFiles, "win-acme", "wacs.exe"),
                WinAcmeLocationSource.ProgramFiles);
        }

        var systemRoot = Path.GetPathRoot(Environment.SystemDirectory);
        if (!string.IsNullOrWhiteSpace(systemRoot))
        {
            Add(Path.Combine(systemRoot, "win-acme", "wacs.exe"),
                WinAcmeLocationSource.ConventionalDirectory);
        }

        var pathValue = Environment.GetEnvironmentVariable("PATH");
        if (!string.IsNullOrWhiteSpace(pathValue))
        {
            foreach (var directory in pathValue.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = directory.Trim().Trim('"');
                if (!string.IsNullOrWhiteSpace(trimmed))
                {
                    Add(Path.Combine(trimmed, "wacs.exe"), WinAcmeLocationSource.PathEnvironment);
                }
            }
        }

        return candidates;
    }

    internal static async Task<string> ComputeSha256Async(
        string filePath,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            filePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            128 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);

        var hash = await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false);
        return Convert.ToHexString(hash);
    }
}
