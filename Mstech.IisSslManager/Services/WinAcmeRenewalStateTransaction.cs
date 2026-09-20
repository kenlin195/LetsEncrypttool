using System.Security.Cryptography;
using System.Text.Json;
using Mstech.IisSslManager.Infrastructure;

namespace Mstech.IisSslManager.Services;

public sealed record WinAcmeRenewalStateRestoreResult
{
    public required bool Success { get; init; }

    public required string Summary { get; init; }
}

/// <summary>
/// Captures and restores only the deterministic production renewal owned by the
/// selected IIS site. The pinned win-acme 2.2.9.1701 source writes a renewal as
/// &lt;Id&gt;.renewal.json and uses .new/.previous sidecars for atomic replacement;
/// all three exact files are therefore part of the transaction.
/// </summary>
public sealed class WinAcmeRenewalStateTransaction : IDisposable
{
    private const long MaximumStateFileBytes = 4L * 1024 * 1024;
    private const int MaximumTreeEntries = 50_000;
    private const int MaximumTreeDepth = 32;

    private readonly string _renewalId;
    private readonly string _productionDirectory;
    private readonly IReadOnlyList<FileSnapshot> _snapshots;
    private bool _completed;
    private bool _executionStarted;

    private WinAcmeRenewalStateTransaction(
        string renewalId,
        string productionDirectory,
        IReadOnlyList<FileSnapshot> snapshots)
    {
        _renewalId = renewalId;
        _productionDirectory = productionDirectory;
        _snapshots = snapshots;
    }

    public string RenewalId => _renewalId;

    public static WinAcmeRenewalStateTransaction Capture(string renewalId)
    {
        ValidateRenewalId(renewalId);
        var productionDirectory = GetProductionConfigurationDirectory();
        EnsurePrivateDirectoryPath(productionDirectory);
        ValidateManagedTree(productionDirectory, renewalId);

        var renewalPath = GetRenewalPath(productionDirectory, renewalId);
        var paths = new[]
        {
            renewalPath,
            renewalPath + ".new",
            renewalPath + ".previous"
        };
        var snapshots = paths.Select(CaptureFile).ToArray();
        ValidateRenewalJson(snapshots[0], renewalId, allowMissing: true);
        if (snapshots.Skip(1).Any(snapshot => snapshot.Existed))
        {
            throw new InvalidDataException(
                "renewal 在正式簽發前已有 .new 或 .previous sidecar；狀態可能來自未完成寫入，請先人工檢查。 ");
        }

        return new WinAcmeRenewalStateTransaction(renewalId, productionDirectory, snapshots);
    }

    public void ValidatePreviewConsent(
        WinAcmeCertificateRequest request,
        string? expectedStateSha256,
        bool confirmRemovedRenewalNames) =>
        WinAcmeRenewalPolicyService.ValidatePreviewConsent(
            request, _snapshots[0].Content, expectedStateSha256, confirmRemovedRenewalNames);

    public void MarkExecutionStarted()
    {
        // Recheck immediately before launching win-acme, after the potentially slow
        // IIS backup. A changed definition must trigger a fresh user preview, not a
        // rollback that could overwrite another successful renewal.
        ValidateManagedTree(_productionDirectory, _renewalId);
        var current = CaptureFile(_snapshots[0].Path);
        if (!string.Equals(WinAcmeRenewalPolicyService.StateHash(current.Content),
                WinAcmeRenewalPolicyService.StateHash(_snapshots[0].Content), StringComparison.Ordinal))
        {
            throw new InvalidDataException("續期設定在預覽後已變更，正式簽發未開始；請重新預覽。");
        }
        WinAcmeRenewalPolicyService.RejectSidecars(_snapshots[0].Path);
        _executionStarted = true;
    }

    public bool ValidateCommittedRenewal(WinAcmeCertificateRequest request, out string error)
    {
        error = string.Empty;
        try
        {
            ValidateManagedTree(_productionDirectory, _renewalId);
            var renewalPath = GetRenewalPath(_productionDirectory, _renewalId);
            var current = CaptureFile(renewalPath);
            ValidateRenewalJson(current, _renewalId, allowMissing: false);
            WinAcmeRenewalPolicyService.VerifyCommittedContent(
                current.Content!, request, WinAcmeRenewalPolicyService.ReadEffectiveDefaultStore());
            var original = _snapshots[0];
            if (original.Existed &&
                CryptographicOperations.FixedTimeEquals(original.Content!, current.Content!))
            {
                error = "win-acme 回報成功，但 renewal 主檔內容沒有更新；已拒絕建立 SYSTEM 排程。";
                return false;
            }

            foreach (var sidecar in new[] { renewalPath + ".new", renewalPath + ".previous" })
            {
                if (Directory.Exists(sidecar))
                {
                    error = $"renewal sidecar 路徑被目錄占用：{Path.GetFileName(sidecar)}";
                    return false;
                }

                if (File.Exists(sidecar))
                {
                    error = $"win-acme 留下未完成的 renewal sidecar：{Path.GetFileName(sidecar)}";
                    return false;
                }
            }

            return true;
        }
        catch (Exception exception)
        {
            error = exception.Message;
            return false;
        }
    }

    public WinAcmeRenewalStateRestoreResult Restore()
    {
        if (_completed)
        {
            return new WinAcmeRenewalStateRestoreResult
            {
                Success = true,
                Summary = $"renewal {_renewalId} 已完成交易，不需再次復原。"
            };
        }

        var failures = new List<string>();
        try
        {
            EnsurePrivateDirectoryPath(_productionDirectory);
            ValidateManagedTree(_productionDirectory, _renewalId);
        }
        catch (Exception exception)
        {
            return new WinAcmeRenewalStateRestoreResult
            {
                Success = false,
                Summary = $"renewal 安全路徑驗證失敗，未寫入任何復原資料：{exception.Message}"
            };
        }

        // Restore the main renewal first so an already-existing scheduled task
        // can never observe the failed definition after this method succeeds.
        foreach (var snapshot in _snapshots)
        {
            try
            {
                RestoreFile(snapshot);
            }
            catch (Exception exception)
            {
                failures.Add($"{Path.GetFileName(snapshot.Path)}：{exception.Message}");
            }
        }

        if (failures.Count == 0)
        {
            _completed = true;
            return new WinAcmeRenewalStateRestoreResult
            {
                Success = true,
                Summary = $"已只復原 renewal {_renewalId} 的原始狀態。"
            };
        }

        return new WinAcmeRenewalStateRestoreResult
        {
            Success = false,
            Summary = "renewal 狀態復原不完整：" + string.Join("；", failures)
        };
    }

    public void Commit() => _completed = true;

    public void Dispose()
    {
        if (!_completed && _executionStarted)
        {
            _ = Restore();
        }
    }

    private static string GetProductionConfigurationDirectory()
    {
        var endpoint = new Uri(WinAcmeRecommendedRelease.ProductionBaseUri);
        if (!endpoint.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            endpoint.AbsolutePath != "/" ||
            !string.IsNullOrEmpty(endpoint.Query) ||
            !string.IsNullOrEmpty(endpoint.Fragment))
        {
            throw new InvalidOperationException("固定的 win-acme production endpoint 不能安全映射到設定目錄。");
        }

        var configurationRoot = Path.GetFullPath(AppPaths.WinAcmeConfigurationDirectory);
        var productionDirectory = Path.GetFullPath(Path.Combine(configurationRoot, endpoint.Host));
        EnsureDirectChild(configurationRoot, productionDirectory);
        return productionDirectory;
    }

    private static string GetRenewalPath(string productionDirectory, string renewalId)
    {
        var path = Path.GetFullPath(Path.Combine(productionDirectory, renewalId + ".renewal.json"));
        EnsureDirectChild(productionDirectory, path);
        return path;
    }

    private static void EnsureDirectChild(string parent, string child)
    {
        var normalizedParent = Path.GetFullPath(parent)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var expectedPrefix = normalizedParent + Path.DirectorySeparatorChar;
        if (!child.StartsWith(expectedPrefix, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(
                Path.GetDirectoryName(child)?.TrimEnd(
                    Path.DirectorySeparatorChar,
                    Path.AltDirectorySeparatorChar),
                normalizedParent,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("renewal 路徑不是受控設定目錄的直接子項目。");
        }
    }

    private static void ValidateRenewalId(string renewalId)
    {
        if (string.IsNullOrWhiteSpace(renewalId) ||
            renewalId.Length > 80 ||
            renewalId.Any(character =>
                !(character is >= 'a' and <= 'z' or >= '0' and <= '9' or '-')))
        {
            throw new InvalidDataException("renewal ID 只能包含小寫英數字與連字號，且長度不可超過 80。 ");
        }
    }

    private static void ValidateManagedTree(string productionDirectory, string renewalId)
    {
        ProgramDataSecurity.ValidateTreeNoReparse(productionDirectory);
        var expectedRenewalPath = GetRenewalPath(productionDirectory, renewalId);
        var matchingRenewals = new List<string>();
        var pending = new Stack<(string Path, int Depth)>();
        pending.Push((productionDirectory, 0));
        var entries = 0;

        while (pending.Count > 0)
        {
            var current = pending.Pop();
            if (current.Depth > MaximumTreeDepth)
            {
                throw new InvalidDataException("win-acme production 設定目錄層級異常。 ");
            }

            foreach (var entry in Directory.EnumerateFileSystemEntries(current.Path))
            {
                entries++;
                if (entries > MaximumTreeEntries)
                {
                    throw new InvalidDataException("win-acme production 設定目錄項目數量異常。 ");
                }

                var attributes = File.GetAttributes(entry);
                if (attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    throw new InvalidDataException($"win-acme 狀態路徑包含 Reparse Point：{entry}");
                }

                if (attributes.HasFlag(FileAttributes.Directory))
                {
                    pending.Push((entry, current.Depth + 1));
                    continue;
                }

                if (Path.GetFileName(entry).Equals(
                        renewalId + ".renewal.json",
                        StringComparison.OrdinalIgnoreCase))
                {
                    matchingRenewals.Add(Path.GetFullPath(entry));
                }
            }
        }

        if (matchingRenewals.Any(path =>
                !path.Equals(expectedRenewalPath, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidDataException("相同 renewal ID 出現在非預期子目錄，已拒絕執行。 ");
        }
    }

    private static FileSnapshot CaptureFile(string path)
    {
        if (Directory.Exists(path))
        {
            throw new InvalidDataException($"renewal 檔案路徑被目錄占用：{Path.GetFileName(path)}");
        }

        if (!File.Exists(path))
        {
            return new FileSnapshot(path, false, null);
        }

        ValidateExistingPathNoReparse(path);
        using var stream = new FileStream(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.SequentialScan);
        if (stream.Length > MaximumStateFileBytes)
        {
            throw new InvalidDataException($"renewal 狀態檔超過安全大小上限：{Path.GetFileName(path)}");
        }

        using var buffer = new MemoryStream((int)stream.Length);
        stream.CopyTo(buffer);
        return new FileSnapshot(path, true, buffer.ToArray());
    }

    private static void ValidateRenewalJson(
        FileSnapshot snapshot,
        string renewalId,
        bool allowMissing)
    {
        if (!snapshot.Existed)
        {
            if (allowMissing)
            {
                return;
            }

            throw new InvalidDataException($"找不到預期 renewal：{renewalId}.renewal.json");
        }

        using var document = JsonDocument.Parse(
            snapshot.Content!,
            new JsonDocumentOptions
            {
                AllowTrailingCommas = false,
                CommentHandling = JsonCommentHandling.Disallow,
                MaxDepth = 128
            });
        if (document.RootElement.ValueKind != JsonValueKind.Object ||
            !document.RootElement.TryGetProperty("Id", out var idElement) ||
            idElement.ValueKind != JsonValueKind.String ||
            !string.Equals(idElement.GetString(), renewalId, StringComparison.Ordinal))
        {
            throw new InvalidDataException("renewal JSON 的 Id 與固定檔名不一致。 ");
        }
    }

    private static void RestoreFile(FileSnapshot snapshot)
    {
        if (!snapshot.Existed)
        {
            if (Directory.Exists(snapshot.Path))
            {
                throw new IOException($"renewal 復原目的地被目錄占用：{snapshot.Path}");
            }

            if (File.Exists(snapshot.Path))
            {
                ValidateExistingPathNoReparse(snapshot.Path);
                File.Delete(snapshot.Path);
            }

            return;
        }

        var temporary = snapshot.Path + $".mstech-restore-{Guid.NewGuid():N}.tmp";
        try
        {
            using (var stream = new FileStream(
                       temporary,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       64 * 1024,
                       FileOptions.WriteThrough))
            {
                stream.Write(snapshot.Content!);
                stream.Flush(flushToDisk: true);
            }

            ProgramDataSecurity.ApplyFileAcl(temporary, ProgramDataAccess.MachinePrivate);
            ProgramDataSecurity.ReplaceFileAtomically(
                temporary,
                snapshot.Path,
                ProgramDataAccess.MachinePrivate);
            var restored = CaptureFile(snapshot.Path);
            if (!restored.Existed ||
                !CryptographicOperations.FixedTimeEquals(restored.Content!, snapshot.Content!))
            {
                throw new IOException("原子復原後的內容驗證失敗。 ");
            }
        }
        finally
        {
            if (File.Exists(temporary))
            {
                ValidateExistingPathNoReparse(temporary);
                File.Delete(temporary);
            }
        }
    }

    private static void EnsurePrivateDirectoryPath(string productionDirectory)
    {
        ProgramDataSecurity.EnsureToolRoot();
        ProgramDataSecurity.EnsureDirectory(
            AppPaths.WinAcmeStateDirectory,
            ProgramDataAccess.MachinePrivate);
        ProgramDataSecurity.EnsureDirectory(
            AppPaths.WinAcmeConfigurationDirectory,
            ProgramDataAccess.MachinePrivate);
        ProgramDataSecurity.EnsureDirectory(
            productionDirectory,
            ProgramDataAccess.MachinePrivate);
    }

    private static void ValidateExistingPathNoReparse(string path)
    {
        _ = ProgramDataSecurity.ValidateNoReparse(path, allowMissingLeaf: false);
    }

    private sealed record FileSnapshot(string Path, bool Existed, byte[]? Content);
}
