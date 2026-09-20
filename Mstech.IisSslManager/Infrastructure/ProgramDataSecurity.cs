using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Mstech.IisSslManager.Infrastructure;

internal enum ProgramDataAccess
{
    UsersReadAndExecute,
    MachinePrivate
}

/// <summary>
/// Creates and validates the application-owned ProgramData tree without ever
/// following a reparse point. Elevated writers must call this helper before
/// creating or replacing files below <see cref="AppPaths.ProgramDataRoot"/>.
/// </summary>
internal static class ProgramDataSecurity
{
    private const int ErrorAlreadyExists = 183;
    private static readonly object SyncRoot = new();
    private static readonly SecurityIdentifier AdministratorsSid = new(
        WellKnownSidType.BuiltinAdministratorsSid,
        null);
    private static readonly SecurityIdentifier SystemSid = new(
        WellKnownSidType.LocalSystemSid,
        null);
    private static readonly SecurityIdentifier UsersSid = new(
        WellKnownSidType.BuiltinUsersSid,
        null);
    private const FileSystemRights DangerousWriterRights =
        FileSystemRights.WriteData |
        FileSystemRights.AppendData |
        FileSystemRights.WriteExtendedAttributes |
        FileSystemRights.WriteAttributes |
        FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.Delete |
        FileSystemRights.ChangePermissions |
        FileSystemRights.TakeOwnership;

    public static string EnsureToolRoot()
    {
        lock (SyncRoot)
        {
            var commonData = Path.GetFullPath(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
            AssertExistingDirectoryChainHasNoReparsePoints(commonData);

            var productRoot = Path.GetFullPath(AppPaths.ProgramDataRoot);
            if (TryGetAttributes(productRoot, out var productAttributes))
            {
                AssertDirectoryAttributes(productRoot, productAttributes);
                AssertExistingDirectoryIsTrusted(productRoot, requireProtectedAcl: true);
            }
            else
            {
                CreateToolRootSecurely(commonData, productRoot);
            }

            AssertTreeNoReparseCore(productRoot);
            ApplyDirectorySecurity(productRoot, ProgramDataAccess.UsersReadAndExecute);

            AssertNoReparseComponentsCore(productRoot, productRoot, allowMissingLeaf: false);
            AssertTreeNoReparseCore(productRoot);
            return productRoot;
        }
    }

    public static string EnsureDirectory(string path, ProgramDataAccess access)
    {
        lock (SyncRoot)
        {
            var root = EnsureToolRoot();
            var fullPath = NormalizeControlledPath(path, root);
            if (string.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase))
            {
                ApplyDirectorySecurity(root, ProgramDataAccess.UsersReadAndExecute);
                return root;
            }

            var relative = Path.GetRelativePath(root, fullPath);
            var current = root;
            foreach (var segment in SplitRelativePath(relative))
            {
                var next = Path.Combine(current, segment);
                var created = EnsureDirectChild(current, next);
                if (!created)
                {
                    AssertExistingDirectoryIsTrusted(next, requireProtectedAcl: false);
                }

                ApplyDirectorySecurity(next, access);
                current = next;
            }

            AssertNoReparseComponentsCore(root, fullPath, allowMissingLeaf: false);
            return fullPath;
        }
    }

    /// <summary>
    /// Validates every existing component from the controlled root through the
    /// supplied path. Only the final component may be absent.
    /// </summary>
    public static string ValidateNoReparse(string path, bool allowMissingLeaf)
    {
        lock (SyncRoot)
        {
            var root = EnsureToolRoot();
            var fullPath = NormalizeControlledPath(path, root);
            AssertNoReparseComponentsCore(root, fullPath, allowMissingLeaf);
            return fullPath;
        }
    }

    public static string ValidateTreeNoReparse(string directory)
    {
        lock (SyncRoot)
        {
            var fullPath = ValidateNoReparse(directory, allowMissingLeaf: false);
            AssertExistingDirectoryNoReparse(fullPath);
            AssertTreeNoReparseCore(fullPath);
            return fullPath;
        }
    }

    public static void ApplyFileAcl(string path, ProgramDataAccess access)
    {
        lock (SyncRoot)
        {
            var fullPath = ValidateNoReparse(path, allowMissingLeaf: false);
            ApplyFileSecurityCore(fullPath, access);
            AssertNoReparseComponentsCore(
                Path.GetFullPath(AppPaths.ProgramDataRoot),
                fullPath,
                allowMissingLeaf: false);
        }
    }

    public static void ApplyTreeAcl(string directory, ProgramDataAccess access)
    {
        lock (SyncRoot)
        {
            var root = ValidateTreeNoReparse(directory);
            var directories = new List<string> { root };
            var files = new List<string>();
            var pending = new Stack<string>();
            pending.Push(root);
            while (pending.Count > 0)
            {
                var current = pending.Pop();
                foreach (var entry in Directory.EnumerateFileSystemEntries(current))
                {
                    var attributes = File.GetAttributes(entry);
                    if (attributes.HasFlag(FileAttributes.ReparsePoint))
                    {
                        throw new IOException($"受控目錄樹包含 Reparse Point：{entry}");
                    }

                    if (attributes.HasFlag(FileAttributes.Directory))
                    {
                        directories.Add(entry);
                        pending.Push(entry);
                    }
                    else
                    {
                        files.Add(entry);
                    }
                }
            }

            foreach (var path in directories)
            {
                ApplyDirectorySecurity(path, access);
            }

            foreach (var path in files)
            {
                ApplyFileSecurityCore(path, access);
            }

            AssertTreeNoReparseCore(root);
        }
    }

    /// <summary>
    /// Replaces a file by a same-directory rename. On Windows this replaces the
    /// destination directory entry; it never opens the old destination for write.
    /// Therefore, if the old destination was a hard link, its other links keep the
    /// old bytes and cannot be modified by this deployment.
    /// </summary>
    public static void ReplaceFileAtomically(
        string temporaryPath,
        string destinationPath,
        ProgramDataAccess access)
    {
        lock (SyncRoot)
        {
            var temporary = ValidateNoReparse(temporaryPath, allowMissingLeaf: false);
            var destination = ValidateNoReparse(destinationPath, allowMissingLeaf: true);
            var temporaryParent = Path.GetDirectoryName(temporary);
            var destinationParent = Path.GetDirectoryName(destination);
            if (temporaryParent is null || destinationParent is null ||
                !string.Equals(
                    temporaryParent,
                    destinationParent,
                    StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException("原子檔案替換必須使用目的地同一目錄內的暫存檔。");
            }

            ValidateNoReparse(destinationParent, allowMissingLeaf: false);
            ApplyFileAcl(temporary, access);
            ValidateNoReparse(temporary, allowMissingLeaf: false);
            ValidateNoReparse(destination, allowMissingLeaf: true);

            File.Move(temporary, destination, overwrite: true);

            ValidateNoReparse(destinationParent, allowMissingLeaf: false);
            ValidateNoReparse(destination, allowMissingLeaf: false);
            AssertFileSecurity(destination);
        }
    }

    private static bool EnsureDirectChild(string expectedParent, string child)
    {
        var normalizedParent = Path.GetFullPath(expectedParent)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var normalizedChild = Path.GetFullPath(child);
        if (!string.Equals(
                Path.GetDirectoryName(normalizedChild),
                normalizedParent,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("受控目錄不是預期父目錄的直接子目錄。");
        }

        AssertExistingDirectoryNoReparse(normalizedParent);
        var created = EnsureOneDirectory(normalizedChild);
        AssertExistingDirectoryNoReparse(normalizedParent);
        AssertExistingDirectoryNoReparse(normalizedChild);
        return created;
    }

    private static void CreateToolRootSecurely(string commonData, string productRoot)
    {
        var common = Path.GetFullPath(commonData)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(
                Path.GetDirectoryName(Path.GetFullPath(productRoot)),
                common,
                StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("工具 ProgramData 根目錄不是 CommonApplicationData 的直接子目錄。");
        }

        for (var attempt = 0; attempt < 8; attempt++)
        {
            var candidate = Path.Combine(
                common,
                $".{AppPaths.VendorName}-{AppPaths.ProductFolderName}-create-{Guid.NewGuid():N}");
            if (!CreateDirectoryNative(candidate, IntPtr.Zero))
            {
                var error = Marshal.GetLastWin32Error();
                if (error == ErrorAlreadyExists)
                {
                    continue;
                }

                throw new Win32Exception(error, $"無法建立安全的工具根目錄暫存：{candidate}");
            }

            try
            {
                AssertExistingDirectoryNoReparse(candidate);
                ApplyDirectorySecurity(candidate, ProgramDataAccess.UsersReadAndExecute);
                if (Directory.EnumerateFileSystemEntries(candidate).Any())
                {
                    throw new IOException("安全根目錄在鎖定 ACL 前遭加入項目，已拒絕使用。");
                }

                try
                {
                    Directory.Move(candidate, productRoot);
                }
                catch (IOException) when (TryGetAttributes(productRoot, out var racedAttributes))
                {
                    AssertDirectoryAttributes(productRoot, racedAttributes);
                    AssertExistingDirectoryIsTrusted(productRoot, requireProtectedAcl: true);
                    TryDeleteEmptyCreationDirectory(candidate, common);
                    return;
                }

                AssertExistingDirectoryNoReparse(productRoot);
                AssertExistingDirectoryIsTrusted(productRoot, requireProtectedAcl: true);
                return;
            }
            catch
            {
                TryDeleteEmptyCreationDirectory(candidate, common);
                throw;
            }
        }

        throw new IOException("無法配置唯一的工具 ProgramData 根目錄暫存名稱。");
    }

    private static void AssertExistingDirectoryIsTrusted(
        string path,
        bool requireProtectedAcl)
    {
        AssertExistingDirectoryNoReparse(path);
        var security = new DirectoryInfo(path).GetAccessControl(
            AccessControlSections.Access | AccessControlSections.Owner);
        if (requireProtectedAcl && !security.AreAccessRulesProtected)
        {
            throw new UnauthorizedAccessException(
                $"既有受控目錄 ACL 未受保護；為避免接管使用者預植內容，已拒絕使用：{path}");
        }

        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || (!owner.Equals(AdministratorsSid) && !owner.Equals(SystemSid)))
        {
            throw new UnauthorizedAccessException(
                $"既有受控目錄擁有者不是 Administrators 或 SYSTEM，已拒絕接管：{path}");
        }

        var allowedWriters = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            AdministratorsSid.Value,
            SystemSid.Value
        };
        var rules = security.GetAccessRules(
            includeExplicit: true,
            includeInherited: true,
            targetType: typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow ||
                !GrantsDangerousWriteAccess(rule.FileSystemRights))
            {
                continue;
            }

            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (!allowedWriters.Contains(sid.Value))
            {
                throw new UnauthorizedAccessException(
                    $"既有受控目錄允許非預期帳號寫入 ({sid.Value})，已拒絕接管：{path}");
            }
        }
    }

    internal static bool GrantsDangerousWriteAccess(FileSystemRights rights) =>
        (rights & DangerousWriterRights) != 0;

    private static void TryDeleteEmptyCreationDirectory(string candidate, string commonData)
    {
        try
        {
            var fullPath = Path.GetFullPath(candidate);
            if (!string.Equals(
                    Path.GetDirectoryName(fullPath),
                    Path.GetFullPath(commonData).TrimEnd(
                        Path.DirectorySeparatorChar,
                        Path.AltDirectorySeparatorChar),
                    StringComparison.OrdinalIgnoreCase) ||
                !TryGetAttributes(fullPath, out var attributes))
            {
                return;
            }

            AssertDirectoryAttributes(fullPath, attributes);
            if (!Directory.EnumerateFileSystemEntries(fullPath).Any())
            {
                Directory.Delete(fullPath, recursive: false);
            }
        }
        catch
        {
            // The directory is protected and intentionally left for an
            // administrator when safe empty-directory cleanup cannot be proven.
        }
    }

    private static bool EnsureOneDirectory(string path)
    {
        if (TryGetAttributes(path, out var attributes))
        {
            AssertDirectoryAttributes(path, attributes);
            return false;
        }

        Directory.CreateDirectory(path);
        if (!TryGetAttributes(path, out attributes))
        {
            throw new IOException($"無法建立受控目錄：{path}");
        }

        AssertDirectoryAttributes(path, attributes);
        return true;
    }

    private static void ApplyDirectorySecurity(string path, ProgramDataAccess access)
    {
        AssertExistingDirectoryNoReparse(path);
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(AdministratorsSid);
        AddMachineRules(security);
        if (access == ProgramDataAccess.UsersReadAndExecute)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                UsersSid,
                FileSystemRights.ReadAndExecute,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        new DirectoryInfo(path).SetAccessControl(security);
        AssertDirectorySecurity(path);
        AssertExistingDirectoryNoReparse(path);
    }

    private static void ApplyFileSecurityCore(string path, ProgramDataAccess access)
    {
        var attributes = File.GetAttributes(path);
        if (attributes.HasFlag(FileAttributes.Directory))
        {
            throw new IOException($"預期為檔案，但找到目錄：{path}");
        }

        if (attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new IOException($"拒絕設定 Reparse Point 檔案 ACL：{path}");
        }

        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.SetOwner(AdministratorsSid);
        AddMachineRules(security);
        if (access == ProgramDataAccess.UsersReadAndExecute)
        {
            security.AddAccessRule(new FileSystemAccessRule(
                UsersSid,
                FileSystemRights.ReadAndExecute,
                AccessControlType.Allow));
        }

        new FileInfo(path).SetAccessControl(security);
        AssertFileSecurity(path);
        if (File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint))
        {
            throw new IOException($"設定 ACL 後檔案成為 Reparse Point：{path}");
        }
    }

    private static void AddMachineRules(FileSystemSecurity security)
    {
        security.AddAccessRule(new FileSystemAccessRule(
            SystemSid,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            AdministratorsSid,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));
    }

    private static void AddMachineRules(FileSecurity security)
    {
        security.AddAccessRule(new FileSystemAccessRule(
            SystemSid,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
        security.AddAccessRule(new FileSystemAccessRule(
            AdministratorsSid,
            FileSystemRights.FullControl,
            AccessControlType.Allow));
    }

    private static void AssertDirectorySecurity(string path)
    {
        var security = new DirectoryInfo(path).GetAccessControl(
            AccessControlSections.Access | AccessControlSections.Owner);
        AssertProtectedAdministratorsOwner(path, security);
    }

    private static void AssertFileSecurity(string path)
    {
        var security = new FileInfo(path).GetAccessControl(
            AccessControlSections.Access | AccessControlSections.Owner);
        AssertProtectedAdministratorsOwner(path, security);
    }

    private static void AssertProtectedAdministratorsOwner(
        string path,
        FileSystemSecurity security)
    {
        if (!security.AreAccessRulesProtected)
        {
            throw new UnauthorizedAccessException($"受控路徑 ACL 仍允許繼承：{path}");
        }

        var owner = security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;
        if (owner is null || !owner.Equals(AdministratorsSid))
        {
            throw new UnauthorizedAccessException($"受控路徑擁有者不是 Administrators：{path}");
        }
    }

    private static void AssertExistingDirectoryChainHasNoReparsePoints(string path)
    {
        var fullPath = Path.GetFullPath(path);
        var root = Path.GetPathRoot(fullPath)
            ?? throw new InvalidOperationException("CommonApplicationData 沒有磁碟根目錄。");
        AssertExistingDirectoryNoReparse(root);

        var relative = Path.GetRelativePath(root, fullPath);
        var current = root;
        foreach (var segment in SplitRelativePath(relative))
        {
            current = Path.Combine(current, segment);
            AssertExistingDirectoryNoReparse(current);
        }
    }

    private static void AssertNoReparseComponentsCore(
        string controlledRoot,
        string path,
        bool allowMissingLeaf)
    {
        var root = Path.GetFullPath(controlledRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var fullPath = NormalizeControlledPath(path, root);
        AssertExistingDirectoryNoReparse(root);
        if (string.Equals(root, fullPath, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        var segments = SplitRelativePath(Path.GetRelativePath(root, fullPath));
        var current = root;
        for (var index = 0; index < segments.Length; index++)
        {
            current = Path.Combine(current, segments[index]);
            if (!TryGetAttributes(current, out var attributes))
            {
                if (allowMissingLeaf && index == segments.Length - 1)
                {
                    return;
                }

                throw new DirectoryNotFoundException($"受控路徑元件不存在：{current}");
            }

            if (attributes.HasFlag(FileAttributes.ReparsePoint))
            {
                throw new IOException($"受控路徑包含 Reparse Point：{current}");
            }

            if (index < segments.Length - 1 &&
                !attributes.HasFlag(FileAttributes.Directory))
            {
                throw new IOException($"受控路徑的父元件不是目錄：{current}");
            }
        }
    }

    private static void AssertTreeNoReparseCore(string directory)
    {
        var pending = new Stack<string>();
        pending.Push(directory);
        while (pending.Count > 0)
        {
            var current = pending.Pop();
            AssertExistingDirectoryNoReparse(current);
            foreach (var entry in Directory.EnumerateFileSystemEntries(current))
            {
                if (!TryGetAttributes(entry, out var attributes))
                {
                    throw new IOException($"檢查期間受控路徑項目消失：{entry}");
                }

                if (attributes.HasFlag(FileAttributes.ReparsePoint))
                {
                    throw new IOException($"受控目錄樹包含 Reparse Point：{entry}");
                }

                if (attributes.HasFlag(FileAttributes.Directory))
                {
                    pending.Push(entry);
                }
            }
        }
    }

    private static string NormalizeControlledPath(string path, string controlledRoot)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var root = Path.GetFullPath(controlledRoot)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var fullPath = Path.GetFullPath(path)
            .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        if (!string.Equals(fullPath, root, StringComparison.OrdinalIgnoreCase) &&
            !fullPath.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("路徑不在工具的受控 ProgramData 根目錄中。");
        }

        return fullPath;
    }

    private static string[] SplitRelativePath(string relative) =>
        relative.Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.RemoveEmptyEntries);

    private static void AssertExistingDirectoryNoReparse(string path)
    {
        if (!TryGetAttributes(path, out var attributes))
        {
            throw new DirectoryNotFoundException($"預期的目錄不存在：{path}");
        }

        AssertDirectoryAttributes(path, attributes);
    }

    private static void AssertDirectoryAttributes(string path, FileAttributes attributes)
    {
        if (!attributes.HasFlag(FileAttributes.Directory))
        {
            throw new IOException($"預期為目錄，但找到檔案：{path}");
        }

        if (attributes.HasFlag(FileAttributes.ReparsePoint))
        {
            throw new IOException($"拒絕使用 Reparse Point 目錄：{path}");
        }
    }

    private static bool TryGetAttributes(string path, out FileAttributes attributes)
    {
        try
        {
            attributes = File.GetAttributes(path);
            return true;
        }
        catch (Exception exception) when (
            exception is FileNotFoundException or DirectoryNotFoundException)
        {
            attributes = default;
            return false;
        }
    }

    [DllImport(
        "kernel32.dll",
        EntryPoint = "CreateDirectoryW",
        CharSet = CharSet.Unicode,
        SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectoryNative(
        string lpPathName,
        IntPtr lpSecurityAttributes);
}
