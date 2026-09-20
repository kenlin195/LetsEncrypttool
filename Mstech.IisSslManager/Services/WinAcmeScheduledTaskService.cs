using System.IO;
using System.Runtime.InteropServices;

namespace Mstech.IisSslManager.Services;

/// <summary>
/// Reads the Windows Task Scheduler through its COM API. This avoids parsing
/// localized schtasks.exe text on Traditional Chinese or English servers.
/// </summary>
public sealed class WinAcmeScheduledTaskService
{
    private const int TaskEnumHidden = 1;

    public IReadOnlyList<WinAcmeScheduledTaskInfo> GetRenewalTasks(string? expectedExecutablePath = null) =>
        ReadRenewalTasks(expectedExecutablePath).Tasks;

    /// <summary>Read-only inventory. A failed query must not be confused with an empty inventory.</summary>
    public WinAcmeScheduledTaskReadResult ReadRenewalTasks(string? expectedExecutablePath = null)
    {
        if (!OperatingSystem.IsWindows())
        {
            return ReadFailed("目前平台無法讀取 Windows 工作排程器，排程狀態未知。");
        }

        object? serviceObject = null;
        object? rootFolderObject = null;
        object? tasksObject = null;
        try
        {
            var serviceType = Type.GetTypeFromProgID("Schedule.Service", throwOnError: false);
            if (serviceType is null)
            {
                return ReadFailed("找不到 Windows 工作排程器 COM 服務，排程狀態未知。");
            }

            serviceObject = Activator.CreateInstance(serviceType);
            if (serviceObject is null)
            {
                return ReadFailed("無法建立 Windows 工作排程器 COM 物件，排程狀態未知。");
            }

            dynamic service = serviceObject;
            service.Connect();
            rootFolderObject = service.GetFolder("\\");
            dynamic rootFolder = rootFolderObject;
            tasksObject = rootFolder.GetTasks(TaskEnumHidden);
            dynamic tasks = tasksObject;

            var result = new List<WinAcmeScheduledTaskInfo>();
            for (var index = 1; index <= (int)tasks.Count; index++)
            {
                object? taskObject = null;
                try
                {
                    taskObject = tasks.Item(index);
                    dynamic task = taskObject;
                    // Inventory managed-name candidates even when their actions have been
                    // damaged. Otherwise a malformed task silently looks like no task.
                    string taskName = task.Name;
                    if (taskName.StartsWith(WinAcmeRecommendedRelease.ManagedClientName + " renew", StringComparison.OrdinalIgnoreCase))
                    {
                        result.Add(ReadTask(task));
                    }
                }
                finally
                {
                    ReleaseComObject(taskObject);
                }
            }

            return new WinAcmeScheduledTaskReadResult
            {
                Succeeded = true,
                Tasks = result.OrderBy(item => item.Name, StringComparer.CurrentCultureIgnoreCase).ToArray()
            };
        }
        catch (Exception exception)
        {
            return ReadFailed($"無法完整讀取工作排程器，排程狀態未知：{exception.Message}");
        }
        finally
        {
            ReleaseComObject(tasksObject);
            ReleaseComObject(rootFolderObject);
            ReleaseComObject(serviceObject);
        }
    }

    public WinAcmeScheduledTaskInfo? GetPrimaryRenewalTask(string? expectedExecutablePath = null) =>
        GetRenewalTasks(expectedExecutablePath)
            .Where(item => IsExpectedRenewalTask(item, expectedExecutablePath))
            .OrderByDescending(item => item.State == WinAcmeScheduledTaskState.Running)
            .ThenByDescending(item => item.Enabled)
            .ThenBy(item => item.Name, StringComparer.CurrentCultureIgnoreCase)
            .FirstOrDefault();

    private static WinAcmeScheduledTaskInfo ReadTask(dynamic task)
    {
        object? definitionObject = null;
        object? principalObject = null;
        object? actionsObject = null;
        object? actionObject = null;
        object? triggersObject = null;
        try
        {
            definitionObject = task.Definition;
            dynamic definition = definitionObject;
            principalObject = definition.Principal;
            actionsObject = definition.Actions;
            dynamic principal = principalObject;
            dynamic actions = actionsObject;

            string? executable = null;
            string? arguments = null;
            string? workingDirectory = null;
            var actionCount = (int)actions.Count;
            if (actionCount == 1)
            {
                actionObject = actions.Item(1);
                dynamic action = actionObject;
                try
                {
                    executable = action.Path as string;
                    arguments = action.Arguments as string;
                    workingDirectory = action.WorkingDirectory as string;
                }
                catch (Microsoft.CSharp.RuntimeBinder.RuntimeBinderException)
                {
                    // Non-exec action. It cannot be a standard win-acme task.
                }
            }

            var lastRun = ConvertTaskDate(task.LastRunTime);
            var nextRun = ConvertTaskDate(task.NextRunTime);
            triggersObject = definition.Triggers;
            dynamic triggers = triggersObject;
            var triggerCount = (int)triggers.Count;
            var recurringTriggerCount = 0;
            for (var index = 1; index <= triggerCount; index++)
            {
                object? triggerObject = null;
                try
                {
                    triggerObject = triggers.Item(index);
                    dynamic trigger = triggerObject;
                    // Pinned win-acme 2.2.9 creates DailyTrigger with DaysInterval=1.
                    string? endBoundary = trigger.EndBoundary as string;
                    var notEnded = string.IsNullOrWhiteSpace(endBoundary) ||
                        (DateTimeOffset.TryParse(endBoundary, System.Globalization.CultureInfo.InvariantCulture,
                            System.Globalization.DateTimeStyles.AssumeLocal, out var endsAt) && endsAt > DateTimeOffset.Now);
                    if ((int)trigger.Type == 2 && (bool)trigger.Enabled && (int)trigger.DaysInterval == 1 && notEnded)
                    {
                        recurringTriggerCount++;
                    }
                }
                finally
                {
                    ReleaseComObject(triggerObject);
                }
            }
            return new WinAcmeScheduledTaskInfo
            {
                Name = (string)task.Name,
                Path = (string)task.Path,
                State = MapState((int)task.State),
                Enabled = (bool)task.Enabled,
                LastRunTime = lastRun,
                NextRunTime = nextRun,
                LastTaskResult = unchecked((int)task.LastTaskResult),
                RunAsUser = principal.UserId as string,
                ExecutablePath = executable,
                Arguments = arguments,
                WorkingDirectory = workingDirectory,
                ActionCount = actionCount,
                TriggerCount = triggerCount,
                EnabledRecurringTriggerCount = recurringTriggerCount
            };
        }
        finally
        {
            ReleaseComObject(actionObject);
            ReleaseComObject(triggersObject);
            ReleaseComObject(actionsObject);
            ReleaseComObject(principalObject);
            ReleaseComObject(definitionObject);
        }
    }

    internal static bool IsExpectedRenewalTask(
        WinAcmeScheduledTaskInfo task,
        string? expectedExecutablePath)
    {
        if (task.ActionCount != 1)
        {
            return false;
        }

        var nameMatches = task.Name.StartsWith(
            WinAcmeRecommendedRelease.ManagedClientName + " renew",
            StringComparison.OrdinalIgnoreCase);
        var executable = NormalizeAbsolutePath(task.ExecutablePath);
        var actionMatches = executable is not null &&
            string.Equals(Path.GetFileName(executable), "wacs.exe", StringComparison.OrdinalIgnoreCase) &&
            HasAllowedRenewalArguments(task.Arguments);
        if (expectedExecutablePath is null && !nameMatches && !actionMatches)
        {
            return false;
        }

        if (expectedExecutablePath is null)
        {
            return nameMatches && actionMatches;
        }

        try
        {
            return nameMatches && actionMatches &&
                   executable is not null &&
                   string.Equals(
                       executable,
                       NormalizeAbsolutePath(expectedExecutablePath),
                       StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException)
        {
            return false;
        }
    }

    /// <summary>
    /// Matches the pinned source TaskSchedulerService.Arguments, with optional --quiet.
    /// No duplicate options, alternate endpoint, script, force, filter or config override
    /// is accepted merely because the command also happens to contain --renew.
    /// </summary>
    internal static bool HasAllowedRenewalArguments(string? arguments)
    {
        if (!TryTokenize(arguments, out var tokens))
        {
            return false;
        }

        var renew = false;
        var baseUri = false;
        var quiet = false;
        for (var index = 0; index < tokens.Count; index++)
        {
            switch (tokens[index].ToLowerInvariant())
            {
                case "--renew" when !renew:
                    renew = true;
                    break;
                case "--quiet" when !quiet:
                    quiet = true;
                    break;
                case "--baseuri" when !baseUri && index + 1 < tokens.Count:
                    baseUri = true;
                    if (!string.Equals(tokens[++index], WinAcmeRecommendedRelease.ProductionBaseUri, StringComparison.OrdinalIgnoreCase))
                    {
                        return false;
                    }
                    break;
                default:
                    return false;
            }
        }
        return renew && baseUri;
    }

    public static ScheduledTaskReadiness EvaluateReadiness(
        WinAcmeScheduledTaskInfo? task,
        string expectedExecutablePath,
        DateTimeOffset? now = null)
    {
        var issues = new List<string>();
        if (task is null)
        {
            issues.Add("找不到本工具管理的續期排程。");
        }
        else
        {
            if (!IsExpectedRenewalTask(task, expectedExecutablePath))
                issues.Add("排程名稱、單一 wacs.exe 動作、受控路徑或完整續期參數不符合允許清單。");
            if (!task.Enabled || task.State == WinAcmeScheduledTaskState.Disabled)
                issues.Add("續期排程未啟用。");
            if (!IsSystemAccount(task.RunAsUser))
                issues.Add("續期排程不是以 SYSTEM 身分執行。");
            var normalizedExecutable = NormalizeAbsolutePath(expectedExecutablePath);
            if (normalizedExecutable is null || !string.Equals(NormalizeAbsolutePath(task.WorkingDirectory),
                    Path.GetDirectoryName(normalizedExecutable), StringComparison.OrdinalIgnoreCase))
                issues.Add("續期排程的工作目錄不是受控 wacs.exe 所在目錄。");
            if (task.TriggerCount == 0 || task.EnabledRecurringTriggerCount == 0)
                issues.Add("續期排程沒有已啟用的每日觸發條件。");
            var checkedAt = (now ?? DateTimeOffset.UtcNow).ToUniversalTime();
            var nextRun = task.NextRunTime is null ? (DateTimeOffset?)null : new DateTimeOffset(task.NextRunTime.Value).ToUniversalTime();
            if (nextRun is null || nextRun <= checkedAt)
                issues.Add("無法確認續期排程有未來的下次執行時間。");
            else if (nextRun > checkedAt.AddHours(48))
                issues.Add("續期排程的下次執行超過 48 小時，不符合每日檢查政策；請確認觸發條件的開始時間。");
            if (task.State is not (WinAcmeScheduledTaskState.Ready or WinAcmeScheduledTaskState.Queued or WinAcmeScheduledTaskState.Running or WinAcmeScheduledTaskState.Disabled))
                issues.Add("工作排程器回報的執行狀態未知。");
        }

        return new ScheduledTaskReadiness
        {
            IsReady = issues.Count == 0,
            Issues = issues,
            Summary = issues.Count == 0
                ? "SYSTEM 每日續期排程配置已就緒；排程成功執行不等於憑證已實際續期。"
                : string.Join(" ", issues)
        };
    }

    public static string DescribeLastExecution(WinAcmeScheduledTaskInfo task)
    {
        if (task.State == WinAcmeScheduledTaskState.Running || task.LastTaskResult == 0x00041301)
            return "排程執行中，尚無本次完成結果。";
        if (task.State == WinAcmeScheduledTaskState.Queued || task.LastTaskResult == 0x00041325)
            return "排程等待執行，尚無本次完成結果。";
        if (task.LastTaskResult == 0x00041303)
            return "排程尚未執行；不代表執行失敗。";
        if (task.LastTaskResult is null)
            return "無法讀取上次排程結果，狀態未知。";
        if (task.LastTaskResult != 0)
            return $"上次排程回傳非成功結果 0x{unchecked((uint)task.LastTaskResult.Value):X8}；請檢查 win-acme 紀錄。";
        if (task.LastRunTime is null)
            return "沒有可確認的上次執行時間，尚不能認定排程曾成功執行。";
        return "上次排程程序成功結束；可能尚未到續期時間，不等於憑證已實際續期。";
    }

    private static bool IsSystemAccount(string? value) =>
        string.Equals(value, "SYSTEM", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(value, "NT AUTHORITY\\SYSTEM", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(value, "S-1-5-18", StringComparison.OrdinalIgnoreCase);

    private static WinAcmeScheduledTaskReadResult ReadFailed(string message) => new() { ErrorMessage = message };

    private static string? NormalizeAbsolutePath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        value = value.Trim();
        if (value.Length >= 2 && value[0] == '"' && value[^1] == '"') value = value[1..^1];
        if (value.Contains('"') || !Path.IsPathFullyQualified(value)) return null;
        try { return Path.GetFullPath(value).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar); }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
    }

    private static bool TryTokenize(string? commandLine, out List<string> tokens)
    {
        tokens = [];
        if (string.IsNullOrWhiteSpace(commandLine)) return false;
        // CreateProcess argument separation is spaces/tabs, not arbitrary Unicode
        // whitespace. Reject control/newline forms rather than validating a CLI
        // differently from the executable that will eventually parse it.
        if (commandLine.Any(character =>
                (char.IsControl(character) && character != '\t') ||
                (char.IsWhiteSpace(character) && character is not (' ' or '\t')))) return false;
        for (var index = 0; index < commandLine.Length;)
        {
            while (index < commandLine.Length && char.IsWhiteSpace(commandLine[index])) index++;
            if (index == commandLine.Length) break;
            var quoted = commandLine[index] == '"';
            if (quoted) index++;
            var start = index;
            while (index < commandLine.Length && (quoted ? commandLine[index] != '"' : !char.IsWhiteSpace(commandLine[index])))
            {
                if (!quoted && commandLine[index] == '"') return false;
                index++;
            }
            if (quoted && index == commandLine.Length) return false;
            tokens.Add(commandLine[start..index]);
            if (quoted)
            {
                index++;
                if (index < commandLine.Length && !char.IsWhiteSpace(commandLine[index])) return false;
            }
        }
        return tokens.Count > 0;
    }

    private static DateTime? ConvertTaskDate(object value)
    {
        try
        {
            var date = Convert.ToDateTime(value, System.Globalization.CultureInfo.InvariantCulture);
            return date.Year <= 1900 ? null : date;
        }
        catch (Exception exception) when (exception is FormatException or InvalidCastException)
        {
            return null;
        }
    }

    private static WinAcmeScheduledTaskState MapState(int state) => state switch
    {
        1 => WinAcmeScheduledTaskState.Disabled,
        2 => WinAcmeScheduledTaskState.Queued,
        3 => WinAcmeScheduledTaskState.Ready,
        4 => WinAcmeScheduledTaskState.Running,
        _ => WinAcmeScheduledTaskState.Unknown
    };

    private static void ReleaseComObject(object? value)
    {
        if (value is not null && Marshal.IsComObject(value))
        {
            try
            {
                Marshal.FinalReleaseComObject(value);
            }
            catch (InvalidComObjectException)
            {
                // Already released by the runtime binder.
            }
        }
    }
}
