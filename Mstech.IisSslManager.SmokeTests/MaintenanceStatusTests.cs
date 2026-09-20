using Mstech.IisSslManager.Services;

namespace Mstech.IisSslManager.SmokeTests;

public static class MaintenanceStatusTests
{
    public static void Run()
    {
        var now = new DateTimeOffset(2026, 9, 20, 12, 0, 0, TimeSpan.Zero);
        var executable = WinAcmeRecommendedRelease.ExecutablePath;
        var task = new WinAcmeScheduledTaskInfo
        {
            Name = WinAcmeRecommendedRelease.ManagedClientName + " renew (acme-v02.api.letsencrypt.org)",
            ExecutablePath = executable,
            WorkingDirectory = Path.GetDirectoryName(executable),
            Arguments = "--renew --baseuri \"https://acme-v02.api.letsencrypt.org/\"",
            ActionCount = 1,
            TriggerCount = 1,
            EnabledRecurringTriggerCount = 1,
            Enabled = true,
            RunAsUser = "S-1-5-18",
            State = WinAcmeScheduledTaskState.Ready,
            NextRunTime = now.AddHours(12).UtcDateTime,
            LastTaskResult = 0x41303
        };

        Assert(Ready(task), "new never-run task with a future daily trigger was rejected");
        Assert(!task.LastRunSucceeded, "never-run task described as successful");
        Assert(WinAcmeScheduledTaskService.DescribeLastExecution(task).Contains("尚未執行"), "never-run status was lost");
        Assert(Ready(task with { Arguments = "--quiet --baseuri https://acme-v02.api.letsencrypt.org/ --renew" }), "allowed quiet/reordered options rejected");
        foreach (var arguments in new[]
        {
            "--renew",
            "--renew --baseuri https://acme-staging-v02.api.letsencrypt.org/",
            "--renew --baseuri https://acme-v02.api.letsencrypt.org/ --force",
            "--renew --baseuri https://acme-v02.api.letsencrypt.org/ --script evil.ps1",
            "--renew --baseuri https://acme-v02.api.letsencrypt.org/ --id other-renewal",
            "--renew --baseuri https://acme-v02.api.letsencrypt.org/ --renew",
            "--renew --baseuri https://acme-v02.api.letsencrypt.org/ --quiet --quiet",
            "--renew --baseuri https://acme-v02.api.letsencrypt.org/ --baseuri https://other.invalid/",
            "--renew --baseuri \"https://acme-v02.api.letsencrypt.org/",
            "--renew --baseuri \"https://acme-v02.api.letsencrypt.org/\"trailing",
            "--renew --baseuri https://acme-v02.api.letsencrypt.org/extra",
            "--renew\n--baseuri https://acme-v02.api.letsencrypt.org/"
        })
        {
            Assert(!Ready(task with { Arguments = arguments }), $"unapproved task CLI accepted: {arguments}");
        }
        Assert(!Ready(task with { Enabled = false }), "disabled task accepted");
        Assert(!Ready(task with { State = WinAcmeScheduledTaskState.Unknown }), "unknown scheduler state accepted");
        Assert(!Ready(task with { RunAsUser = "Administrator" }), "non-SYSTEM task accepted");
        Assert(!Ready(task with { ActionCount = 2 }), "multiple actions accepted");
        Assert(!Ready(task with { ExecutablePath = @"C:\other\wacs.exe" }), "different executable accepted");
        Assert(!Ready(task with { WorkingDirectory = @"C:\other" }), "different working directory accepted");
        Assert(Ready(task with { ExecutablePath = $"\"{executable}\"" }), "pinned source's quoted executable form rejected");
        Assert(!Ready(task with { ExecutablePath = "wacs.exe" }), "relative executable accepted");
        Assert(!Ready(task with { TriggerCount = 0, EnabledRecurringTriggerCount = 0 }), "triggerless task accepted");
        Assert(!Ready(task with { EnabledRecurringTriggerCount = 0 }), "disabled/non-daily trigger accepted");
        Assert(!Ready(task with { NextRunTime = null }), "missing next run accepted");
        Assert(!Ready(task with { NextRunTime = now.AddMinutes(-1).UtcDateTime }), "past next run accepted");
        Assert(Ready(task with { NextRunTime = now.AddDays(1).UtcDateTime }), "normal next-day schedule rejected");
        Assert(Ready(task with { NextRunTime = now.AddHours(48).UtcDateTime }), "48-hour tolerance boundary rejected");
        Assert(!Ready(task with { NextRunTime = now.AddDays(3).UtcDateTime }), "distant future trigger accepted as daily readiness");
        Assert(Ready(task with { State = WinAcmeScheduledTaskState.Running, LastTaskResult = 0x41301 }), "healthy running task rejected");
        Assert(!Ready(task with { State = WinAcmeScheduledTaskState.Running, NextRunTime = null }), "running task bypassed future schedule check");
        Assert(WinAcmeScheduledTaskService.DescribeLastExecution(task with { LastTaskResult = 5 }).Contains("0x00000005"), "failed result hidden by absent last run");
        Assert(WinAcmeScheduledTaskService.DescribeLastExecution(task with { LastTaskResult = 0, LastRunTime = now.AddHours(-1).UtcDateTime }).Contains("不等於"), "process success incorrectly equated to certificate renewal");
        Assert(!WinAcmeScheduledTaskService.EvaluateReadiness(null, executable, now).IsReady, "absent task accepted");

        var valid = MaintenanceStatusService.EvaluateCertificateValidity(now.AddDays(-5), now.AddDays(60), true, now);
        Assert(valid.State == "有效期間內" && valid.DaysRemaining == 60, "healthy certificate classification mismatch");
        Assert(MaintenanceStatusService.EvaluateCertificateValidity(now.AddDays(-5), now.AddDays(30), true, now).State == "即將到期", "30-day boundary missed");
        Assert(MaintenanceStatusService.EvaluateCertificateValidity(now.AddDays(-5), now, true, now).State == "已到期", "expiry boundary missed");
        Assert(MaintenanceStatusService.EvaluateCertificateValidity(now.AddDays(1), now.AddDays(60), true, now).State == "尚未生效", "not-yet-valid certificate accepted");
        Assert(MaintenanceStatusService.EvaluateCertificateValidity(now.AddDays(-5), now.AddDays(60), false, now).State == "缺少私鑰", "missing private-key association accepted");
        Assert(MaintenanceStatusService.EvaluateCertificateValidity(now.AddDays(-5), now.AddMinutes(-1), true, now).DaysRemaining < 0, "expired partial-day displayed as zero remaining");

        bool Ready(WinAcmeScheduledTaskInfo candidate) =>
            WinAcmeScheduledTaskService.EvaluateReadiness(candidate, executable, now).IsReady;
    }

    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
