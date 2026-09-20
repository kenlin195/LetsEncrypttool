using Mstech.IisSslManager.Models;
using Mstech.IisSslManager.ViewModels;

internal static class UiWorkflowTests
{
    public static void Run()
    {
        var warning = new PreflightCheckResult
        {
            Id = "dns-confirm", Phase = PreflightPhase.PublicEnvironment,
            Category = "DNS", Title = "NAT 人工確認", Status = CheckStatus.Warning,
            Summary = "確認 Port 80 轉送。", RequiresUserConfirmation = true,
            DomainName = "example.com"
        };
        var vm = new MainViewModel();
        vm.ReplaceCheckResults([warning]);
        Check(vm.CheckItems[0].StatusText == "需確認", "unconfirmed warning was acknowledged");
        vm.PublicPreflightPassed = true;
        Check(vm.CheckItems[0].StatusText == "已人工確認", "confirmation not shown");
        Check(vm.CheckItems[0].Severity == CheckSeverity.Warning, "warning was converted to a pass");
        Check(!vm.StagingPassed && !vm.RunProductionCommand.CanExecute(null), "warning unlocked production");
        vm.SingleDomain = "changed.example.com";
        Check(vm.CheckItems[0].StatusText == "需確認" && !vm.PublicPreflightPassed, "edited input retained acknowledgement");
        vm.ReplaceCheckResults([warning with { RequiresUserConfirmation = false }]);
        Check(vm.CheckItems[0].StatusText == "提醒", "informational warning asks for confirmation");
        vm.ReplaceCheckResults([warning with { Status = CheckStatus.Failed }]);
        vm.PublicPreflightPassed = true;
        Check(vm.CheckItems[0].StatusText == "未通過", "failed check text was overridden");
        vm.SelectedSite = new IisSiteOptionViewModel { Id = "1", Name = "Site" };
        vm.LocalPreflightPassed = true;
        vm.StagingPassed = true;
        vm.ReplaceSites([new IisSiteOptionViewModel { Id = "1", Name = "Site" }]);
        Check(vm.LocalPreflightPassed && vm.StagingPassed, "refreshing unchanged site invalidates gate");
        vm.SelectedSite = new IisSiteOptionViewModel { Id = "2", Name = "Other" };
        Check(!vm.LocalPreflightPassed && !vm.StagingPassed, "different site retained gate");
        vm.IsBusy = true;
        Check(!vm.RefreshMaintenanceCommand.CanExecute(null), "maintenance refresh can overlap production");
    }

    private static void Check(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
