using Mstech.IisSslManager.Core;
using Mstech.IisSslManager.Models;

public static class SniPreflightTests
{
    public static void Run()
    {
        SnapshotKeepsUnknownDistinctFromDisabled();
        ExistingBindingRequiresSniAndRejectsCcs();
        EveryMatchingBindingMustBeCompatible();
        NewBindingKeepsExplicitConfirmation();
        CrossSiteConflictStillFails();
    }

    private static void SnapshotKeepsUnknownDistinctFromDisabled()
    {
        var site = Site(1, "http/*:80:example.com,https/*:443:example.com,https/[::]:443:other.example.com");
        Assert(site.Bindings.All(binding => binding.SslFlags is null),
            "appcmd list output must not invent disabled SNI for unread flags");

        var enriched = IisDiscoveryService.ApplySslFlagsSnapshot([site],
        [
            new IisBindingSslFlags(1, "HTTPS/*:443:EXAMPLE.COM", 0),
            new IisBindingSslFlags(2, "https/[::]:443:other.example.com", 1)
        ]).Single();
        Assert(enriched.Bindings[0].SslFlags is null, "HTTP binding was given HTTPS flags");
        Assert(enriched.Bindings[1].SslFlags == 0, "confirmed SNI-disabled flags were lost");
        Assert(enriched.Bindings[2].SslFlags is null, "another site's SNI flags were used");
        Assert(site.Bindings.All(binding => binding.SslFlags is null), "original discovery snapshot was mutated");

        var stale = IisDiscoveryService.ApplySslFlagsSnapshot([site],
            [new IisBindingSslFlags(1, "https/192.0.2.1:443:example.com", 1)]).Single();
        Assert(stale.Bindings[1].SslFlags is null, "flags from a different IP binding were accepted");

        AssertThrows(() => IisDiscoveryService.ApplySslFlagsSnapshot([site],
            [new IisBindingSslFlags(1, "https/*:443:example.com", -1)]),
            "negative flags were accepted");
        AssertThrows(() => IisDiscoveryService.ApplySslFlagsSnapshot([site],
        [
            new IisBindingSslFlags(1, "https/*:443:example.com", 1),
            new IisBindingSslFlags(1, "HTTPS/*:443:EXAMPLE.COM", 0)
        ]), "ambiguous duplicate snapshot was accepted");
    }

    private static void ExistingBindingRequiresSniAndRejectsCcs()
    {
        var unknown = Check(BindingSite(null), "存取被拒絕");
        Assert(unknown.Status == CheckStatus.Failed && unknown.IsRequired && !unknown.RequiresUserConfirmation,
            "unknown SslFlags could be acknowledged as a warning");
        Assert(unknown.Details.TryGetValue("ReadError", out var reason) && reason == "存取被拒絕",
            "unknown flag diagnostic was lost");

        var disabled = Check(BindingSite(0));
        Assert(disabled.Status == CheckStatus.Failed && disabled.Summary.Contains("SNI", StringComparison.Ordinal),
            "existing non-SNI binding passed preflight");
        foreach (var flags in new[] { 2, 3, 7 })
        {
            var ccs = Check(BindingSite(flags));
            Assert(ccs.Status == CheckStatus.Failed && ccs.Summary.Contains("CCS", StringComparison.Ordinal),
                $"CCS flags {flags} were not rejected");
        }

        foreach (var flags in new[] { 1, 5 })
        {
            var supported = Check(BindingSite(flags));
            Assert(supported.Status == CheckStatus.Warning && supported.RequiresUserConfirmation,
                $"SNI flags {flags} did not retain the binding-change confirmation gate");
            Assert(supported.Details["Action"] == "Update", "existing SNI binding preview was not Update");
        }
    }

    private static void EveryMatchingBindingMustBeCompatible()
    {
        var site = Site(1, "https/*:443:example.com,https/[::]:443:example.com");
        foreach (int? secondFlags in new int?[] { 0, 3, null })
        {
            var mixed = site with
            {
                Bindings = [site.Bindings[0] with { SslFlags = 1 }, site.Bindings[1] with { SslFlags = secondFlags }]
            };
            Assert(Check(mixed).Status == CheckStatus.Failed,
                "one compatible binding hid an incompatible duplicate host binding");
        }

        var unrelated = Site(1, "https/*:443:example.com,https/*:443:other.example.com");
        unrelated = unrelated with
        {
            Bindings = [unrelated.Bindings[0] with { SslFlags = 1 }, unrelated.Bindings[1] with { SslFlags = 0 }]
        };
        Assert(Check(unrelated).Status == CheckStatus.Warning,
            "an unrelated hostname changed the requested binding's SNI result");
    }

    private static void NewBindingKeepsExplicitConfirmation()
    {
        var result = Check(Site(1, "http/*:80:example.com"));
        Assert(result.Status == CheckStatus.Warning && result.RequiresUserConfirmation,
            "new SNI binding lost its explicit change confirmation");
        Assert(result.Details["Action"] == "Create", "new binding preview was not Create");
    }

    private static void CrossSiteConflictStillFails()
    {
        var selected = BindingSite(1);
        var other = selected with { Id = 2, Name = "Other Site" };
        var inventory = Inventory([selected, other]);
        Assert(ElevatedLocalPreflightService.CheckHttpsBinding("example.com", inventory, selected).Status == CheckStatus.Failed,
            "cross-site duplicate host was accepted");
    }

    private static IisSiteInfo BindingSite(int? flags)
    {
        var site = Site(1, "https/*:443:example.com");
        return site with { Bindings = [site.Bindings.Single() with { SslFlags = flags }] };
    }

    private static IisSiteInfo Site(long id, string bindings) => new()
    {
        Id = id,
        Name = "Test Site",
        State = "Started",
        Bindings = IisDiscoveryService.ParseBindings(bindings)
    };

    private static IisInventory Inventory(IReadOnlyList<IisSiteInfo> sites, string? readError = null) => new()
    {
        IsIisInstalled = true,
        AppCmdPath = "appcmd.exe",
        Sites = sites,
        SslFlagsReadError = readError
    };

    private static PreflightCheckResult Check(IisSiteInfo site, string? readError = null) =>
        ElevatedLocalPreflightService.CheckHttpsBinding("example.com", Inventory([site], readError), site);

    private static void Assert(bool condition, string message)
    {
        if (!condition)
        {
            throw new InvalidOperationException(message);
        }
    }

    private static void AssertThrows(Action action, string message)
    {
        try
        {
            action();
        }
        catch (InvalidDataException)
        {
            return;
        }

        throw new InvalidOperationException(message);
    }
}
