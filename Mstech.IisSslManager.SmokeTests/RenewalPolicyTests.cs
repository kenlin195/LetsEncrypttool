using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Mstech.IisSslManager.Infrastructure;
using Mstech.IisSslManager.Services;

public static class RenewalPolicyTests
{
    public static void Run()
    {
        var request = Request("example.com", "www.example.com");
        var first = WinAcmeRenewalPolicyService.CreatePreview(request, null);
        Assert(!first.ExistingRenewal && first.AddedHostNames.Count == 2 && first.RemovedHostNames.Count == 0,
            "first issuance preview is incorrect");
        WinAcmeRenewalPolicyService.ValidatePreviewConsent(request, null, first.ExpectedStateSha256, false);
        Reject(() => WinAcmeRenewalPolicyService.ValidatePreviewConsent(request, null, null, false),
            "production accepted a missing preview token");

        var existing = Bytes(Fixture());
        var reducedRequest = Request("example.com", "api.example.com");
        var reduced = WinAcmeRenewalPolicyService.CreatePreview(reducedRequest, existing);
        Assert(reduced.RemovedHostNames.SequenceEqual(new[] { "www.example.com" }) &&
            reduced.AddedHostNames.SequenceEqual(new[] { "api.example.com" }) && reduced.RequiresRemovalConfirmation,
            "SAN replacement preview lost a removed or added name");
        Reject(() => WinAcmeRenewalPolicyService.ValidatePreviewConsent(reducedRequest, existing, reduced.ExpectedStateSha256, false),
            "SAN reduction accepted without explicit acknowledgement");
        WinAcmeRenewalPolicyService.ValidatePreviewConsent(reducedRequest, existing, reduced.ExpectedStateSha256, true);
        Reject(() => WinAcmeRenewalPolicyService.ValidatePreviewConsent(reducedRequest,
            Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(existing) + " "), reduced.ExpectedStateSha256, true),
            "changed renewal bytes accepted after preview");
        Reject(() => WinAcmeRenewalPolicyService.ValidatePreviewConsent(request, existing, first.ExpectedStateSha256, true),
            "new renewal appearing after first-issuance preview was accepted");
        Reject(() => WinAcmeRenewalPolicyService.CreatePreview(request, Encoding.UTF8.GetBytes("{")),
            "invalid JSON accepted for preview");
        Reject(() => WinAcmeRenewalPolicyService.CreatePreview(request,
            Encoding.UTF8.GetBytes("{\"Id\":\"one\",\"Id\":\"two\"}")), "duplicate JSON properties accepted");
        Reject(() => WinAcmeRenewalPolicyService.CreatePreview(request with { SiteId = 8 }, existing),
            "preview accepted a different site's renewal");

        // Fixture follows the pinned source's serialized options. DefaultAsNull omits
        // the store name, binding IP and port; these valid defaults must keep working.
        WinAcmeRenewalPolicyService.VerifyCommittedContent(existing, request, "WebHosting");
        var nullDefaults = Fixture();
        nullDefaults["StorePluginOptions"]![0]!["StoreName"] = null;
        nullDefaults["InstallationPluginOptions"]![0]!["NewBindingPort"] = null;
        nullDefaults["InstallationPluginOptions"]![0]!["NewBindingIp"] = null;
        WinAcmeRenewalPolicyService.VerifyCommittedContent(Bytes(nullDefaults), request, "WebHosting");
        var explicitDefaults = Fixture();
        explicitDefaults["StorePluginOptions"]![0]!["StoreName"] = "WebHosting";
        explicitDefaults["InstallationPluginOptions"]![0]!["NewBindingPort"] = 443;
        explicitDefaults["InstallationPluginOptions"]![0]!["NewBindingIp"] = "*";
        WinAcmeRenewalPolicyService.VerifyCommittedContent(Bytes(explicitDefaults), request, "My");
        Reject(() => WinAcmeRenewalPolicyService.VerifyCommittedContent(existing, request, "My"),
            "implicit store accepted when effective default is My");

        RejectPolicy(request, json => json["TargetPluginOptions"]!["AlternativeNames"] = new JsonArray("example.com"), "missing SAN");
        RejectPolicy(request, json => json["TargetPluginOptions"]!["CommonName"] = "www.example.com", "wrong CommonName");
        RejectPolicy(request, json => json["ValidationPluginOptions"]!["Plugin"] = "dns-01", "wrong validation plugin");
        RejectPolicy(request, json => json["ValidationPluginOptions"]!["Port"] = 8080, "wrong validation port");
        RejectPolicy(request, json => json["ValidationPluginOptions"]!["Https"] = true, "HTTPS validation override");
        RejectPolicy(request, json => json["CsrPluginOptions"]!["Plugin"] = "ec", "wrong CSR");
        RejectPolicy(request, json => json["OrderPluginOptions"]!["Plugin"] = "split", "wrong order plugin");
        RejectPolicy(request, json => json["StorePluginOptions"]![0]!["KeepExisting"] = false, "old-certificate deletion");
        RejectPolicy(request, json => json["StorePluginOptions"]![0]!["StoreName"] = "My", "wrong certificate store");
        RejectPolicy(request, json => json["StorePluginOptions"]![0]!["AclRead"] = new JsonArray("Everyone"), "extra private-key permissions");
        RejectPolicy(request, json => json["InstallationPluginOptions"]![0]!["SiteId"] = 8, "wrong IIS site");
        RejectPolicy(request, json => json["InstallationPluginOptions"]![0]!["NewBindingPort"] = 8443, "wrong IIS port");
        RejectPolicy(request, json => json["InstallationPluginOptions"]![1]!["Script"] = "C:\\other.ps1", "different retention script");
        RejectPolicy(request, json => json["InstallationPluginOptions"]![1]!["ScriptParameters"] = "-Cleanup", "different retention arguments");
        RejectPolicy(request, json => json["InstallationPluginOptions"]!.AsArray().RemoveAt(1), "missing retention step");
        RejectPolicy(request, json => json["InstallationPluginOptions"]!.AsArray().Add(json["InstallationPluginOptions"]![1]!.DeepClone()), "extra installation step");
    }

    private static WinAcmeCertificateRequest Request(params string[] names) => new()
    {
        SiteId = 7,
        HostNames = names,
        CommonName = "example.com",
        ContactEmail = "admin@example.com"
    };

    private static JsonObject Fixture()
    {
        var json = JsonNode.Parse("""
            {
              "Id": "mstech-iis-site-7",
              "TargetPluginOptions": {
                "Plugin": "e239db3b-b42f-48aa-b64f-46d4f3e9941b",
                "CommonName": "example.com",
                "AlternativeNames": ["example.com", "www.example.com"]
              },
              "ValidationPluginOptions": {"Plugin": "c7d5e050-9363-4ba1-b3a8-931b31c618b7"},
              "CsrPluginOptions": {"Plugin": "b9060d4b-c2d3-49ac-b37f-962e7c3cbe9d"},
              "OrderPluginOptions": {"Plugin": "b705fa7c-1152-4436-8913-e433d7f84c82"},
              "StorePluginOptions": [{"Plugin": "e30adc8e-d756-4e16-a6f2-450f784b1a97", "KeepExisting": true}],
              "InstallationPluginOptions": [
                {"Plugin": "ea6a5be3-f8de-4d27-a6bd-750b619b2ee2", "SiteId": 7},
                {"Plugin": "3bb22c70-358d-4251-86bd-11858363d913"}
              ]
            }
            """)!.AsObject();
        json["InstallationPluginOptions"]![1]!["Script"] = Path.Combine(AppPaths.ProgramDataRoot, "Scripts", "CertificateRetention.ps1");
        json["InstallationPluginOptions"]![1]!["ScriptParameters"] =
            "-OldThumbprint \"{OldCertThumbprint}\" -NewThumbprint \"{CertThumbprint}\" -RetentionDays 30";
        return json;
    }

    private static byte[] Bytes(JsonObject json) => JsonSerializer.SerializeToUtf8Bytes(json);
    private static void RejectPolicy(WinAcmeCertificateRequest request, Action<JsonObject> mutate, string scenario)
    {
        var json = Fixture();
        mutate(json);
        Reject(() => WinAcmeRenewalPolicyService.VerifyCommittedContent(Bytes(json), request, "WebHosting"), scenario + " was accepted");
    }
    private static void Reject(Action action, string message)
    {
        try { action(); }
        catch (InvalidDataException) { return; }
        throw new InvalidOperationException(message);
    }
    private static void Assert(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }
}
