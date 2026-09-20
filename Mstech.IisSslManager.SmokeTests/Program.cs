using Mstech.IisSslManager.Core;
using Mstech.IisSslManager.Infrastructure;
using Mstech.IisSslManager.Services;
using System.Security.AccessControl;
using System.Text;
using System.Text.Json;

var tests = new List<(string Name, Action Run)>
{
    ("DNS normalization", TestDnsNormalization),
    ("DNS rejection", TestDnsRejection),
    ("IIS binding parser", TestBindingParser),
    ("IIS site XML parser", TestSiteParser),
    ("Staging command safety", TestStagingCommand),
    ("Production command policy", TestProductionCommand),
    ("Secret masking", TestSecretMasking),
    ("Authenticated elevated result", TestAuthenticatedElevatedResult),
    ("Secure staging directory", TestSecureStagingDirectory),
    ("Process completion output marker", TestProcessCompletionOutputMarker),
    ("Renewal task action allow-list", TestRenewalTaskActionAllowList),
    ("Retention script encoding and HTTP.sys", TestRetentionChecksHttpSys),
    ("IIS SNI and CCS preflight", SniPreflightTests.Run),
    ("Renewal preview and schema policy", RenewalPolicyTests.Run),
    ("Renewal task readiness and certificate health", Mstech.IisSslManager.SmokeTests.MaintenanceStatusTests.Run),
    ("Warning acknowledgement and gate invalidation", UiWorkflowTests.Run),
    ("Application version", TestApplicationVersion),
    ("Offline WPF layout and binding", WpfLayoutTests.Run)
};

var failures = new List<string>();
foreach (var test in tests)
{
    try
    {
        test.Run();
        Console.WriteLine($"PASS {test.Name}");
    }
    catch (Exception exception)
    {
        failures.Add($"{test.Name}: {exception.Message}");
        Console.WriteLine($"FAIL {test.Name}: {exception.Message}");
    }
}

Console.WriteLine($"{tests.Count - failures.Count}/{tests.Count} smoke tests passed.");
return failures.Count == 0 ? 0 : 1;

static void TestDnsNormalization()
{
    Assert(DomainNameValidator.TryNormalize("WWW.Example.COM.", out var value, out _), "valid host rejected");
    Assert(value == "www.example.com", $"unexpected normalized value: {value}");
}

static void TestDnsRejection()
{
    Assert(!DomainNameValidator.TryNormalize("*.example.com", out _, out _), "wildcard accepted");
    Assert(!DomainNameValidator.TryNormalize("https://example.com/path", out _, out _), "URL accepted");
    Assert(!DomainNameValidator.TryNormalize("localhost", out _, out _), "single-label host accepted");
}

static void TestBindingParser()
{
    var bindings = IisDiscoveryService.ParseBindings(
        "http/*:80:example.com, https/[::]:443:www.example.com");
    Assert(bindings.Count == 2, $"expected 2 bindings, got {bindings.Count}");
    Assert(bindings[0].Port == 80 && bindings[0].HostName == "example.com", "HTTP binding mismatch");
    Assert(bindings[1].Port == 443 && bindings[1].HostName == "www.example.com", "HTTPS binding mismatch");
}

static void TestSiteParser()
{
    const string xml = "<appcmd><SITE SITE.NAME=\"Default Web Site\" SITE.ID=\"1\" bindings=\"http/*:80:example.com,https/*:443:example.com\" state=\"Started\" /></appcmd>";
    var sites = IisDiscoveryService.ParseSites(xml);
    Assert(sites.Count == 1, "site count mismatch");
    Assert(sites[0].Id == 1 && sites[0].IsStarted && sites[0].Bindings.Count == 2, "site values mismatch");
}

static void TestStagingCommand()
{
    var command = new WinAcmeCommandBuilder().BuildStagingValidation(Request());
    Assert(command.UsesStagingEnvironment, "staging flag missing");
    Assert(!command.ChangesIisBindings, "staging can change IIS");
    Assert(HasPair(command.Arguments, "--source", "manual"), "manual source missing");
    Assert(HasPair(command.Arguments, "--store", "pfxfile"), "temporary PFX store missing");
    Assert(HasPair(command.Arguments, "--installation", "none"), "installation none missing");
    Assert(command.Arguments.Contains("--notaskscheduler"), "notaskscheduler missing");
    Assert(command.Arguments.Contains("--test"), "test endpoint missing");
    Assert(
        command.CompletionOutputMarker == WinAcmeRecommendedRelease.StagingCompletionOutputMarker,
        "pinned test-mode completion marker missing");
    Assert(!command.Arguments.Contains("certificatestore"), "certificate store present in staging");
    Assert(command.TemporaryDirectoriesToDelete.Count == 1, "temporary cleanup directory missing");

    var passwordIndex = command.Arguments.ToList().FindIndex(item => item == "--pfxpassword");
    Assert(passwordIndex >= 0, "PFX password option missing");
    var password = command.Arguments[passwordIndex + 1];
    var safe = SecurityArgumentService.ToSafeDisplayCommand("wacs.exe", command.Arguments);
    Assert(!safe.Contains(password, StringComparison.Ordinal), "PFX password leaked into safe command");
}

static void TestProductionCommand()
{
    var command = new WinAcmeCommandBuilder().BuildProductionIssuance(
        Request(),
        @"C:\ProgramData\MSTECH\IisSslManager\Scripts\CertificateRetention.ps1");
    Assert(!command.UsesStagingEnvironment, "production marked staging");
    Assert(command.ChangesIisBindings, "production not marked as IIS-changing");
    Assert(HasPair(command.Arguments, "--source", "manual"), "manual source missing");
    Assert(HasPair(command.Arguments, "--installation", "iis,script"), "IIS + retention installation missing");
    Assert(HasPair(command.Arguments, "--certificatestore", "WebHosting"), "WebHosting store missing");
    Assert(HasPair(command.Arguments, "--installationsiteid", "1"), "installation site missing");
    Assert(HasPair(command.Arguments, "--id", "mstech-iis-site-1"), "deterministic renewal id missing");
    Assert(
        HasPair(command.Arguments, "--baseuri", WinAcmeRecommendedRelease.ProductionBaseUri),
        "pinned production base URI missing");
    Assert(command.Arguments.Contains("--nocache"), "nocache policy missing");
    Assert(command.Arguments.Contains("--notaskscheduler"), "deferred task scheduler policy missing");
    Assert(command.Arguments.Contains("--keepexisting"), "old-certificate retention flag missing");
    Assert(!command.Arguments.Contains("--test"), "production accidentally uses staging");
    Assert(command.CompletionOutputMarker is null, "production has a stdout completion bypass");
}

static void TestSecretMasking()
{
    var safe = SecurityArgumentService.ToSafeDisplayCommand(
        "wacs.exe",
        ["--pfxpassword", "top-secret", "--emailaddress", "admin@example.com"]);
    Assert(!safe.Contains("top-secret", StringComparison.Ordinal), "secret was not masked");
    Assert(safe.Contains("admin@example.com", StringComparison.Ordinal), "ordinary argument unexpectedly masked");

    var output = SecurityArgumentService.RedactSecretValues(
        "win-acme diagnostic: top-secret",
        ["--pfxpassword", "top-secret"]);
    Assert(!output.Contains("top-secret", StringComparison.Ordinal), "secret leaked through process output");
}

static void TestAuthenticatedElevatedResult()
{
    var key = Convert.ToHexString(Enumerable.Range(0, 32).Select(value => (byte)value).ToArray());
    var result = new ElevatedWorkerResult
    {
        Success = true,
        ExitCode = 0,
        PayloadJson = "{}"
    };
    var envelope = ElevationService.CreateAuthenticatedResultEnvelope(result, key);
    var parsed = ElevationService.ParseAuthenticatedResultEnvelope(envelope, key);
    Assert(parsed.Success && parsed.ExitCode == 0, "authenticated result did not round-trip");

    var envelopeModel = JsonSerializer.Deserialize<AuthenticatedElevatedWorkerResult>(envelope)
        ?? throw new InvalidOperationException("authenticated result envelope was empty");
    var alteredResult = envelopeModel.ResultJson.Replace(
        "\"Success\":true",
        "\"Success\":false",
        StringComparison.Ordinal);
    Assert(alteredResult != envelopeModel.ResultJson, "test could not alter the result payload");
    var tampered = JsonSerializer.Serialize(envelopeModel with { ResultJson = alteredResult });
    AssertThrows<InvalidDataException>(
        () => ElevationService.ParseAuthenticatedResultEnvelope(tampered, key),
        "tampered elevated result was accepted");
}

static void TestSecureStagingDirectory()
{
    Assert(
        !ProgramDataSecurity.GrantsDangerousWriteAccess(
            FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize),
        "Users read-and-execute ACL was incorrectly treated as writable");
    Assert(
        ProgramDataSecurity.GrantsDangerousWriteAccess(FileSystemRights.Write),
        "Users write ACL was not rejected");
    Assert(
        ProgramDataSecurity.GrantsDangerousWriteAccess(FileSystemRights.Modify),
        "Users modify ACL was not rejected");
    Assert(
        ProgramDataSecurity.GrantsDangerousWriteAccess(FileSystemRights.FullControl),
        "Users full-control ACL was not rejected");

    var command = new WinAcmeCommandBuilder().BuildStagingValidation(Request());
    var directory = Path.GetFullPath(command.TemporaryDirectoriesToDelete.Single());
    var expectedParent = Path.GetFullPath(AppPaths.SecureStagingDirectory)
        .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
    Assert(
        string.Equals(Path.GetDirectoryName(directory), expectedParent, StringComparison.OrdinalIgnoreCase),
        "staging PFX directory is not a direct child of protected ProgramData");
    Assert(Guid.TryParseExact(Path.GetFileName(directory), "N", out _), "staging directory is not random");
}

static void TestRenewalTaskActionAllowList()
{
    var executable = Path.Combine(AppPaths.WinAcmeDirectory, "wacs.exe");
    var task = new WinAcmeScheduledTaskInfo
    {
        Name = WinAcmeRecommendedRelease.ManagedClientName + " renew (acme-v02.api.letsencrypt.org)",
        ExecutablePath = executable,
        Arguments = "--renew --baseuri https://acme-v02.api.letsencrypt.org/",
        ActionCount = 1
    };
    Assert(
        WinAcmeScheduledTaskService.IsExpectedRenewalTask(task, Path.GetFullPath(executable)),
        "expected single-action renewal task was rejected");
    Assert(
        !WinAcmeScheduledTaskService.IsExpectedRenewalTask(task with { ActionCount = 2 }, Path.GetFullPath(executable)),
        "renewal task with an extra action was accepted");
}

static void TestProcessCompletionOutputMarker()
{
    const string marker = "MSTECH-PROCESS-MARKER";
    var powershell = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.System),
        @"WindowsPowerShell\v1.0\powershell.exe");
    var result = new ProcessRunner().RunAsync(new Mstech.IisSslManager.Models.ProcessRequest
    {
        FileName = powershell,
        Arguments =
        [
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            $"[Console]::Out.Write('{marker}'); [Console]::Out.Flush(); Start-Sleep -Seconds 30"
        ],
        Timeout = TimeSpan.FromSeconds(10),
        CompletionOutputMarker = marker,
        CreateNoWindow = true
    }).GetAwaiter().GetResult();

    Assert(result.Succeeded, result.ErrorMessage ?? "completion marker did not succeed");
    Assert(result.CompletedByOutputMarker, "process was not completed by the output marker");
    Assert(result.StandardOutput.Contains(marker, StringComparison.Ordinal), "marker output was not captured");
    Assert(result.Duration < TimeSpan.FromSeconds(10), "marker did not stop the waiting process promptly");
}

static void TestRetentionChecksHttpSys()
{
    var assembly = typeof(CertificateRetentionService).Assembly;
    var resource = assembly.GetManifestResourceNames()
        .Single(name => name.EndsWith(".Scripts.CertificateRetention.ps1", StringComparison.Ordinal));
    using var stream = assembly.GetManifestResourceStream(resource)
        ?? throw new InvalidOperationException("retention resource missing");
    using var buffer = new MemoryStream();
    stream.CopyTo(buffer);
    var scriptBytes = buffer.ToArray();
    var utf8Preamble = Encoding.UTF8.GetPreamble();
    Assert(
        scriptBytes.AsSpan().StartsWith(utf8Preamble),
        "retention resource must retain a UTF-8 BOM for Windows PowerShell 5.1");
    var script = new UTF8Encoding(
        encoderShouldEmitUTF8Identifier: false,
        throwOnInvalidBytes: true).GetString(scriptBytes.AsSpan(utf8Preamble.Length));
    Assert(script.Contains("http show sslcert", StringComparison.Ordinal), "HTTP.sys usage check missing");
    Assert(script.Contains("$LASTEXITCODE -ne 0", StringComparison.Ordinal), "netsh fail-closed check missing");
}

static void TestApplicationVersion()
{
    Assert(AppVersion.DisplayVersion == "v1.3", "display version mismatch");
    Assert(AppVersion.SemanticVersion == "1.3.0", "semantic version mismatch");
    Assert(AppVersion.FileVersion == "1.3.0.0", "file version label mismatch");
    Assert(AppVersion.ArtifactVersion == "v1.3", "artifact version mismatch");
    Assert(typeof(AppVersion).Assembly.GetName().Version?.ToString() == "1.3.0.0", "assembly version mismatch");
}

static WinAcmeCertificateRequest Request() => new()
{
    SiteId = 1,
    HostNames = ["example.com", "www.example.com"],
    CommonName = "example.com",
    ContactEmail = "admin@example.com"
};

static bool HasPair(IReadOnlyList<string> arguments, string option, string value)
{
    for (var index = 0; index + 1 < arguments.Count; index++)
    {
        if (arguments[index] == option && arguments[index + 1] == value)
        {
            return true;
        }
    }

    return false;
}

static void Assert(bool condition, string message)
{
    if (!condition)
    {
        throw new InvalidOperationException(message);
    }
}

static void AssertThrows<TException>(Action action, string message) where TException : Exception
{
    try
    {
        action();
    }
    catch (TException)
    {
        return;
    }

    throw new InvalidOperationException(message);
}
