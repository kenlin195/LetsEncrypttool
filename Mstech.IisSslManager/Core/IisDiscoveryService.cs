using System.Collections;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using Mstech.IisSslManager.Models;

namespace Mstech.IisSslManager.Core;

public interface IIisDiscoveryService
{
    Task<IisInventory> DiscoverAsync(CancellationToken cancellationToken = default);
}

public sealed partial class IisDiscoveryService(IProcessRunner processRunner) : IIisDiscoveryService
{
    public async Task<IisInventory> DiscoverAsync(CancellationToken cancellationToken = default)
    {
        var appCmdPath = FindAppCmdPath();
        if (appCmdPath is null)
        {
            return new IisInventory
            {
                IsIisInstalled = false,
                AppCmdPath = string.Empty,
                Sites = Array.Empty<IisSiteInfo>(),
                ErrorMessage = "找不到 IIS appcmd.exe，請確認已安裝 IIS 管理工具。"
            };
        }

        var result = await processRunner.RunAsync(
            new ProcessRequest
            {
                FileName = appCmdPath,
                Arguments = ["list", "sites", "/xml"],
                Timeout = TimeSpan.FromSeconds(30),
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            },
            cancellationToken).ConfigureAwait(false);

        if (!result.Succeeded)
        {
            var reason = result.TimedOut
                ? "讀取 IIS 設定逾時。"
                : FirstNonEmpty(result.StandardError, result.ErrorMessage, "appcmd.exe 執行失敗。");

            return new IisInventory
            {
                IsIisInstalled = true,
                AppCmdPath = appCmdPath,
                Sites = Array.Empty<IisSiteInfo>(),
                ErrorMessage = reason
            };
        }

        try
        {
            var sites = ParseSites(result.StandardOutput);
            string? sslFlagsReadError = null;
            if (sites.Any(site => site.Bindings.Any(binding =>
                    binding.Protocol.Equals("https", StringComparison.OrdinalIgnoreCase))))
            {
                cancellationToken.ThrowIfCancellationRequested();
                try
                {
                    sites = ApplySslFlagsSnapshot(sites, ReadSslFlagsSnapshot());
                }
                catch (Exception exception) when (exception is not OperationCanceledException)
                {
                    // Keep ordinary site discovery usable without elevated rights.
                    // Unknown flags remain null and the elevated preflight rejects
                    // any existing target HTTPS binding it cannot verify.
                    sslFlagsReadError = "無法讀取 IIS HTTPS SslFlags：" +
                        (exception.GetBaseException().Message);
                }

                cancellationToken.ThrowIfCancellationRequested();
            }

            return new IisInventory
            {
                IsIisInstalled = true,
                AppCmdPath = appCmdPath,
                Sites = sites,
                ErrorMessage = null,
                SslFlagsReadError = sslFlagsReadError
            };
        }
        catch (XmlException exception)
        {
            return new IisInventory
            {
                IsIisInstalled = true,
                AppCmdPath = appCmdPath,
                Sites = Array.Empty<IisSiteInfo>(),
                ErrorMessage = $"無法解析 IIS 回傳資料：{exception.Message}"
            };
        }
    }

    public static IReadOnlyList<IisSiteInfo> ParseSites(string appCmdXml)
    {
        if (string.IsNullOrWhiteSpace(appCmdXml))
        {
            return Array.Empty<IisSiteInfo>();
        }

        using var stringReader = new StringReader(appCmdXml.TrimStart('\uFEFF', ' ', '\r', '\n', '\t'));
        using var xmlReader = XmlReader.Create(
            stringReader,
            new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null
            });
        var document = XDocument.Load(xmlReader, LoadOptions.None);

        return document
            .Descendants()
            .Where(element => element.Name.LocalName.Equals("SITE", StringComparison.OrdinalIgnoreCase))
            .Select(ParseSite)
            .OrderBy(site => site.Id)
            .ToArray();
    }

    public static IReadOnlyList<IisBindingInfo> ParseBindings(string? rawBindings)
    {
        if (string.IsNullOrWhiteSpace(rawBindings))
        {
            return Array.Empty<IisBindingInfo>();
        }

        var bindings = new List<IisBindingInfo>();
        foreach (var rawBinding in rawBindings.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var slashIndex = rawBinding.IndexOf('/');
            if (slashIndex <= 0 || slashIndex == rawBinding.Length - 1)
            {
                continue;
            }

            var protocol = rawBinding[..slashIndex];
            var bindingInformation = rawBinding[(slashIndex + 1)..];
            var match = BindingInformationPattern().Match(bindingInformation);
            if (!match.Success ||
                !int.TryParse(match.Groups["port"].Value, NumberStyles.None, CultureInfo.InvariantCulture, out var port))
            {
                continue;
            }

            bindings.Add(new IisBindingInfo
            {
                Protocol = protocol,
                IpAddress = match.Groups["ip"].Value,
                Port = port,
                HostName = match.Groups["host"].Value,
                RawValue = rawBinding
            });
        }

        return bindings;
    }

    internal static IReadOnlyList<IisSiteInfo> ApplySslFlagsSnapshot(
        IReadOnlyList<IisSiteInfo> sites,
        IReadOnlyList<IisBindingSslFlags> snapshot)
    {
        var lookup = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var entry in snapshot)
        {
            if (entry.SslFlags < 0 ||
                !lookup.TryAdd(SslFlagsKey(entry.SiteId, entry.RawBinding), entry.SslFlags))
            {
                throw new InvalidDataException("IIS HTTPS SslFlags 快照含無效或重複 Binding。");
            }
        }

        return sites.Select(site => site with
        {
            Bindings = site.Bindings.Select(binding => binding with
            {
                SslFlags = binding.Protocol.Equals("https", StringComparison.OrdinalIgnoreCase) &&
                    lookup.TryGetValue(SslFlagsKey(site.Id, binding.RawValue), out var flags)
                        ? flags
                        : null
            }).ToArray()
        }).ToArray();
    }

    private static IReadOnlyList<IisBindingSslFlags> ReadSslFlagsSnapshot()
    {
        var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var systemFolder = Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess
            ? "Sysnative"
            : "System32";
        var assemblyPath = Path.Combine(
            windowsDirectory, systemFolder, "inetsrv", "Microsoft.Web.Administration.dll");
        if (!File.Exists(assemblyPath))
        {
            throw new FileNotFoundException("找不到 IIS 管理 API，無法確認 SNI／CCS 設定。", assemblyPath);
        }

        var assembly = Assembly.LoadFrom(assemblyPath);
        var serverManagerType = assembly.GetType(
            "Microsoft.Web.Administration.ServerManager", throwOnError: true, ignoreCase: false)!;
        var serverManager = Activator.CreateInstance(serverManagerType)
            ?? throw new InvalidOperationException("無法建立 IIS ServerManager。");
        try
        {
            var sites = GetRequiredProperty(serverManager, "Sites") as IEnumerable
                ?? throw new InvalidOperationException("無法讀取 IIS Sites 集合。");
            var result = new List<IisBindingSslFlags>();
            foreach (var site in sites)
            {
                if (site is null)
                {
                    continue;
                }

                var siteId = Convert.ToInt64(GetRequiredProperty(site, "Id"), CultureInfo.InvariantCulture);
                var bindings = GetRequiredProperty(site, "Bindings") as IEnumerable
                    ?? throw new InvalidOperationException("無法讀取 IIS Bindings 集合。");
                foreach (var binding in bindings)
                {
                    if (binding is null || !string.Equals(
                            Convert.ToString(GetRequiredProperty(binding, "Protocol"), CultureInfo.InvariantCulture),
                            "https", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var information = Convert.ToString(
                        GetRequiredProperty(binding, "BindingInformation"), CultureInfo.InvariantCulture);
                    var parsed = ParseBindings($"https/{information}").SingleOrDefault()
                        ?? throw new InvalidDataException("IIS 管理 API 回傳無效 HTTPS Binding。");
                    var flags = Convert.ToInt32(
                        GetRequiredProperty(binding, "SslFlags"), CultureInfo.InvariantCulture);
                    result.Add(new IisBindingSslFlags(siteId, parsed.RawValue, flags));
                }
            }

            return result;
        }
        finally
        {
            (serverManager as IDisposable)?.Dispose();
        }
    }

    private static object GetRequiredProperty(object instance, string propertyName)
    {
        var property = instance.GetType().GetProperty(propertyName, BindingFlags.Instance | BindingFlags.Public)
            ?? throw new InvalidOperationException($"IIS 管理 API 缺少必要屬性 {propertyName}。");
        return property.GetValue(instance)
            ?? throw new InvalidOperationException($"IIS 管理 API 屬性 {propertyName} 沒有值。");
    }

    private static string SslFlagsKey(long siteId, string rawBinding) =>
        siteId.ToString(CultureInfo.InvariantCulture) + "/" + rawBinding;

    private static IisSiteInfo ParseSite(XElement element)
    {
        var idText = AttributeValue(element, "SITE.ID", "id");
        _ = long.TryParse(idText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var id);

        return new IisSiteInfo
        {
            Id = id,
            Name = AttributeValue(element, "SITE.NAME", "name") ?? string.Empty,
            State = AttributeValue(element, "state") ?? "Unknown",
            Bindings = ParseBindings(AttributeValue(element, "bindings"))
        };
    }

    private static string? AttributeValue(XElement element, params string[] names)
    {
        foreach (var name in names)
        {
            var attribute = element.Attributes().FirstOrDefault(candidate =>
                candidate.Name.LocalName.Equals(name, StringComparison.OrdinalIgnoreCase));
            if (attribute is not null)
            {
                return attribute.Value;
            }
        }

        return null;
    }

    private static string? FindAppCmdPath()
    {
        var windowsDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (string.IsNullOrWhiteSpace(windowsDirectory))
        {
            return null;
        }

        var systemFolder = Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess
            ? "Sysnative"
            : "System32";
        var candidate = Path.Combine(windowsDirectory, systemFolder, "inetsrv", "appcmd.exe");
        return File.Exists(candidate) ? candidate : null;
    }

    private static string FirstNonEmpty(params string?[] values) =>
        values.First(value => !string.IsNullOrWhiteSpace(value))!;

    [GeneratedRegex("^(?<ip>.*):(?<port>[0-9]+):(?<host>.*)$", RegexOptions.CultureInvariant)]
    private static partial Regex BindingInformationPattern();
}

internal sealed record IisBindingSslFlags(long SiteId, string RawBinding, int SslFlags);
