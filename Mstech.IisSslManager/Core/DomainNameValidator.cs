using System.Globalization;

namespace Mstech.IisSslManager.Core;

public static class DomainNameValidator
{
    public static bool TryNormalize(string? value, out string normalized, out string? error)
    {
        normalized = string.Empty;
        error = null;

        if (string.IsNullOrWhiteSpace(value))
        {
            error = "網域名稱不可為空白。";
            return false;
        }

        var candidate = value.Trim().TrimEnd('.');
        if (candidate.StartsWith("*.", StringComparison.Ordinal))
        {
            error = $"{Infrastructure.AppVersion.DisplayVersion} 不支援 Wildcard；請輸入明確的主機名稱。";
            return false;
        }

        if (candidate.Contains("//", StringComparison.Ordinal) ||
            candidate.Contains('/', StringComparison.Ordinal) ||
            candidate.Contains(':', StringComparison.Ordinal))
        {
            error = "請只輸入網域名稱，不要包含 http://、https://、連接埠或路徑。";
            return false;
        }

        try
        {
            normalized = new IdnMapping().GetAscii(candidate).ToLowerInvariant();
        }
        catch (ArgumentException)
        {
            error = "網域名稱包含無法轉換的字元。";
            return false;
        }

        if (Uri.CheckHostName(normalized) != UriHostNameType.Dns)
        {
            error = "網域名稱格式不正確。";
            return false;
        }

        if (normalized.Length > 253)
        {
            error = "網域名稱長度不可超過 253 個字元。";
            return false;
        }

        var labels = normalized.Split('.');
        if (labels.Length < 2)
        {
            error = "Let's Encrypt 必須使用公開完整網域名稱，不能使用單一內部主機名稱。";
            return false;
        }

        if (labels.Any(label =>
                label.Length is < 1 or > 63 ||
                label.StartsWith("-", StringComparison.Ordinal) ||
                label.EndsWith("-", StringComparison.Ordinal)))
        {
            error = "網域標籤長度不正確，或以連字號開頭／結尾。";
            return false;
        }

        if (normalized.EndsWith(".local", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".internal", StringComparison.OrdinalIgnoreCase) ||
            normalized.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            error = "Let's Encrypt 不會為內部使用的網域名稱簽發憑證。";
            return false;
        }

        return true;
    }
}
