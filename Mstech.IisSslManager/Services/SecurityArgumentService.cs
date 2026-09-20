using System.Security.Principal;
using System.Text;

namespace Mstech.IisSslManager.Services;

public static class SecurityArgumentService
{
    private static readonly HashSet<string> SecretOptions = new(StringComparer.OrdinalIgnoreCase)
    {
        "--password",
        "--pfxpassword",
        "--pempassword",
        "--apikey",
        "--apisecret",
        "--cloudflareapitoken",
        "--digitaloceanapitoken",
        "--azuresecret",
        "--eab-key",
        "--route53secretaccesskey",
        "--tsigkeysecret",
        "--rest-securitytoken"
    };

    public static bool IsCurrentProcessAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            return false;
        }

        using var identity = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static string ToSafeDisplayCommand(
        string executablePath,
        IReadOnlyList<string> arguments)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executablePath);
        ArgumentNullException.ThrowIfNull(arguments);

        var builder = new StringBuilder(QuoteForDisplay(executablePath));
        var maskNext = false;
        foreach (var argument in arguments)
        {
            builder.Append(' ');
            if (maskNext)
            {
                builder.Append("********");
                maskNext = false;
                continue;
            }

            builder.Append(QuoteForDisplay(argument));
            maskNext = SecretOptions.Contains(argument);
        }

        return builder.ToString();
    }

    public static string RedactSecretValues(
        string? text,
        IReadOnlyList<string> arguments)
    {
        var redacted = text ?? string.Empty;
        for (var index = 0; index + 1 < arguments.Count; index++)
        {
            if (!SecretOptions.Contains(arguments[index]))
            {
                continue;
            }

            var secret = arguments[index + 1];
            if (!string.IsNullOrEmpty(secret))
            {
                redacted = redacted.Replace(secret, "********", StringComparison.Ordinal);
            }

            index++;
        }

        return redacted;
    }

    private static string QuoteForDisplay(string value)
    {
        if (value.Length > 0 && value.All(character =>
                !char.IsWhiteSpace(character) && character is not '"' and not '\r' and not '\n'))
        {
            return value;
        }

        // This is only diagnostic rendering. Process execution always uses
        // ProcessStartInfo.ArgumentList and never parses this string again.
        return '"' + value.Replace("\"", "\\\"") + '"';
    }
}
