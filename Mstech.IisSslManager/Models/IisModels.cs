namespace Mstech.IisSslManager.Models;

public sealed record IisBindingInfo
{
    public required string Protocol { get; init; }

    public required string IpAddress { get; init; }

    public required int Port { get; init; }

    public required string HostName { get; init; }

    public required string RawValue { get; init; }

    // null means the IIS management API could not confirm this binding's flags.
    // An HTTPS host name alone does not prove that SNI is enabled.
    public int? SslFlags { get; init; }

    public bool UsesSniCandidate =>
        Protocol.Equals("https", StringComparison.OrdinalIgnoreCase) &&
        !string.IsNullOrWhiteSpace(HostName);
}

public sealed record IisSiteInfo
{
    public required long Id { get; init; }

    public required string Name { get; init; }

    public required string State { get; init; }

    public required IReadOnlyList<IisBindingInfo> Bindings { get; init; }

    public bool IsStarted => State.Equals("Started", StringComparison.OrdinalIgnoreCase);
}

public sealed record IisInventory
{
    public required bool IsIisInstalled { get; init; }

    public required string AppCmdPath { get; init; }

    public required IReadOnlyList<IisSiteInfo> Sites { get; init; }

    public string? ErrorMessage { get; init; }

    public string? SslFlagsReadError { get; init; }
}
