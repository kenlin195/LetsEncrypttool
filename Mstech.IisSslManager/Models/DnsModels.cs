using System.Net;

namespace Mstech.IisSslManager.Models;

public enum DnsRecordType : ushort
{
    A = 1,
    CName = 5,
    Aaaa = 28,
    Caa = 257
}

public enum DnsResponseCode
{
    NoError = 0,
    FormatError = 1,
    ServerFailure = 2,
    NameError = 3,
    NotImplemented = 4,
    Refused = 5,
    Unknown = 255
}

public sealed record DnsRecord
{
    public required string Name { get; init; }

    public required DnsRecordType Type { get; init; }

    public required TimeSpan TimeToLive { get; init; }

    public IPAddress? Address { get; init; }

    public string? CanonicalName { get; init; }

    public byte? CaaFlags { get; init; }

    public string? CaaTag { get; init; }

    public string? CaaValue { get; init; }
}

public sealed record DnsLookupResult
{
    public required string QueryName { get; init; }

    public required DnsRecordType QueryType { get; init; }

    public required IPAddress Resolver { get; init; }

    public required DnsResponseCode ResponseCode { get; init; }

    public required IReadOnlyList<DnsRecord> Records { get; init; }

    public string? ErrorMessage { get; init; }

    public bool Succeeded => ErrorMessage is null && ResponseCode == DnsResponseCode.NoError;
}

public sealed record EffectiveCaaResult
{
    public required string RequestedName { get; init; }

    public string? RecordOwnerName { get; init; }

    public required IReadOnlyList<DnsRecord> Records { get; init; }

    public required IPAddress Resolver { get; init; }

    public string? ErrorMessage { get; init; }

    public bool IsTransportFailure { get; init; }
}
