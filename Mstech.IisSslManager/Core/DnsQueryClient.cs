using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Mstech.IisSslManager.Models;

namespace Mstech.IisSslManager.Core;

public interface IDnsQueryClient
{
    Task<DnsLookupResult> QueryAsync(
        string name,
        DnsRecordType type,
        TimeSpan timeout,
        CancellationToken cancellationToken = default);

    Task<EffectiveCaaResult> QueryEffectiveCaaAsync(
        string name,
        TimeSpan timeout,
        CancellationToken cancellationToken = default);
}

/// <summary>
/// Minimal DNS client used to query public recursive resolvers without depending on
/// localized command output or an external NuGet package.
/// </summary>
public sealed class DnsQueryClient : IDnsQueryClient
{
    private const int DnsPort = 53;
    private const int HeaderLength = 12;
    private const ushort InternetClass = 1;

    private readonly IReadOnlyList<IPAddress> _resolvers;

    public DnsQueryClient(IEnumerable<IPAddress>? resolvers = null)
    {
        _resolvers = (resolvers ?? DefaultResolvers)
            .Where(address => address.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
            .Distinct()
            .ToArray();

        if (_resolvers.Count == 0)
        {
            throw new ArgumentException("At least one DNS resolver is required.", nameof(resolvers));
        }
    }

    public static IReadOnlyList<IPAddress> DefaultResolvers { get; } =
    [
        IPAddress.Parse("1.1.1.1"),
        IPAddress.Parse("8.8.8.8")
    ];

    public async Task<DnsLookupResult> QueryAsync(
        string name,
        DnsRecordType type,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        if (!DomainNameValidator.TryNormalize(name, out var normalized, out var validationError))
        {
            return FailedLookup(name, type, _resolvers[0], validationError!);
        }

        Exception? lastError = null;
        foreach (var resolver in _resolvers)
        {
            cancellationToken.ThrowIfCancellationRequested();

            try
            {
                using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                timeoutSource.CancelAfter(timeout);
                var query = CreateQuery(normalized, type, out var transactionId);
                var response = await QueryUdpAsync(query, resolver, timeoutSource.Token).ConfigureAwait(false);

                if (IsTruncated(response))
                {
                    response = await QueryTcpAsync(query, resolver, timeoutSource.Token).ConfigureAwait(false);
                }

                return ParseResponse(response, normalized, type, resolver, transactionId);
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                lastError = new TimeoutException($"DNS resolver {resolver} did not respond in time.");
            }
            catch (Exception exception) when (
                exception is SocketException or IOException or InvalidDataException)
            {
                lastError = exception;
            }
        }

        return FailedLookup(
            normalized,
            type,
            _resolvers[^1],
            lastError?.Message ?? "All configured public DNS resolvers failed.");
    }

    public async Task<EffectiveCaaResult> QueryEffectiveCaaAsync(
        string name,
        TimeSpan timeout,
        CancellationToken cancellationToken = default)
    {
        if (!DomainNameValidator.TryNormalize(name, out var normalized, out var validationError))
        {
            return new EffectiveCaaResult
            {
                RequestedName = name,
                Records = Array.Empty<DnsRecord>(),
                Resolver = _resolvers[0],
                ErrorMessage = validationError
            };
        }

        var labels = normalized.Split('.');
        DnsLookupResult? lastResult = null;

        // CAA processing walks from the requested name toward its parent. The final
        // top-level label is not queried because it cannot be an effective registrable
        // parent for the requested host.
        for (var index = 0; index < labels.Length - 1; index++)
        {
            var candidate = string.Join('.', labels[index..]);
            var result = await QueryAsync(candidate, DnsRecordType.Caa, timeout, cancellationToken)
                .ConfigureAwait(false);
            lastResult = result;

            if (result.ResponseCode == DnsResponseCode.Unknown && result.ErrorMessage is not null)
            {
                return new EffectiveCaaResult
                {
                    RequestedName = normalized,
                    Records = Array.Empty<DnsRecord>(),
                    Resolver = result.Resolver,
                    ErrorMessage = result.ErrorMessage,
                    IsTransportFailure = true
                };
            }

            if (result.ResponseCode == DnsResponseCode.ServerFailure ||
                result.ResponseCode == DnsResponseCode.Refused ||
                result.ResponseCode == DnsResponseCode.FormatError)
            {
                return new EffectiveCaaResult
                {
                    RequestedName = normalized,
                    Records = Array.Empty<DnsRecord>(),
                    Resolver = result.Resolver,
                    ErrorMessage = result.ErrorMessage ?? $"CAA 查詢失敗：{result.ResponseCode}",
                    IsTransportFailure = false
                };
            }

            var caaRecords = result.Records
                .Where(record => record.Type == DnsRecordType.Caa)
                .ToArray();
            if (caaRecords.Length > 0)
            {
                return new EffectiveCaaResult
                {
                    RequestedName = normalized,
                    RecordOwnerName = candidate,
                    Records = caaRecords,
                    Resolver = result.Resolver
                };
            }
        }

        return new EffectiveCaaResult
        {
            RequestedName = normalized,
            Records = Array.Empty<DnsRecord>(),
            Resolver = lastResult?.Resolver ?? _resolvers[0],
            ErrorMessage = lastResult?.ErrorMessage,
            IsTransportFailure = lastResult?.ResponseCode == DnsResponseCode.Unknown
        };
    }

    private static async Task<byte[]> QueryUdpAsync(
        byte[] query,
        IPAddress resolver,
        CancellationToken cancellationToken)
    {
        using var client = new UdpClient(resolver.AddressFamily);
        client.Connect(resolver, DnsPort);
        await client.SendAsync(query, cancellationToken).ConfigureAwait(false);
        var response = await client.ReceiveAsync(cancellationToken).ConfigureAwait(false);
        return response.Buffer;
    }

    private static async Task<byte[]> QueryTcpAsync(
        byte[] query,
        IPAddress resolver,
        CancellationToken cancellationToken)
    {
        using var client = new TcpClient(resolver.AddressFamily);
        await client.ConnectAsync(resolver, DnsPort, cancellationToken).ConfigureAwait(false);
        await using var stream = client.GetStream();

        var framedQuery = new byte[query.Length + 2];
        BinaryPrimitives.WriteUInt16BigEndian(framedQuery, checked((ushort)query.Length));
        query.CopyTo(framedQuery, 2);
        await stream.WriteAsync(framedQuery, cancellationToken).ConfigureAwait(false);

        var lengthBytes = new byte[2];
        await ReadExactlyAsync(stream, lengthBytes, cancellationToken).ConfigureAwait(false);
        var responseLength = BinaryPrimitives.ReadUInt16BigEndian(lengthBytes);
        var response = new byte[responseLength];
        await ReadExactlyAsync(stream, response, cancellationToken).ConfigureAwait(false);
        return response;
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer[read..], cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                throw new EndOfStreamException("DNS TCP response ended unexpectedly.");
            }

            read += count;
        }
    }

    private static byte[] CreateQuery(string name, DnsRecordType type, out ushort transactionId)
    {
        transactionId = checked((ushort)RandomNumberGenerator.GetInt32(ushort.MaxValue + 1));
        using var stream = new MemoryStream();

        WriteUInt16(stream, transactionId);
        WriteUInt16(stream, 0x0100); // Recursion desired.
        WriteUInt16(stream, 1);      // QDCOUNT.
        WriteUInt16(stream, 0);
        WriteUInt16(stream, 0);
        WriteUInt16(stream, 0);

        foreach (var label in name.Split('.'))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            stream.WriteByte(checked((byte)bytes.Length));
            stream.Write(bytes);
        }

        stream.WriteByte(0);
        WriteUInt16(stream, (ushort)type);
        WriteUInt16(stream, InternetClass);
        return stream.ToArray();
    }

    private static DnsLookupResult ParseResponse(
        byte[] response,
        string queryName,
        DnsRecordType queryType,
        IPAddress resolver,
        ushort expectedTransactionId)
    {
        if (response.Length < HeaderLength)
        {
            throw new InvalidDataException("DNS response is shorter than its header.");
        }

        var transactionId = ReadUInt16(response, 0);
        if (transactionId != expectedTransactionId)
        {
            throw new InvalidDataException("DNS response transaction ID does not match the query.");
        }

        var flags = ReadUInt16(response, 2);
        if ((flags & 0x8000) == 0)
        {
            throw new InvalidDataException("DNS packet is not a response.");
        }

        var responseCodeValue = flags & 0x000F;
        var responseCode = Enum.IsDefined(typeof(DnsResponseCode), (int)responseCodeValue)
            ? (DnsResponseCode)responseCodeValue
            : DnsResponseCode.Unknown;
        var questionCount = ReadUInt16(response, 4);
        var answerCount = ReadUInt16(response, 6);
        var authorityCount = ReadUInt16(response, 8);
        var additionalCount = ReadUInt16(response, 10);
        var offset = HeaderLength;

        for (var index = 0; index < questionCount; index++)
        {
            _ = ReadName(response, ref offset);
            EnsureAvailable(response, offset, 4);
            offset += 4;
        }

        var records = new List<DnsRecord>();
        var recordCount = answerCount + authorityCount + additionalCount;
        for (var index = 0; index < recordCount; index++)
        {
            var ownerName = ReadName(response, ref offset);
            EnsureAvailable(response, offset, 10);
            var typeValue = ReadUInt16(response, offset);
            var recordClass = ReadUInt16(response, offset + 2);
            var ttl = ReadUInt32(response, offset + 4);
            var dataLength = ReadUInt16(response, offset + 8);
            offset += 10;
            EnsureAvailable(response, offset, dataLength);
            var dataOffset = offset;

            if (recordClass == InternetClass && Enum.IsDefined(typeof(DnsRecordType), typeValue))
            {
                var parsed = ParseRecord(
                    response,
                    dataOffset,
                    dataLength,
                    ownerName,
                    (DnsRecordType)typeValue,
                    ttl);
                if (parsed is not null)
                {
                    records.Add(parsed);
                }
            }

            offset = dataOffset + dataLength;
        }

        return new DnsLookupResult
        {
            QueryName = queryName,
            QueryType = queryType,
            Resolver = resolver,
            ResponseCode = responseCode,
            Records = records,
            ErrorMessage = responseCode switch
            {
                DnsResponseCode.NoError => null,
                DnsResponseCode.NameError => "公開 DNS 回覆 NXDOMAIN（網域不存在）。",
                DnsResponseCode.ServerFailure => "公開 DNS 回覆 SERVFAIL；請檢查 DNSSEC 或權威 DNS。",
                _ => $"公開 DNS 回覆錯誤：{responseCode}。"
            }
        };
    }

    private static DnsRecord? ParseRecord(
        byte[] response,
        int dataOffset,
        int dataLength,
        string ownerName,
        DnsRecordType type,
        uint ttl)
    {
        var timeToLive = TimeSpan.FromSeconds(ttl);
        switch (type)
        {
            case DnsRecordType.A when dataLength == 4:
                return new DnsRecord
                {
                    Name = ownerName,
                    Type = type,
                    TimeToLive = timeToLive,
                    Address = new IPAddress(response.AsSpan(dataOffset, dataLength))
                };

            case DnsRecordType.Aaaa when dataLength == 16:
                return new DnsRecord
                {
                    Name = ownerName,
                    Type = type,
                    TimeToLive = timeToLive,
                    Address = new IPAddress(response.AsSpan(dataOffset, dataLength))
                };

            case DnsRecordType.CName:
                var nameOffset = dataOffset;
                return new DnsRecord
                {
                    Name = ownerName,
                    Type = type,
                    TimeToLive = timeToLive,
                    CanonicalName = ReadName(response, ref nameOffset)
                };

            case DnsRecordType.Caa when dataLength >= 2:
                var flags = response[dataOffset];
                var tagLength = response[dataOffset + 1];
                if (tagLength > dataLength - 2)
                {
                    return null;
                }

                var tag = Encoding.ASCII.GetString(response, dataOffset + 2, tagLength);
                var valueLength = dataLength - 2 - tagLength;
                var value = Encoding.ASCII.GetString(response, dataOffset + 2 + tagLength, valueLength);
                return new DnsRecord
                {
                    Name = ownerName,
                    Type = type,
                    TimeToLive = timeToLive,
                    CaaFlags = flags,
                    CaaTag = tag,
                    CaaValue = value
                };

            default:
                return null;
        }
    }

    private static string ReadName(byte[] message, ref int offset)
    {
        var labels = new List<string>();
        var cursor = offset;
        var jumped = false;
        var jumpCount = 0;

        while (true)
        {
            EnsureAvailable(message, cursor, 1);
            var length = message[cursor];

            if ((length & 0xC0) == 0xC0)
            {
                EnsureAvailable(message, cursor, 2);
                var pointer = ((length & 0x3F) << 8) | message[cursor + 1];
                if (pointer >= message.Length || ++jumpCount > 32)
                {
                    throw new InvalidDataException("DNS name compression pointer is invalid.");
                }

                if (!jumped)
                {
                    offset = cursor + 2;
                }

                cursor = pointer;
                jumped = true;
                continue;
            }

            if ((length & 0xC0) != 0)
            {
                throw new InvalidDataException("DNS label has an unsupported encoding.");
            }

            cursor++;
            if (length == 0)
            {
                if (!jumped)
                {
                    offset = cursor;
                }

                break;
            }

            EnsureAvailable(message, cursor, length);
            labels.Add(Encoding.ASCII.GetString(message, cursor, length));
            cursor += length;
            if (!jumped)
            {
                offset = cursor;
            }
        }

        return string.Join('.', labels);
    }

    private static bool IsTruncated(byte[] response) =>
        response.Length >= HeaderLength && (ReadUInt16(response, 2) & 0x0200) != 0;

    private static DnsLookupResult FailedLookup(
        string name,
        DnsRecordType type,
        IPAddress resolver,
        string message) => new()
    {
        QueryName = name,
        QueryType = type,
        Resolver = resolver,
        ResponseCode = DnsResponseCode.Unknown,
        Records = Array.Empty<DnsRecord>(),
        ErrorMessage = message
    };

    private static ushort ReadUInt16(byte[] bytes, int offset)
    {
        EnsureAvailable(bytes, offset, sizeof(ushort));
        return BinaryPrimitives.ReadUInt16BigEndian(bytes.AsSpan(offset, sizeof(ushort)));
    }

    private static uint ReadUInt32(byte[] bytes, int offset)
    {
        EnsureAvailable(bytes, offset, sizeof(uint));
        return BinaryPrimitives.ReadUInt32BigEndian(bytes.AsSpan(offset, sizeof(uint)));
    }

    private static void WriteUInt16(Stream stream, ushort value)
    {
        Span<byte> bytes = stackalloc byte[sizeof(ushort)];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        stream.Write(bytes);
    }

    private static void EnsureAvailable(byte[] message, int offset, int length)
    {
        if (offset < 0 || length < 0 || offset > message.Length - length)
        {
            throw new InvalidDataException(
                string.Format(
                    CultureInfo.InvariantCulture,
                    "DNS response is truncated at offset {0}.",
                    offset));
        }
    }
}
