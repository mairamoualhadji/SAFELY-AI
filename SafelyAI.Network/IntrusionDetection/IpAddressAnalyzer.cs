using System.Net;
using System.Net.Sockets;
using SafelyAI.Network.TrafficMonitoring;

namespace SafelyAI.Network.IntrusionDetection;

public record IpAddressAnalysis(string Address, bool IsValid, bool IsPrivate, bool IsLoopback, bool IsMulticast, string Classification);

public sealed class IpAddressAnalyzer
{
    public IpAddressAnalysis Analyze(string address)
    {
        if (!IPAddress.TryParse(address, out var ip))
            return new(address, false, false, false, false, "Invalide");
        bool loopback = IPAddress.IsLoopback(ip);
        bool multicast = ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().IsIPv6Multicast : ip.IsIPv6Multicast;
        bool privateAddress = IsPrivate(ip);
        string classification = loopback ? "Boucle locale" : multicast ? "Multicast" : privateAddress ? "Réseau privé" : "Adresse publique";
        return new(address, true, privateAddress, loopback, multicast, classification);
    }

    public List<IpAddressAnalysis> AnalyzeConnections(IEnumerable<NetConnection> connections) =>
        connections.Select(c => Analyze(c.RemoteAddress)).DistinctBy(x => x.Address).ToList();

    private static bool IsPrivate(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            byte[] ipv6 = address.GetAddressBytes();
            return address.IsIPv6LinkLocal || address.IsIPv6SiteLocal || (ipv6[0] & 0xFE) == 0xFC;
        }
        byte[] bytes = address.GetAddressBytes();
        return bytes[0] == 10 || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31) ||
               (bytes[0] == 192 && bytes[1] == 168) || (bytes[0] == 169 && bytes[1] == 254);
    }
}
