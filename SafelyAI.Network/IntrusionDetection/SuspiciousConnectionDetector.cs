using System.Net;
using System.Net.Sockets;
using SafelyAI.Network.TrafficMonitoring;
namespace SafelyAI.Network.IntrusionDetection;

public class SuspiciousConnectionDetector
{
    private static readonly HashSet<int> RiskyPorts = new() { 1337, 4444, 5555, 6667, 9001, 31337 };
    private static readonly HashSet<string> ScriptTools = new(StringComparer.OrdinalIgnoreCase) { "powershell", "cmd", "wscript", "cscript", "mshta" };

    public List<string> Analyze(IEnumerable<NetConnection> connections)
    {
        var alerts = new List<string>();
        foreach (var c in connections.Where(c => c.State == "Established" && !IsLocal(c.RemoteAddress)))
        {
            if (RiskyPorts.Contains(c.RemotePort))
                alerts.Add($"{c.Process} communique avec {c.RemoteAddress}:{c.RemotePort} (port souvent utilisé par des malwares)");
            if (ScriptTools.Contains(c.Process))
                alerts.Add($"L'outil système {c.Process} communique avec Internet ({c.RemoteAddress})");
        }
        return alerts.Distinct().ToList();
    }

    private static bool IsLocal(string ip)
    {
        if (!IPAddress.TryParse(ip, out var a)) return true;
        if (IPAddress.IsLoopback(a) || a.Equals(IPAddress.Any) || a.Equals(IPAddress.IPv6Any)) return true;
        if (a.AddressFamily == AddressFamily.InterNetworkV6) return a.IsIPv6LinkLocal || a.IsIPv6SiteLocal;
        var b = a.GetAddressBytes();
        return b[0] == 10 || (b[0] == 172 && b[1] >= 16 && b[1] <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 169 && b[1] == 254);
    }
}
