using System.Net;
using System.Net.NetworkInformation;
using SafelyAI.Network.TrafficMonitoring;
namespace SafelyAI.Network.PortMonitoring;

public class PortMonitor
{
    // Ports ouverts en écoute sur ce PC.
    public List<int> GetListeningPorts() =>
        IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(e => e.Port).Distinct().OrderBy(p => p).ToList();

    // Détection de scan de ports : une même adresse distante qui touche beaucoup de ports locaux différents.
    public List<string> DetectPortScans(IEnumerable<NetConnection> connections, int threshold = 10)
    {
        return connections
            .Where(c => c.State != "Listen" && IPAddress.TryParse(c.RemoteAddress, out var ip)
                        && !IPAddress.IsLoopback(ip) && !ip.Equals(IPAddress.Any) && !ip.Equals(IPAddress.IPv6Any))
            .GroupBy(c => c.RemoteAddress)
            .Where(g => g.Select(c => c.LocalPort).Distinct().Count() >= threshold)
            .Select(g => $"Scan de ports possible depuis {g.Key} ({g.Select(c => c.LocalPort).Distinct().Count()} ports touchés)")
            .ToList();
    }
}
