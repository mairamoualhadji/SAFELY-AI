using System.Net;
using System.Net.NetworkInformation;
using SafelyAI.Network.TrafficMonitoring;
namespace SafelyAI.Network.PortMonitoring;

public record ListeningEndpoint(string Address, int Port, string Protocol, int ProcessId, string ProcessName);

public class PortMonitor
{
    public List<ListeningEndpoint> GetListeningEndpoints()
    {
        var endpoints = new List<ListeningEndpoint>();
        foreach (var port in GetListeningPorts())
            endpoints.Add(new ListeningEndpoint("*", port, "TCP", 0, "inconnu"));
        return endpoints;
    }

    public List<ListeningEndpoint> GetListeningEndpoints(IEnumerable<NetConnection> connections) =>
        connections.Where(c => c.State.Equals("Listen", StringComparison.OrdinalIgnoreCase))
            .Select(c => new ListeningEndpoint(c.LocalAddress, c.LocalPort, "TCP", c.Pid, c.Process))
            .DistinctBy(c => $"{c.Address}:{c.Port}:{c.ProcessId}")
            .OrderBy(c => c.Port)
            .ToList();

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
