using System.Diagnostics;
using SafelyAI.Common;
namespace SafelyAI.Network.TrafficMonitoring;

public record NetConnection(string LocalAddress, int LocalPort, string RemoteAddress, int RemotePort, string State, int Pid, string Process);

public class ConnectionMonitor
{
    // Connexions TCP entrantes et sortantes, avec l'application qui les utilise.
    public List<NetConnection> GetConnections()
    {
        var list = new List<NetConnection>();
        var output = Shell.PowerShell("""Get-NetTCPConnection | ForEach-Object { "$($_.LocalAddress)|$($_.LocalPort)|$($_.RemoteAddress)|$($_.RemotePort)|$($_.State)|$($_.OwningProcess)" }""");
        foreach (var line in Shell.Lines(output))
        {
            var p = line.Split('|');
            if (p.Length != 6) continue;
            int.TryParse(p[1], out var lp);
            int.TryParse(p[3], out var rp);
            int.TryParse(p[5], out var pid);
            list.Add(new NetConnection(p[0], lp, p[2], rp, p[4], pid, ProcessName(pid)));
        }
        return list;
    }

    // Applications qui ont une connexion établie.
    public List<string> GetConnectedApps() =>
        GetConnections().Where(c => c.State == "Established").Select(c => c.Process).Distinct().OrderBy(n => n).ToList();

    private static string ProcessName(int pid)
    {
        try { return Process.GetProcessById(pid).ProcessName; } catch { return "?"; }
    }
}
