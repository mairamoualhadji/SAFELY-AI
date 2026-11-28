using SafelyAI.Common;
using System.Text.RegularExpressions;
namespace SafelyAI.Identity.SessionMonitoring;

public record WindowsSession(string UserName, string SessionName, int SessionId, string State, string IdleTime, string LogonTime);

public class SessionMonitor
{
    // Nombre d'événements du journal Sécurité (droits administrateur requis). Renvoie -1 si illisible.
    private static int CountSecurityEvents(int eventId, int hours)
    {
        var script = "Get-WinEvent -FilterHashtable @{LogName='Security';Id=" + eventId +
                     ";StartTime=(Get-Date).AddHours(-" + hours + ")} -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count";
        return int.TryParse(Shell.PowerShell(script), out var n) ? n : -1;
    }

    // Tentatives de connexion échouées (événement 4625).
    public int FailedLogins(int hours = 24) => CountSecurityEvents(4625, hours);

    // Ajouts à un groupe local, par exemple Administrateurs (événement 4732).
    public int PrivilegeChanges(int hours = 24) => CountSecurityEvents(4732, hours);

    // Sessions Windows ouvertes.
    public string CurrentSessions() => Shell.Run("quser.exe", "");

    public List<WindowsSession> GetSessions()
    {
        var sessions = new List<WindowsSession>();
        foreach (var line in Shell.Lines(CurrentSessions()).Skip(1))
        {
            string normalized = line.TrimStart('>', ' ');
            var match = Regex.Match(normalized, @"^(\S+)\s+(\S*)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.*)$");
            if (!match.Success || !int.TryParse(match.Groups[3].Value, out int id)) continue;
            sessions.Add(new(match.Groups[1].Value, match.Groups[2].Value, id, match.Groups[4].Value, match.Groups[5].Value, match.Groups[6].Value.Trim()));
        }
        return sessions;
    }
}
