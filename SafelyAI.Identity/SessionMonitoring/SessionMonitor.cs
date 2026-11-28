using SafelyAI.Common;
namespace SafelyAI.Identity.SessionMonitoring;

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
}
