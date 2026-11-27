using System.Net;
using SafelyAI.Common;
namespace SafelyAI.Network.Firewall;

// Les actions de modification demandent de lancer l'application en administrateur.
public class FirewallManager
{
    public string GetStatus() =>
        Shell.PowerShell("""Get-NetFirewallProfile | ForEach-Object { "$($_.Name): $($_.Enabled)" }""");

    public string SetEnabled(bool enabled)
    {
        if (!Shell.IsAdmin()) return "Droits administrateur requis.";
        return Shell.PowerShell($"Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled {(enabled ? "True" : "False")}");
    }

    public string BlockIp(string ip)
    {
        if (!IPAddress.TryParse(ip, out _)) return "Adresse IP invalide.";
        if (!Shell.IsAdmin()) return "Droits administrateur requis.";
        return Shell.PowerShell(
            $"New-NetFirewallRule -DisplayName 'SafelyAI Block {ip} out' -Direction Outbound -RemoteAddress {ip} -Action Block | Out-Null; " +
            $"New-NetFirewallRule -DisplayName 'SafelyAI Block {ip} in' -Direction Inbound -RemoteAddress {ip} -Action Block | Out-Null; 'OK'");
    }
}
