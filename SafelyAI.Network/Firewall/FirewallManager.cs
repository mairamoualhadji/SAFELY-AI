using System.Net;
using SafelyAI.Common;
namespace SafelyAI.Network.Firewall;

// Les actions de modification demandent de lancer l'application en administrateur.
public class FirewallManager
{
    public record FirewallRule(string DisplayName, string Direction, string Action, string RemoteAddress, bool Enabled);

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

    public string UnblockIp(string ip)
    {
        if (!IPAddress.TryParse(ip, out _)) return "Adresse IP invalide.";
        if (!Shell.IsAdmin()) return "Droits administrateur requis.";
        return Shell.PowerShell(
            $"Get-NetFirewallRule -DisplayName 'SafelyAI Block {ip} out','SafelyAI Block {ip} in' -ErrorAction SilentlyContinue | Remove-NetFirewallRule; 'OK'");
    }

    public List<FirewallRule> GetSafelyAiRules() =>
        Shell.Lines(Shell.PowerShell("Get-NetFirewallRule -DisplayName 'SafelyAI *' -ErrorAction SilentlyContinue | ForEach-Object { $f=$_; $a=Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $f; \"$($f.DisplayName)|$($f.Direction)|$($f.Action)|$($a.RemoteAddress -join ',')|$($f.Enabled)\" }"))
            .Select(line => line.Split('|'))
            .Where(parts => parts.Length >= 5)
            .Select(parts => new FirewallRule(parts[0], parts[1], parts[2], parts[3], parts[4].Equals("True", StringComparison.OrdinalIgnoreCase)))
            .ToList();
}
