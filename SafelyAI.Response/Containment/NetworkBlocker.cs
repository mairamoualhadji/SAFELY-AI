using System.Diagnostics;
using System.Net;

namespace SafelyAI.Response.Containment;

/// <summary>Creates/removes explicit SAFELY AI firewall rules for an IP address.</summary>
public sealed class NetworkBlocker
{
    public ContainmentResult BlockIp(string ip, bool confirmed)
    {
        if (!confirmed)
            return new(false, "Blocage annulé : confirmation explicite requise.");
        if (!IPAddress.TryParse(ip, out _))
            return new(false, "Adresse IP invalide.");
        if (!OperatingSystem.IsWindows())
            return new(false, "Le pare-feu Windows est requis.");

        var outbound = RunNetsh($"advfirewall firewall add rule name=\"SAFELY AI Block {ip} Out\" dir=out action=block remoteip={ip}");
        var inbound = RunNetsh($"advfirewall firewall add rule name=\"SAFELY AI Block {ip} In\" dir=in action=block remoteip={ip}");
        return outbound && inbound
            ? new(true, $"Les connexions vers {ip} sont bloquées.")
            : new(false, "Impossible de créer les règles pare-feu. Lancez l'application en administrateur.");
    }

    public ContainmentResult UnblockIp(string ip, bool confirmed)
    {
        if (!confirmed)
            return new(false, "Déblocage annulé : confirmation explicite requise.");
        if (!IPAddress.TryParse(ip, out _))
            return new(false, "Adresse IP invalide.");
        var outbound = RunNetsh($"advfirewall firewall delete rule name=\"SAFELY AI Block {ip} Out\"");
        var inbound = RunNetsh($"advfirewall firewall delete rule name=\"SAFELY AI Block {ip} In\"");
        return outbound || inbound
            ? new(true, $"Les règles SAFELY AI pour {ip} ont été supprimées.")
            : new(false, "Aucune règle SAFELY AI supprimée.");
    }

    private static bool RunNetsh(string arguments)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("netsh", arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });
            process?.WaitForExit(10000);
            return process?.ExitCode == 0;
        }
        catch { return false; }
    }
}
