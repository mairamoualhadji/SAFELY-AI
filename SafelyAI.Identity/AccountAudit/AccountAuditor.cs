using SafelyAI.Common;
namespace SafelyAI.Identity.AccountAudit;

public record WindowsAccount(string Name, bool Enabled, bool IsAdmin, string LastLogon, bool PasswordRequired);

public class AccountAuditor
{
    public List<WindowsAccount> Audit()
    {
        // Les administrateurs sont retrouvés par leur identifiant fixe (S-1-5-32-544), valable quelle que soit la langue de Windows.
        var admins = Shell.Lines(Shell.PowerShell("Get-LocalGroupMember -SID S-1-5-32-544 | ForEach-Object { $_.Name }"))
            .Select(n => n.Split('\\').Last()).ToHashSet(StringComparer.OrdinalIgnoreCase);

        var accounts = new List<WindowsAccount>();
        var users = Shell.PowerShell("""Get-LocalUser | ForEach-Object { "$($_.Name)|$($_.Enabled)|$($_.LastLogon)|$($_.PasswordRequired)" }""");
        foreach (var line in Shell.Lines(users))
        {
            var p = line.Split('|');
            if (p.Length != 4) continue;
            accounts.Add(new WindowsAccount(p[0], p[1] == "True", admins.Contains(p[0]), p[2], p[3] == "True"));
        }
        return accounts;
    }

    public List<string> FindSuspicious(List<WindowsAccount> accounts)
    {
        var alerts = new List<string>();
        var activeAdmins = accounts.Where(a => a.IsAdmin && a.Enabled).ToList();
        foreach (var a in activeAdmins.Where(a => !a.PasswordRequired))
            alerts.Add($"Le compte administrateur « {a.Name} » n'a pas de mot de passe obligatoire");
        if (activeAdmins.Count > 2)
            alerts.Add($"{activeAdmins.Count} comptes administrateurs actifs : vérifiez qu'ils sont tous légitimes");
        return alerts;
    }
}
