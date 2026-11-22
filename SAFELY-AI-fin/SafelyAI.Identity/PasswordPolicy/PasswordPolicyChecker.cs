using SafelyAI.Common;
namespace SafelyAI.Identity.PasswordPolicy;

public record PasswordPolicy(int MinLength, int MaxAgeDays, bool ComplexityRequired, int LockoutThreshold);

public class PasswordPolicyChecker
{
    // Lit la politique locale via secedit (droits administrateur requis). Renvoie null en cas d'échec.
    public PasswordPolicy? Read()
    {
        var tmp = Path.Combine(Path.GetTempPath(), "safelyai_secpol.cfg");
        try
        {
            Shell.Run("secedit.exe", $"/export /cfg \"{tmp}\" /areas SECURITYPOLICY");
            if (!File.Exists(tmp)) return null;
            var values = File.ReadAllLines(tmp)
                .Select(l => l.Split('=', 2)).Where(p => p.Length == 2)
                .ToDictionary(p => p[0].Trim(), p => p[1].Trim(), StringComparer.OrdinalIgnoreCase);
            int Get(string key) => values.TryGetValue(key, out var v) && int.TryParse(v, out var n) ? n : 0;
            return new PasswordPolicy(Get("MinimumPasswordLength"), Get("MaximumPasswordAge"), Get("PasswordComplexity") == 1, Get("LockoutBadCount"));
        }
        finally { if (File.Exists(tmp)) File.Delete(tmp); }
    }

    public List<string> Evaluate(PasswordPolicy p)
    {
        var issues = new List<string>();
        if (p.MinLength < 8) issues.Add("Longueur minimale du mot de passe inférieure à 8 caractères");
        if (!p.ComplexityRequired) issues.Add("La complexité du mot de passe n'est pas exigée");
        if (p.LockoutThreshold == 0) issues.Add("Aucun verrouillage du compte après des échecs de connexion");
        return issues;
    }
}
