namespace SafelyAI.AI.BehaviorAnalysis;

public class BehaviorAnalyzer
{
    private static readonly string[] SystemNames = { "svchost", "lsass", "csrss", "winlogon", "services", "smss" };

    public BehaviorReport Analyze(ProcessBehavior p)
    {
        int score = 0;
        var reasons = new List<string>();
        var path = p.Path ?? "";

        if (path.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase))
        {
            score += 30; reasons.Add("Lancé depuis un dossier temporaire ou de téléchargements");
        }
        if (SystemNames.Contains(p.Name.ToLowerInvariant()) && path.Length > 0 &&
            !path.StartsWith(@"C:\Windows", StringComparison.OrdinalIgnoreCase))
        {
            score += 50; reasons.Add("Porte le nom d'un processus Windows mais ne vient pas du dossier système");
        }
        if (p.CpuPercent > 85) { score += 15; reasons.Add("Utilise presque tout le processeur"); }
        if (p.MemoryMb > 2000) { score += 10; reasons.Add("Consomme beaucoup de mémoire"); }
        if (p.NetworkConnections > 50) { score += 20; reasons.Add("Ouvre un nombre inhabituel de connexions réseau"); }

        return new BehaviorReport(p, Math.Min(score, 100), reasons);
    }
}
