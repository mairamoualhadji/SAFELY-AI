namespace SafelyAI.AI.BehaviorAnalysis;

public class BehaviorAnalyzer
{
    private static readonly HashSet<string> SystemNames = new(StringComparer.OrdinalIgnoreCase)
        { "svchost", "lsass", "csrss", "winlogon", "services", "smss" };

    private readonly BehaviorAnalysisOptions _options;

    public BehaviorAnalyzer(BehaviorAnalysisOptions? options = null)
    {
        _options = options ?? new BehaviorAnalysisOptions();
        _options.Validate();
    }

    public BehaviorReport Analyze(ProcessBehavior process)
    {
        int score = 0;
        var reasons = new List<string>();
        var path = process.Path ?? string.Empty;

        if (path.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase) ||
            path.Contains(@"\Downloads\", StringComparison.OrdinalIgnoreCase))
        {
            score += 30;
            reasons.Add("Lancé depuis un dossier temporaire ou de téléchargements");
        }

        if (SystemNames.Contains(process.Name) &&
            path.Length > 0 &&
            !path.StartsWith(@"C:\Windows", StringComparison.OrdinalIgnoreCase))
        {
            score += 50;
            reasons.Add("Porte le nom d'un processus Windows mais ne vient pas du dossier système");
        }

        if (process.CpuPercent >= _options.HighCpuPercent)
        {
            score += 15;
            reasons.Add("Utilise presque tout le processeur");
        }

        if (process.MemoryMb >= _options.HighMemoryMb)
        {
            score += 10;
            reasons.Add("Consomme beaucoup de mémoire");
        }

        if (process.NetworkConnections >= _options.ManyNetworkConnections)
        {
            score += 20;
            reasons.Add("Ouvre un nombre inhabituel de connexions réseau");
        }

        return new BehaviorReport(process, Math.Min(score, 100), reasons);
    }
}
