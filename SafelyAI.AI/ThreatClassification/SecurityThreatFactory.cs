using SafelyAI.AI.BehaviorAnalysis;
using SafelyAI.Core.Models;

namespace SafelyAI.AI.ThreatClassification;

public static class SecurityThreatFactory
{
    public static SecurityThreat FromBehavior(BehaviorAnalysisResult result)
    {
        ArgumentNullException.ThrowIfNull(result);

        var process = result.Behavior.Process;
        return new SecurityThreat
        {
            Name = $"Processus suspect : {process.Name}",
            Description = result.Explanation,
            ThreatType = "Analyse comportementale",
            Severity = ToCoreSeverity(result.ThreatLevel),
            Source = $"SafelyAI.AI (PID {process.Pid})"
        };
    }

    private static string ToCoreSeverity(ThreatLevel level) => level switch
    {
        ThreatLevel.Critical => "Critique",
        ThreatLevel.High => "Élevé",
        ThreatLevel.Medium => "Modéré",
        ThreatLevel.Low or ThreatLevel.Info => "Faible",
        _ => "Faible"
    };
}
