using SafelyAI.AI.ThreatClassification;

namespace SafelyAI.AI.BehaviorAnalysis;

public sealed record BehaviorAnalysisResult(
    BehaviorReport Behavior,
    ThreatLevel ThreatLevel,
    IReadOnlyList<string> AnomalyReasons,
    string Explanation)
{
    public bool IsSuspicious => ThreatLevel >= ThreatLevel.Low;

    public IReadOnlyList<string> Recommendations =>
        SecurityRecommendationEngine.For(ThreatLevel, Behavior.Reasons);
}
