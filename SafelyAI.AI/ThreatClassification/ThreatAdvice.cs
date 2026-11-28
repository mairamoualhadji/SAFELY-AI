namespace SafelyAI.AI.ThreatClassification;

public sealed record ThreatAdvice(
    string Summary,
    IReadOnlyList<string> Recommendations,
    bool UsedLocalModel);
