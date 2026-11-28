using SafelyAI.AI.ThreatClassification;

namespace SafelyAI.AI.Reporting;

public sealed record SecurityReport(
    DateTime GeneratedAt,
    ThreatLevel OverallLevel,
    int ProcessCount,
    int SuspiciousProcessCount,
    int FileCount,
    int SuspiciousFileCount,
    int SystemAnomalyCount,
    IReadOnlyList<string> Findings,
    string Summary,
    IReadOnlyList<string> Recommendations,
    bool UsedLocalModel);
