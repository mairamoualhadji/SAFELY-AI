using SafelyAI.AI.ThreatClassification;

namespace SafelyAI.AI.FileAnalysis;

public sealed record FileSuspicionFinding(
    string Code,
    string Description,
    int Score);

public sealed record FileSuspicionAssessment(
    int Score,
    IReadOnlyList<FileSuspicionFinding> Findings);

public sealed record FileAnalysisResult(
    string Path,
    bool Exists,
    bool Accessible,
    long SizeBytes,
    string Sha256,
    int Score,
    ThreatLevel ThreatLevel,
    IReadOnlyList<string> Findings,
    string Explanation,
    IReadOnlyList<string> Recommendations,
    DateTime AnalyzedAt)
{
    public bool IsSuspicious => ThreatLevel >= ThreatLevel.Low;
}
