namespace SafelyAI.AI.BehaviorAnalysis;

public record ProcessBehavior(
    string Name,
    int Pid,
    string? Path,
    double CpuPercent,
    double MemoryMb,
    int NetworkConnections);

public record BehaviorReport(
    ProcessBehavior Process,
    int Score,
    IReadOnlyList<string> Reasons);
