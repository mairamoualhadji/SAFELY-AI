namespace SafelyAI.AI.AnomalyDetection;

public sealed record SystemDiskSnapshot(
    string Drive,
    double FreeGb,
    double TotalGb,
    double FreePercent);

public sealed record SystemAnomalySnapshot(
    double CpuPercent,
    double RamUsedPercent,
    IReadOnlyList<SystemDiskSnapshot> Disks,
    DateTime CapturedAt);

public sealed record SystemAnomalyFinding(
    string Metric,
    double Value,
    string Description);

public sealed record SystemAnomalyReport(
    SystemAnomalySnapshot Snapshot,
    IReadOnlyList<SystemAnomalyFinding> Findings)
{
    public bool HasAnomalies => Findings.Count > 0;
}
