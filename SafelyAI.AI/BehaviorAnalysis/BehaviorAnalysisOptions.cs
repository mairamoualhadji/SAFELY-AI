namespace SafelyAI.AI.BehaviorAnalysis;

public sealed class BehaviorAnalysisOptions
{
    public double HighCpuPercent { get; set; } = 85;

    public double HighMemoryMb { get; set; } = 2_000;

    public int ManyNetworkConnections { get; set; } = 50;

    public void Validate()
    {
        if (HighCpuPercent is < 1 or > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(HighCpuPercent));
        }

        if (HighMemoryMb <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(HighMemoryMb));
        }

        if (ManyNetworkConnections <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(ManyNetworkConnections));
        }
    }
}
