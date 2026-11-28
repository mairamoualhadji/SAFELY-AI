using SafelyAI.SystemMonitor.ProcessMonitor;

namespace SafelyAI.AI.AnomalyDetection;

public sealed class SystemAnomalyAnalyzer
{
    private readonly ProcessMonitor _processMonitor;
    private readonly AnomalyDetector _detector;

    public SystemAnomalyAnalyzer(
        AnomalyDetector detector,
        ProcessMonitor? processMonitor = null)
    {
        _detector = detector ?? throw new ArgumentNullException(nameof(detector));
        _processMonitor = processMonitor ?? new ProcessMonitor();
    }

    public bool LearnAfterAnalysis { get; set; } = true;

    public async Task<SystemAnomalyReport> AnalyzeAsync(
        int cpuSampleMilliseconds = 500,
        CancellationToken cancellationToken = default)
    {
        if (cpuSampleMilliseconds is < 100 or > 10_000)
        {
            throw new ArgumentOutOfRangeException(nameof(cpuSampleMilliseconds));
        }

        cancellationToken.ThrowIfCancellationRequested();
        var cpuPercent = await _processMonitor.GetCpuPercentAsync(cpuSampleMilliseconds);
        cancellationToken.ThrowIfCancellationRequested();

        var disks = ProcessMonitor.GetDisks()
            .Select(disk => new SystemDiskSnapshot(
                disk.Drive,
                disk.FreeGb,
                disk.TotalGb,
                disk.TotalGb > 0 ? disk.FreeGb / disk.TotalGb * 100 : 0))
            .ToArray();

        var snapshot = new SystemAnomalySnapshot(
            cpuPercent,
            ProcessMonitor.GetRamUsedPercent(),
            disks,
            DateTime.UtcNow);

        var findings = new List<SystemAnomalyFinding>();
        AddFinding("system.cpu", snapshot.CpuPercent, "l'utilisation CPU globale", findings);
        AddFinding("system.ram", snapshot.RamUsedPercent, "l'utilisation de la mémoire RAM", findings);

        foreach (var disk in snapshot.Disks)
        {
            AddFinding(
                $"system.disk.free:{disk.Drive}",
                disk.FreePercent,
                $"l'espace libre du disque {disk.Drive}",
                findings,
                lowerIsAnomalous: true);
        }

        if (LearnAfterAnalysis)
        {
            _detector.Learn("system.cpu", snapshot.CpuPercent);
            _detector.Learn("system.ram", snapshot.RamUsedPercent);
            foreach (var disk in snapshot.Disks)
            {
                _detector.Learn($"system.disk.free:{disk.Drive}", disk.FreePercent);
            }
        }

        return new SystemAnomalyReport(snapshot, findings);
    }

    private void AddFinding(
        string metric,
        double value,
        string label,
        ICollection<SystemAnomalyFinding> findings,
        bool lowerIsAnomalous = false)
    {
        if (!_detector.IsAnomaly(metric, value))
        {
            return;
        }

        var direction = lowerIsAnomalous ? "inhabituellement faible" : "inhabituellement élevée";
        findings.Add(new SystemAnomalyFinding(
            metric,
            value,
            $"Valeur {direction} pour {label} ({value:0.##} %)."));
    }
}
