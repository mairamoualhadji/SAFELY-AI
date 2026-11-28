using System.Diagnostics;
using SafelyAI.Network.TrafficMonitoring;
using SafelyAI.SystemMonitor.ProcessMonitor;

namespace SafelyAI.AI.BehaviorAnalysis;

public sealed class ProcessBehaviorCollector
{
    private readonly ProcessMonitor _processMonitor;
    private readonly ConnectionMonitor _connectionMonitor;

    public ProcessBehaviorCollector(
        ProcessMonitor? processMonitor = null,
        ConnectionMonitor? connectionMonitor = null)
    {
        _processMonitor = processMonitor ?? new ProcessMonitor();
        _connectionMonitor = connectionMonitor ?? new ConnectionMonitor();
    }

    public async Task<IReadOnlyList<ProcessBehavior>> CollectAsync(
        TimeSpan? sampleInterval = null,
        CancellationToken cancellationToken = default)
    {
        var interval = sampleInterval ?? TimeSpan.FromMilliseconds(500);
        if (interval < TimeSpan.FromMilliseconds(100) || interval > TimeSpan.FromSeconds(10))
        {
            throw new ArgumentOutOfRangeException(
                nameof(sampleInterval),
                "L'intervalle doit être compris entre 100 ms et 10 secondes.");
        }

        cancellationToken.ThrowIfCancellationRequested();

        var processes = _processMonitor.GetProcesses()
            .Where(process => process.Pid > 0)
            .ToArray();
        var connectionsByProcess = GetConnectionsByProcess();
        var before = CaptureCpuTimes(processes.Select(process => process.Pid));

        await Task.Delay(interval, cancellationToken);

        var after = CaptureCpuTimes(before.Keys);
        var behaviors = new List<ProcessBehavior>(processes.Length);

        foreach (var process in processes)
        {
            var hasBeforeSample = before.TryGetValue(process.Pid, out var beforeCpu);
            var hasAfterSample = after.TryGetValue(process.Pid, out var afterCpu);
            var cpuPercent = hasBeforeSample && hasAfterSample
                ? CalculateCpuPercent(beforeCpu, afterCpu, interval)
                : 0;
            connectionsByProcess.TryGetValue(process.Pid, out var connectionCount);

            behaviors.Add(new ProcessBehavior(
                process.Name,
                process.Pid,
                process.Path,
                cpuPercent,
                process.MemoryMb,
                connectionCount));
        }

        return behaviors;
    }

    private Dictionary<int, int> GetConnectionsByProcess()
    {
        try
        {
            return _connectionMonitor.GetConnections()
                .GroupBy(connection => connection.Pid)
                .ToDictionary(group => group.Key, group => group.Count());
        }
        catch
        {
            return new Dictionary<int, int>();
        }
    }

    private static Dictionary<int, TimeSpan> CaptureCpuTimes(IEnumerable<int> processIds)
    {
        var snapshot = new Dictionary<int, TimeSpan>();

        foreach (var processId in processIds.Distinct())
        {
            try
            {
                using var process = Process.GetProcessById(processId);
                snapshot[processId] = process.TotalProcessorTime;
            }
            catch
            {
                // Un processus peut se terminer ou être protégé entre deux instantanés.
            }
        }

        return snapshot;
    }

    private static double CalculateCpuPercent(
        TimeSpan before,
        TimeSpan after,
        TimeSpan interval)
    {
        if (after <= before || interval <= TimeSpan.Zero)
        {
            return 0;
        }

        var processMilliseconds = (after - before).TotalMilliseconds;
        var availableMilliseconds = interval.TotalMilliseconds * Environment.ProcessorCount;
        return Math.Clamp(processMilliseconds / availableMilliseconds * 100, 0, 100);
    }
}
