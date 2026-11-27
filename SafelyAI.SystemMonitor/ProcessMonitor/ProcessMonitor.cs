using System.Diagnostics;
using System.Runtime.InteropServices;
namespace SafelyAI.SystemMonitor.ProcessMonitor;

public record ProcInfo(int Pid, string Name, double MemoryMb, string? Path);
public record DiskInfo(string Drive, double FreeGb, double TotalGb);

public class ProcessMonitor
{
    public List<ProcInfo> GetProcesses()
    {
        var list = new List<ProcInfo>();
        foreach (var p in Process.GetProcesses())
        {
            string? path = null;
            try { path = p.MainModule?.FileName; } catch { } // accès refusé pour certains processus système
            list.Add(new ProcInfo(p.Id, p.ProcessName, p.WorkingSet64 / 1024.0 / 1024.0, path));
        }
        return list.OrderByDescending(p => p.MemoryMb).ToList();
    }

    // Utilisation du processeur (%) mesurée sur une courte durée.
    public async Task<double> GetCpuPercentAsync(int milliseconds = 1000)
    {
        double Total() => Process.GetProcesses().Sum(p => { try { return p.TotalProcessorTime.TotalMilliseconds; } catch { return 0; } });
        var a = Total();
        await Task.Delay(milliseconds);
        var b = Total();
        return Math.Clamp((b - a) / (milliseconds * Environment.ProcessorCount) * 100, 0, 100);
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private class MemoryStatus
    {
        public uint dwLength = (uint)Marshal.SizeOf(typeof(MemoryStatus));
        public uint dwMemoryLoad;
        public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GlobalMemoryStatusEx([In, Out] MemoryStatus buffer);

    // Mémoire RAM utilisée (%).
    public static double GetRamUsedPercent()
    {
        var m = new MemoryStatus();
        return GlobalMemoryStatusEx(m) ? m.dwMemoryLoad : 0;
    }

    public static List<DiskInfo> GetDisks() =>
        DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady)
            .Select(d => new DiskInfo(d.Name, d.AvailableFreeSpace / 1e9, d.TotalSize / 1e9)).ToList();
}
