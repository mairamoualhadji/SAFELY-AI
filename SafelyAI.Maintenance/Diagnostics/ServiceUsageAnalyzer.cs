using System.Diagnostics;

namespace SafelyAI.Maintenance.Diagnostics;

public record ServiceCandidate(string Name, string DisplayName, string StartMode, string State, string PathName, string Reason);

/// <summary>Identifies candidates for review. It never disables a service automatically.</summary>
public sealed class ServiceUsageAnalyzer
{
    public List<ServiceCandidate> FindCandidates()
    {
        if (!OperatingSystem.IsWindows()) return new();
        string script = "Get-CimInstance Win32_Service | Where-Object { $_.StartMode -eq 'Auto' -and $_.State -ne 'Running' } | ForEach-Object { \"$($_.Name)|$($_.DisplayName)|$($_.StartMode)|$($_.State)|$($_.PathName)\" }";
        var result = new List<ServiceCandidate>();
        foreach (var line in RunPowerShell(script).Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = line.Split('|', 5);
            if (parts.Length < 5 || IsCoreService(parts[0])) continue;
            result.Add(new(parts[0], parts[1], parts[2], parts[3], parts[4], "Service automatique arrêté : à vérifier avant toute désactivation."));
        }
        return result;
    }

    private static bool IsCoreService(string name) =>
        name.Equals("RpcSs", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("WinDefend", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("MpsSvc", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("EventLog", StringComparison.OrdinalIgnoreCase);

    private static string RunPowerShell(string script)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo("powershell.exe", $"-NoProfile -NonInteractive -Command \"{script}\"")
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true
            });
            return process?.StandardOutput.ReadToEnd() ?? string.Empty;
        }
        catch { return string.Empty; }
    }
}
