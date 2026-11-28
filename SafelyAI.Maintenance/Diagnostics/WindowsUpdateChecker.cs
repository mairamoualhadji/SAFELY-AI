using System.Diagnostics;

namespace SafelyAI.Maintenance.Diagnostics;

public record WindowsUpdateStatus(bool Supported, DateTime? LatestHotFixDate, int HotFixCount, string Message);

/// <summary>Read-only Windows update health check based on installed hotfixes.</summary>
public sealed class WindowsUpdateChecker
{
    public WindowsUpdateStatus Check()
    {
        if (!OperatingSystem.IsWindows()) return new(false, null, 0, "Cette fonctionnalité nécessite Windows.");
        try
        {
            using var process = Process.Start(new ProcessStartInfo("powershell.exe", "-NoProfile -NonInteractive -Command \"Get-HotFix | ForEach-Object { $_.InstalledOn.ToString('o') }\"")
            {
                UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true
            });
            string output = process?.StandardOutput.ReadToEnd() ?? string.Empty;
            var dates = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(x => DateTime.TryParse(x.Trim(), out var date) ? date : (DateTime?)null)
                .Where(x => x.HasValue).Select(x => x!.Value).OrderByDescending(x => x).ToList();
            return new(true, dates.FirstOrDefault(), dates.Count, dates.Count == 0 ? "Aucun correctif détecté." : "Correctifs Windows installés vérifiés.");
        }
        catch (Exception ex)
        {
            return new(false, null, 0, $"Vérification impossible : {ex.Message}");
        }
    }
}
