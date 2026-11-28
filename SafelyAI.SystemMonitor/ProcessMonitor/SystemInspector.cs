using SafelyAI.Common;
namespace SafelyAI.SystemMonitor.ProcessMonitor;

// Services, tâches planifiées, pilotes et journaux Windows (lecture seule).
public class SystemInspector
{
    public List<string> GetRunningServices() =>
        Shell.Lines(Shell.PowerShell("Get-Service | Where-Object { $_.Status -eq 'Running' } | ForEach-Object { $_.Name }"));

    public List<string> GetScheduledTasks() =>
        Shell.Lines(Shell.PowerShell("""Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' } | ForEach-Object { "$($_.TaskPath)$($_.TaskName)" }"""));

    public List<string> GetDrivers() =>
        Shell.Lines(Shell.Run("driverquery.exe", "/fo csv /nh"));

    // Dernières erreurs et alertes critiques du journal Système.
    public List<string> GetRecentSystemErrors(int count = 20) =>
        Shell.Lines(Shell.PowerShell("Get-WinEvent -FilterHashtable @{LogName='System';Level=1,2} -MaxEvents " + count +
            """ -ErrorAction SilentlyContinue | ForEach-Object { "$($_.TimeCreated) $($_.ProviderName) (ID $($_.Id))" }"""));
}
