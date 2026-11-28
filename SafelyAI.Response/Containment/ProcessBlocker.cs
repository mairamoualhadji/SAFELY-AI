using System.Diagnostics;

namespace SafelyAI.Response.Containment;

public sealed record ContainmentResult(bool Success, string Message);

/// <summary>Stops a process only after an explicit confirmation.</summary>
public sealed class ProcessBlocker
{
    public ContainmentResult Block(int processId, bool confirmed)
    {
        if (!confirmed)
            return new(false, "Blocage annulé : confirmation explicite requise.");
        if (processId <= 0 || processId == Environment.ProcessId)
            return new(false, "Identifiant de processus invalide ou protégé.");

        try
        {
            using var process = Process.GetProcessById(processId);
            string name = process.ProcessName;
            process.Kill(entireProcessTree: true);
            process.WaitForExit(5000);
            return new(true, $"Le processus {name} ({processId}) a été arrêté.");
        }
        catch (ArgumentException)
        {
            return new(false, "Le processus n'existe plus.");
        }
        catch (Exception ex)
        {
            return new(false, $"Blocage impossible : {ex.Message}");
        }
    }
}
