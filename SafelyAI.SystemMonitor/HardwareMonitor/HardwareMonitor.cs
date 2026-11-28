using SafelyAI.Common;
namespace SafelyAI.SystemMonitor.HardwareMonitor;

public record HardwareSecuritySnapshot(string SecureBoot, string Tpm, string BitLocker, DateTimeOffset CapturedAt);

// Ces vérifications demandent en général les droits administrateur.
public class HardwareMonitor
{
    private const string Unknown = "Inconnu (droits administrateur requis ou matériel non compatible)";

    public string GetSecureBootStatus() =>
        Shell.PowerShell("try { Confirm-SecureBootUEFI } catch { '" + Unknown + "' }");

    public string GetTpmStatus() =>
        Shell.PowerShell("""try { $t = Get-Tpm; "Présent=$($t.TpmPresent) Prêt=$($t.TpmReady)" } catch { 'Inconnu (droits administrateur requis ou matériel non compatible)' }""");

    public string GetBitLockerStatus() =>
        Shell.PowerShell("""try { Get-BitLockerVolume | ForEach-Object { "$($_.MountPoint): $($_.ProtectionStatus)" } } catch { 'Inconnu (droits administrateur requis ou matériel non compatible)' }""");

    public HardwareSecuritySnapshot GetSecuritySnapshot() =>
        new(GetSecureBootStatus(), GetTpmStatus(), GetBitLockerStatus(), DateTimeOffset.UtcNow);

    // Liste des périphériques présents : à comparer d'un lancement à l'autre.
    public List<string> TakeSnapshot() =>
        Shell.Lines(Shell.PowerShell("Get-PnpDevice -PresentOnly | Where-Object { $_.FriendlyName } | ForEach-Object { $_.FriendlyName }"));

    public (List<string> Added, List<string> Removed) DetectChanges(List<string> before, List<string> now) =>
        (now.Except(before).ToList(), before.Except(now).ToList());
}
