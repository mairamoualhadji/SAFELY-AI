using SafelyAI.Desktop.Models;
namespace SafelyAI.Desktop.Services;
// Contrat à valider avec Membre 3 : SafelyAI.Antivirus implémentera cette interface.
public interface IScanService
{
    Task<ScanResult> RunAsync(ScanType type, string? path = null);
}
// Données factices pour développer l'interface sans le moteur.
public class MockScanService : IScanService
{
    public async Task<ScanResult> RunAsync(ScanType type, string? path = null)
    {
        await Task.Delay(1500);
        return new ScanResult(type, type == ScanType.Quick ? 4200 : 98000, 0, DateTime.Now);
    }
}
