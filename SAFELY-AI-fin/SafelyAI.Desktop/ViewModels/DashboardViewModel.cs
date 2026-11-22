using SafelyAI.Desktop.Helpers;
using SafelyAI.Desktop.Models;
using SafelyAI.Desktop.Services;
namespace SafelyAI.Desktop.ViewModels;
public class DashboardViewModel : ObservableObject
{
    private readonly IScanService _scan = new MockScanService();
    private string _status = "Votre PC est protégé";
    private string _lastScan = "Aucune analyse effectuée";
    private int _protectionLevel = 85;
    private bool _busy;
    public string Status { get => _status; set => Set(ref _status, value); }
    public string LastScan { get => _lastScan; set => Set(ref _lastScan, value); }
    public int ProtectionLevel { get => _protectionLevel; set => Set(ref _protectionLevel, value); }
    public RelayCommand QuickScanCommand { get; }
    public RelayCommand FullScanCommand { get; }
    public RelayCommand CustomScanCommand { get; }
    public DashboardViewModel()
    {
        QuickScanCommand = new(_ => Run(ScanType.Quick));
        FullScanCommand = new(_ => Run(ScanType.Full));
        CustomScanCommand = new(_ => Run(ScanType.Custom)); // TODO : sélecteur de dossier
    }
    private async void Run(ScanType type)
    {
        if (_busy) return;
        _busy = true; Status = "Analyse en cours…";
        var r = await _scan.RunAsync(type);
        LastScan = $"Dernière analyse : {r.FinishedAt:dd/MM/yyyy HH:mm}, {r.FilesScanned} fichiers, {r.ThreatsFound} menace(s)";
        Status = r.ThreatsFound == 0 ? "Votre PC est protégé" : "Des menaces ont été détectées";
        _busy = false;
    }
}
