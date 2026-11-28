using Microsoft.Win32;
using SafelyAI.Desktop.Helpers;
using SafelyAI.Desktop.Models;
using SafelyAI.Desktop.Services;

namespace SafelyAI.Desktop.ViewModels;

public class DashboardViewModel : ObservableObject
{
    public DesktopSession Session { get; }
    public RelayCommand QuickScanCommand { get; }
    public RelayCommand FullScanCommand { get; }
    public RelayCommand CustomScanCommand { get; }
    public RelayCommand CancelScanCommand { get; }
    public RelayCommand RefreshDefenderCommand { get; }
    public RelayCommand OpenWindowsSecurityCommand { get; }
    public bool CanStartScan => Session.CanStartScan;
    private readonly MicrosoftDefenderService _defender = new();
    private DefenderProtectionStatus _defenderStatus = DefenderProtectionStatus.Unavailable("Lecture de l’état de Microsoft Defender…");
    private bool _isRefreshingDefender;
    public DefenderProtectionStatus DefenderStatus { get => _defenderStatus; private set { if (Set(ref _defenderStatus, value)) { OnPropertyChanged(nameof(DefenderStatusLabel)); OnPropertyChanged(nameof(DefenderSignatureLabel)); } } }
    public string DefenderStatusLabel => !DefenderStatus.Available ? "État de Sécurité Windows indisponible"
        : DefenderStatus.RealTimeProtectionEnabled ? "Protection en temps réel active"
        : DefenderStatus.AntivirusEnabled ? "Protection en temps réel désactivée" : "Antivirus Microsoft Defender inactif";
    public string DefenderSignatureLabel => DefenderStatus.SignaturesLastUpdated is { } updated
        ? $"Signatures mises à jour le {updated.ToLocalTime():dd/MM/yyyy à HH:mm} · moteur {DefenderStatus.EngineVersion}"
        : DefenderStatus.Available ? $"Date des signatures indisponible · moteur {DefenderStatus.EngineVersion}"
        : DefenderStatus.Message;
    public bool IsRefreshingDefender { get => _isRefreshingDefender; private set { if (Set(ref _isRefreshingDefender, value)) OnPropertyChanged(nameof(CanRefreshDefender)); } }
    public bool CanRefreshDefender => !IsRefreshingDefender;
    public string Status => Session.IsScanRunning ? "Analyse en cours" : Session.Threats.Count > 0
        ? "Des indicateurs demandent votre attention"
        : Session.LastScan is null ? "Une première analyse est nécessaire" : Session.LastScan.ThreatsFound > 0
            ? "Le dernier scan a relevé des indicateurs" : "Aucun indicateur au dernier scan";
    public string LastScan => Session.LastScan is { } scan
        ? $"Dernière session : {scan.Type} · {scan.FinishedAt:dd/MM/yyyy à HH:mm} · {scan.FilesScanned:N0} fichiers"
        : "Aucune analyse effectuée";
    public string ScanMessage => Session.ScanStatus;
    public int Progress => Session.ScanProgress;
    public bool IsBusy => Session.IsScanRunning;

    public DashboardViewModel(DesktopSession session)
    {
        Session = session;
        QuickScanCommand = new(_ => _ = Session.RunScanAsync(ScanType.Quick));
        FullScanCommand = new(_ => _ = Session.RunScanAsync(ScanType.Full));
        CustomScanCommand = new(_ => ChooseFolderAndRun());
        CancelScanCommand = new(_ => Session.CancelScan());
        RefreshDefenderCommand = new(_ => _ = RefreshDefenderStatusAsync());
        OpenWindowsSecurityCommand = new(_ => OpenWindowsSecurity());
        Session.Threats.CollectionChanged += (_, _) => OnPropertyChanged(nameof(Status));
        Session.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(DesktopSession.ScanStatus) or nameof(DesktopSession.ScanProgress)
                or nameof(DesktopSession.IsScanRunning) or nameof(DesktopSession.LastScan))
            {
                OnPropertyChanged(nameof(Status)); OnPropertyChanged(nameof(LastScan));
                OnPropertyChanged(nameof(ScanMessage)); OnPropertyChanged(nameof(Progress));
                OnPropertyChanged(nameof(IsBusy)); OnPropertyChanged(nameof(CanStartScan));
            }
        };
        _ = RefreshDefenderStatusAsync();
    }

    private async Task RefreshDefenderStatusAsync()
    {
        if (IsRefreshingDefender) return;
        IsRefreshingDefender = true;
        try { DefenderStatus = await _defender.GetProtectionStatusAsync(); }
        catch (Exception ex) { DefenderStatus = DefenderProtectionStatus.Unavailable($"État de Microsoft Defender indisponible : {ex.Message}"); }
        finally { IsRefreshingDefender = false; }
    }

    private void OpenWindowsSecurity()
    {
        try { MicrosoftDefenderService.OpenWindowsSecurity(); }
        catch (Exception ex) { Session.AddNotification("Sécurité Windows indisponible", ex.Message, "Avertissement"); }
    }

    private void ChooseFolderAndRun()
    {
        var dialog = new OpenFolderDialog { Title = "Choisir un dossier à analyser", Multiselect = false };
        if (dialog.ShowDialog() == true) _ = Session.RunScanAsync(ScanType.Custom, dialog.FolderName);
    }
}
