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
    public bool CanStartScan => Session.CanStartScan;
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
    }

    private void ChooseFolderAndRun()
    {
        var dialog = new OpenFolderDialog { Title = "Choisir un dossier à analyser", Multiselect = false };
        if (dialog.ShowDialog() == true) _ = Session.RunScanAsync(ScanType.Custom, dialog.FolderName);
    }
}
