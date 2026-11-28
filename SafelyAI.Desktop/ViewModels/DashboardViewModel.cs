using Microsoft.Win32;
using System.ComponentModel;
using SafelyAI.Desktop.Helpers;
using SafelyAI.Desktop.Models;
using SafelyAI.Desktop.Services;
using System.Windows.Threading;

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
    public RelayCommand DefenderQuickScanCommand { get; }
    public RelayCommand DefenderFullScanCommand { get; }
    public RelayCommand DefenderCustomScanCommand { get; }
    private readonly MicrosoftDefenderService _defender = new();
    private readonly DispatcherTimer _defenderRefreshTimer;
    private DefenderProtectionStatus _defenderStatus = DefenderProtectionStatus.Unavailable("Lecture de l’état de Microsoft Defender…");
    private bool _isDefenderScanRunning;
    private string _defenderScanStatus = "Les analyses principales utilisent Microsoft Defender.";
    private bool _isRefreshingDefender;
    public DefenderProtectionStatus DefenderStatus { get => _defenderStatus; private set { if (Set(ref _defenderStatus, value)) { OnPropertyChanged(nameof(DefenderStatusLabel)); OnPropertyChanged(nameof(DefenderSignatureLabel)); OnPropertyChanged(nameof(Status)); } } }
    public string DefenderStatusLabel => !DefenderStatus.Available ? "État de Sécurité Windows indisponible"
        : DefenderStatus.RealTimeProtectionEnabled ? "Protection en temps réel active"
        : DefenderStatus.AntivirusEnabled ? "Protection en temps réel désactivée" : "Antivirus Microsoft Defender inactif";
    public string DefenderSignatureLabel => DefenderStatus.SignaturesLastUpdated is { } updated
        ? $"Signatures mises à jour le {updated.ToLocalTime():dd/MM/yyyy à HH:mm} · moteur {DefenderStatus.EngineVersion}"
        : DefenderStatus.Available ? $"Date des signatures indisponible · moteur {DefenderStatus.EngineVersion}"
        : DefenderStatus.Message;
    public bool IsRefreshingDefender { get => _isRefreshingDefender; private set { if (Set(ref _isRefreshingDefender, value)) OnPropertyChanged(nameof(CanRefreshDefender)); } }
    public bool CanRefreshDefender => !IsRefreshingDefender;
    public bool CanStartScan => Session.CanStartScan;
    public bool IsDefenderScanRunning { get => _isDefenderScanRunning; private set { if (Set(ref _isDefenderScanRunning, value)) { OnPropertyChanged(nameof(CanStartDefenderScan)); OnPropertyChanged(nameof(Status)); } } }
    public bool CanStartDefenderScan => !IsDefenderScanRunning;
    public string DefenderScanStatus { get => _defenderScanStatus; private set => Set(ref _defenderScanStatus, value); }
    public string Status => IsDefenderScanRunning ? "Analyse Microsoft Defender en cours"
        : !DefenderStatus.Available ? "État de la protection Windows indisponible"
        : !DefenderStatus.AntivirusEnabled ? "Protection antivirus Windows à vérifier"
        : !DefenderStatus.RealTimeProtectionEnabled ? "Protection en temps réel à vérifier"
        : Session.Threats.Count > 0 ? "Des indicateurs locaux sont à examiner"
        : "Protection Windows active";
    public string LastScan => Session.LastScan is { } scan
        ? $"Dernière analyse locale complémentaire : {scan.FinishedAt:dd/MM/yyyy à HH:mm} · {scan.FilesScanned:N0} fichiers"
        : "Aucune analyse locale complémentaire effectuée";
    public string ScanMessage => Session.ScanStatus;
    public int Progress => Session.ScanProgress;
    public bool IsBusy => Session.IsScanRunning;

    public DashboardViewModel(DesktopSession session)
    {
        Session = session;
        // The dashboard's primary actions use the Windows antivirus engine. The local
        // supplemental scanner remains available from the Antivirus page.
        QuickScanCommand = new(_ => _ = RunDefenderScanAsync(ScanType.Quick));
        FullScanCommand = new(_ => _ = RunDefenderScanAsync(ScanType.Full));
        CustomScanCommand = new(_ => ChooseFolderAndRun());
        CancelScanCommand = new(_ => Session.CancelScan());
        RefreshDefenderCommand = new(_ => _ = RefreshDefenderStatusAsync());
        OpenWindowsSecurityCommand = new(_ => OpenWindowsSecurity());
        DefenderQuickScanCommand = QuickScanCommand;
        DefenderFullScanCommand = FullScanCommand;
        DefenderCustomScanCommand = CustomScanCommand;
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
        _defenderRefreshTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMinutes(1)
        };
        _defenderRefreshTimer.Tick += (_, _) => _ = RefreshDefenderStatusAsync();
        _defenderRefreshTimer.Start();
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
        var dialog = new OpenFolderDialog { Title = "Choisir un dossier à analyser avec Microsoft Defender", Multiselect = false };
        if (dialog.ShowDialog() == true) _ = RunDefenderScanAsync(ScanType.Custom, dialog.FolderName);
    }

    private async Task RunDefenderScanAsync(ScanType type, string? path = null)
    {
        if (IsDefenderScanRunning) return;
        IsDefenderScanRunning = true;
        DefenderScanStatus = "Demande d’analyse Microsoft Defender… Windows peut demander une autorisation UAC.";
        try
        {
            var result = await _defender.RunScanAsync(type, path);
            DefenderScanStatus = result.Message;
            Session.RecordDefenderScan(type, path, result);
            Session.AddNotification(result.Outcome == DefenderScanOutcome.Completed
                    ? "Analyse Microsoft Defender terminée"
                    : "Vérification Microsoft Defender requise",
                result.Message,
                result.Outcome == DefenderScanOutcome.Completed ? "Information" : "Avertissement");
            await RefreshDefenderStatusAsync();
        }
        catch (Win32Exception exception) when (exception.NativeErrorCode == 1223)
        {
            DefenderScanStatus = "La demande d’autorisation Windows a été refusée; l’analyse n’a pas démarré.";
            Session.AddNotification("Analyse Defender annulée", DefenderScanStatus, "Information");
        }
        catch (Exception exception)
        {
            DefenderScanStatus = $"Analyse Microsoft Defender impossible : {exception.Message}";
            Session.AddNotification("Analyse Microsoft Defender impossible", exception.Message, "Avertissement");
        }
        finally { IsDefenderScanRunning = false; }
    }
}
