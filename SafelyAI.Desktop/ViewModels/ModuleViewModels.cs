using System.Collections.ObjectModel;
using System.IO;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Win32;
using SafelyAI.Desktop.Helpers;
using SafelyAI.Desktop.Models;
using SafelyAI.Desktop.Services;
using SafelyAI.Identity.AccountAudit;
using SafelyAI.Identity.PasswordPolicy;
using SafelyAI.Maintenance.Diagnostics;
using SafelyAI.Maintenance.Optimization;
using SafelyAI.Network.TrafficMonitoring;
using SafelyAI.SystemMonitor.ProcessMonitor;
using SafelyAI.SystemMonitor.StartupMonitor;
using SafelyAI.SystemMonitor.USBMonitor;
using SafelyAI.SystemMonitor.HardwareMonitor;
using SafelyAI.WebProtection.Certificates;
using SafelyAI.WebProtection.DomainReputation;
using SafelyAI.WebProtection.DownloadAnalysis;
using SafelyAI.WebProtection.PhishingDetection;
using SafelyAI.WebProtection.UrlAnalysis;
using System.Windows;

namespace SafelyAI.Desktop.ViewModels;

public sealed class AntivirusViewModel : ObservableObject
{
    private ThreatListItem? _selectedThreat;
    private BackupListItem? _selectedBackup;
    public DesktopSession Session { get; }
    public ObservableCollection<ScanHistoryEntry> ScanHistory => Session.ScanHistory;
    public RelayCommand QuickScanCommand { get; }
    public RelayCommand FullScanCommand { get; }
    public RelayCommand CancelScanCommand { get; }
    public RelayCommand CustomScanCommand { get; }
    public RelayCommand QuarantineCommand { get; }
    public RelayCommand RegisterSignatureCommand { get; }
    public RelayCommand ToggleDownloadMonitoringCommand { get; }
    public RelayCommand ToggleFolderMonitoringCommand { get; }
    public RelayCommand CreateBackupCommand { get; }
    public RelayCommand RestoreBackupCommand { get; }
    public RelayCommand RefreshUsbCommand { get; }
    public RelayCommand UsbScanCommand { get; }
    public ObservableCollection<string> RemovableDrives { get; } = [];
    private string? _selectedRemovableDrive;
    public string? SelectedRemovableDrive { get => _selectedRemovableDrive; set => Set(ref _selectedRemovableDrive, value); }
    public BackupListItem? SelectedBackup { get => _selectedBackup; set { if (Set(ref _selectedBackup, value)) OnPropertyChanged(nameof(CanRestoreBackup)); } }
    public bool CanRestoreBackup => SelectedBackup is not null;
    public string DownloadMonitorLabel => Session.IsDownloadMonitoring ? "Arrêter la surveillance des téléchargements" : "Surveiller les téléchargements";
    public string FolderMonitorLabel => Session.IsFolderMonitoring ? "Arrêter la surveillance du dossier" : "Surveiller un dossier protégé";
    public ThreatListItem? SelectedThreat { get => _selectedThreat; set { if (Set(ref _selectedThreat, value)) OnPropertyChanged(nameof(CanQuarantine)); } }
    public bool CanQuarantine => SelectedThreat is not null && !IsScanRunning;
    public bool CanStartScan => Session.CanStartScan;
    public bool IsScanRunning => Session.IsScanRunning;
    public int Progress => Session.ScanProgress;

    public AntivirusViewModel(DesktopSession session)
    {
        Session = session;
        QuickScanCommand = new(_ => _ = Session.RunScanAsync(ScanType.Quick));
        FullScanCommand = new(_ => _ = Session.RunScanAsync(ScanType.Full));
        CancelScanCommand = new(_ => Session.CancelScan());
        CustomScanCommand = new(_ => SelectCustomFolder());
        QuarantineCommand = new(_ => QuarantineSelected());
        RegisterSignatureCommand = new(_ => RegisterSelectedSignature());
        ToggleDownloadMonitoringCommand = new(_ => { Session.ToggleDownloadMonitoring(); OnPropertyChanged(nameof(DownloadMonitorLabel)); });
        ToggleFolderMonitoringCommand = new(_ => ToggleFolderMonitoring());
        CreateBackupCommand = new(_ => CreateBackup());
        RestoreBackupCommand = new(_ => RestoreBackup());
        RefreshUsbCommand = new(_ => RefreshUsbDrives());
        UsbScanCommand = new(_ => { if (SelectedRemovableDrive is { } drive) _ = Session.RunScanAsync(ScanType.Usb, drive); });
        RefreshUsbDrives();
        Session.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName is nameof(DesktopSession.IsScanRunning) or nameof(DesktopSession.ScanProgress))
            {
                OnPropertyChanged(nameof(CanStartScan)); OnPropertyChanged(nameof(IsScanRunning)); OnPropertyChanged(nameof(Progress));
                OnPropertyChanged(nameof(CanQuarantine));
            }
            if (e.PropertyName == nameof(DesktopSession.IsDownloadMonitoring)) OnPropertyChanged(nameof(DownloadMonitorLabel));
            if (e.PropertyName == nameof(DesktopSession.IsFolderMonitoring)) OnPropertyChanged(nameof(FolderMonitorLabel));
        };
    }

    private void SelectCustomFolder()
    {
        var dialog = new Microsoft.Win32.OpenFolderDialog { Title = "Choisir le dossier à analyser", Multiselect = false };
        if (dialog.ShowDialog() == true) _ = Session.RunScanAsync(ScanType.Custom, dialog.FolderName);
    }

    private void QuarantineSelected()
    {
        if (SelectedThreat is not { } threat) return;
        var answer = MessageBox.Show($"Déplacer ce fichier vers la quarantaine ?\n\n{threat.Location}\n\nIl ne sera pas supprimé et pourra être restauré.", "Confirmer la mise en quarantaine", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (answer != MessageBoxResult.Yes) return;
        try { Session.QuarantineThreat(threat); SelectedThreat = null; }
        catch (Exception ex) { Session.AddNotification("Mise en quarantaine impossible", ex.Message, "Avertissement"); }
    }

    private void RegisterSelectedSignature()
    {
        if (SelectedThreat is not { } threat) return;
        if (MessageBox.Show($"Ajouter l’empreinte SHA-256 de ce fichier à la base locale ? Ne le faites que si vous avez vérifié qu’il est malveillant.\n\n{threat.Name}\n{threat.Sha256}", "Confirmer la signature locale", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try { Session.RegisterThreatSignature(threat); }
        catch (Exception ex) { Session.AddNotification("Ajout de signature impossible", ex.Message, "Avertissement"); }
    }

    private void RefreshUsbDrives()
    {
        var selected = SelectedRemovableDrive;
        RemovableDrives.Clear();
        foreach (var drive in new SafelyAI.Antivirus.FileScanner.RemovableDriveScanner(new SafelyAI.Antivirus.FileScanner.FileScannerService()).GetReadyDrives()) RemovableDrives.Add(drive);
        SelectedRemovableDrive = selected is not null && RemovableDrives.Contains(selected) ? selected : RemovableDrives.FirstOrDefault();
    }

    private void ToggleFolderMonitoring()
    {
        if (Session.IsFolderMonitoring) { Session.ToggleFolderMonitoring(Session.MonitoredFolder); OnPropertyChanged(nameof(FolderMonitorLabel)); return; }
        var dialog = new Microsoft.Win32.OpenFolderDialog { Title = "Choisir le dossier à protéger contre les modifications massives", Multiselect = false };
        if (dialog.ShowDialog() == true) { Session.ToggleFolderMonitoring(dialog.FolderName); OnPropertyChanged(nameof(FolderMonitorLabel)); }
    }

    private void CreateBackup()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog { Title = "Choisir un fichier à sauvegarder", CheckFileExists = true, Multiselect = false };
        if (dialog.ShowDialog() != true) return;
        try { Session.CreateBackup(dialog.FileName); }
        catch (Exception ex) { Session.AddNotification("Sauvegarde impossible", ex.Message, "Avertissement"); }
    }

    private void RestoreBackup()
    {
        if (SelectedBackup is not { } item) return;
        if (MessageBox.Show($"Restaurer une copie de {item.Name} ? Si le fichier d’origine existe, la copie restaurée sera créée sous un autre nom.", "Confirmer la restauration", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try { Session.RestoreBackup(item); }
        catch (Exception ex) { Session.AddNotification("Restauration impossible", ex.Message, "Avertissement"); }
    }
}

public sealed class QuarantineViewModel : ObservableObject
{
    private readonly DesktopSession _session;
    private QuarantineListItem? _selectedItem;
    public ObservableCollection<QuarantineListItem> Items => _session.Quarantine;
    public QuarantineListItem? SelectedItem { get => _selectedItem; set { if (Set(ref _selectedItem, value)) { OnPropertyChanged(nameof(CanAct)); } } }
    public bool CanAct => SelectedItem is not null;
    public RelayCommand RestoreCommand { get; }
    public RelayCommand DeleteCommand { get; }
    public QuarantineViewModel(DesktopSession session)
    {
        _session = session;
        RestoreCommand = new(_ => RestoreSelected());
        DeleteCommand = new(_ => DeleteSelected());
    }
    private void RestoreSelected()
    {
        if (SelectedItem is not { } item) return;
        if (MessageBox.Show($"Restaurer {item.Name} à son emplacement d’origine ? Le fichier sera de nouveau accessible.", "Confirmer la restauration", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        try { _session.RestoreQuarantine(item); SelectedItem = null; }
        catch (Exception ex) { _session.AddNotification("Restauration impossible", ex.Message, "Avertissement"); }
    }
    private void DeleteSelected()
    {
        if (SelectedItem is not { } item) return;
        if (MessageBox.Show($"Supprimer définitivement {item.Name} ? Cette action est irréversible.", "Confirmer la suppression définitive", MessageBoxButton.YesNo, MessageBoxImage.Error) != MessageBoxResult.Yes) return;
        try { _session.DeleteQuarantine(item); SelectedItem = null; }
        catch (Exception ex) { _session.AddNotification("Suppression impossible", ex.Message, "Avertissement"); }
    }
}

public sealed record NetworkConnectionRow(string LocalAddress, int LocalPort, string RemoteAddress, int RemotePort, string State);

public sealed class NetworkViewModel : ObservableObject
{
    private string _firewallStatus = "État en cours de lecture…";
    private string _trafficSummary = "—";
    private string _message = "Actualisez pour lire les connexions réseau locales.";
    private bool _isLoading;
    public ObservableCollection<NetworkConnectionRow> Connections { get; } = [];
    public string FirewallStatus { get => _firewallStatus; private set => Set(ref _firewallStatus, value); }
    public string TrafficSummary { get => _trafficSummary; private set => Set(ref _trafficSummary, value); }
    public string Message { get => _message; private set => Set(ref _message, value); }
    public bool IsLoading { get => _isLoading; private set { if (Set(ref _isLoading, value)) OnPropertyChanged(nameof(CanRefresh)); } }
    public bool CanRefresh => !IsLoading;
    public RelayCommand RefreshCommand { get; }

    public NetworkViewModel() { RefreshCommand = new(_ => _ = RefreshAsync()); _ = RefreshAsync(); }

    private async Task RefreshAsync()
    {
        if (IsLoading) return;
        IsLoading = true;
        try
        {
            var rows = await Task.Run(() => IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections()
                .Select(c => new NetworkConnectionRow(c.LocalEndPoint.Address.ToString(), c.LocalEndPoint.Port,
                    c.RemoteEndPoint.Address.ToString(), c.RemoteEndPoint.Port, c.State.ToString()))
                .OrderBy(c => c.State).ThenBy(c => c.RemoteAddress).ToList());
            Connections.Clear(); foreach (var row in rows) Connections.Add(row);
            var totals = await Task.Run(TrafficMonitor.GetTotals);
            TrafficSummary = $"{FormatBytes(totals.Sent)} envoyés · {FormatBytes(totals.Received)} reçus (compteurs cumulés)";
            FirewallStatus = await Task.Run(() => new SafelyAI.Network.Firewall.FirewallManager().GetStatus());
            if (string.IsNullOrWhiteSpace(FirewallStatus) || FirewallStatus.StartsWith("ERREUR:", StringComparison.OrdinalIgnoreCase)) FirewallStatus = "État du pare-feu indisponible";
            Message = $"{Connections.Count} connexion(s) TCP visibles sur cet appareil.";
        }
        catch (Exception ex) { Message = $"Lecture réseau impossible : {ex.Message}"; }
        finally { IsLoading = false; }
    }

    private static string FormatBytes(long bytes) => bytes >= 1_000_000_000 ? $"{bytes / 1_000_000_000d:0.0} Go" : $"{bytes / 1_000_000d:0.0} Mo";
}

public sealed record ProcessRow(int Pid, string Name, double MemoryMb, string Path);

public sealed class SystemViewModel : ObservableObject
{
    private readonly ProcessMonitor _monitor = new();
    private string _cpu = "—", _ram = "—", _disk = "—", _status = "Chargement des mesures locales…";
    private string _searchText = "";
    private bool _isLoading;
    private List<ProcInfo> _allProcesses = [];
    private string _extendedStatus = "Les détails avancés de Windows ne sont pas encore chargés.";
    private string _secureBoot = "Non vérifié", _tpm = "Non vérifié", _bitLocker = "Non vérifié";
    public ObservableCollection<ProcessRow> Processes { get; } = [];
    public ObservableCollection<string> Services { get; } = [];
    public ObservableCollection<string> ScheduledTasks { get; } = [];
    public ObservableCollection<string> Drivers { get; } = [];
    public ObservableCollection<string> RecentErrors { get; } = [];
    public ObservableCollection<string> UsbDevices { get; } = [];
    public ObservableCollection<StartupItem> StartupPrograms { get; } = [];
    public string Cpu { get => _cpu; private set => Set(ref _cpu, value); }
    public string Ram { get => _ram; private set => Set(ref _ram, value); }
    public string Disk { get => _disk; private set => Set(ref _disk, value); }
    public string Status { get => _status; private set => Set(ref _status, value); }
    public string ExtendedStatus { get => _extendedStatus; private set => Set(ref _extendedStatus, value); }
    public string SecureBoot { get => _secureBoot; private set => Set(ref _secureBoot, value); }
    public string Tpm { get => _tpm; private set => Set(ref _tpm, value); }
    public string BitLocker { get => _bitLocker; private set => Set(ref _bitLocker, value); }
    public bool IsLoading { get => _isLoading; private set => Set(ref _isLoading, value); }
    public string SearchText { get => _searchText; set { if (Set(ref _searchText, value)) ApplyFilter(); } }
    public RelayCommand RefreshCommand { get; }
    public RelayCommand RefreshWindowsDetailsCommand { get; }

    public SystemViewModel()
    {
        RefreshCommand = new(_ => _ = RefreshAsync());
        RefreshWindowsDetailsCommand = new(_ => _ = RefreshWindowsDetailsAsync());
        _ = RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        if (IsLoading) return;
        IsLoading = true;
        try
        {
            var cpu = await _monitor.GetCpuPercentAsync(500);
            _allProcesses = await Task.Run(() => _monitor.GetProcesses());
            Cpu = $"{cpu:0}%";
            Ram = $"{ProcessMonitor.GetRamUsedPercent():0}% utilisée";
            var disks = ProcessMonitor.GetDisks();
            Disk = disks.Count == 0 ? "Indisponible" : string.Join(" · ", disks.Select(d => $"{d.Drive} {d.FreeGb:0.0} Go libres"));
            ApplyFilter();
            Status = $"Mesures locales · {_allProcesses.Count} processus détectés · actualisé à {DateTime.Now:HH:mm:ss}";
        }
        catch (Exception ex) { Status = $"Lecture du système impossible : {ex.Message}"; }
        finally { IsLoading = false; }
    }

    private void ApplyFilter()
    {
        Processes.Clear();
        foreach (var p in _allProcesses.Where(p => string.IsNullOrWhiteSpace(SearchText)
                     || p.Name.Contains(SearchText, StringComparison.OrdinalIgnoreCase)
                     || p.Pid.ToString().Contains(SearchText, StringComparison.OrdinalIgnoreCase)).Take(250))
            Processes.Add(new ProcessRow(p.Pid, p.Name, p.MemoryMb, p.Path ?? "Accès refusé"));
    }

    private async Task RefreshWindowsDetailsAsync()
    {
        if (IsLoading) return;
        IsLoading = true;
        ExtendedStatus = "Lecture des composants Windows…";
        try
        {
            var data = await Task.Run(() =>
            {
                var inspector = new SystemInspector();
                var hardware = new HardwareMonitor();
                return (services: inspector.GetRunningServices(), tasks: inspector.GetScheduledTasks(), drivers: inspector.GetDrivers(),
                    errors: inspector.GetRecentSystemErrors(), startup: new StartupMonitor().GetItems(), usb: new UsbMonitor().GetUsbDevices(),
                    secureBoot: hardware.GetSecureBootStatus(), tpm: hardware.GetTpmStatus(), bitLocker: hardware.GetBitLockerStatus());
            });
            Replace(Services, data.services); Replace(ScheduledTasks, data.tasks); Replace(Drivers, data.drivers);
            Replace(RecentErrors, data.errors); Replace(StartupPrograms, data.startup); Replace(UsbDevices, data.usb);
            SecureBoot = Clean(data.secureBoot); Tpm = Clean(data.tpm); BitLocker = Clean(data.bitLocker);
            ExtendedStatus = "Détails Windows actualisés en lecture seule.";
        }
        catch (Exception ex) { ExtendedStatus = $"Détails Windows indisponibles : {ex.Message}"; }
        finally { IsLoading = false; }
    }

    private static void Replace<T>(ObservableCollection<T> target, IEnumerable<T> values)
    {
        target.Clear(); foreach (var value in values) target.Add(value);
    }
    private static string Clean(string value) => string.IsNullOrWhiteSpace(value) ? "Inconnu" : value.Trim();
}

public sealed class IdentityViewModel : ObservableObject
{
    private readonly DesktopSession _session;
    private string _status = "L’audit n’a pas encore été lancé.";
    private string _failedLogins = "Non vérifié";
    private string _privilegeChanges = "Non vérifié";
    private string _sessions = "Non vérifiées";
    private string _passwordPolicy = "Non vérifiée";
    private bool _isLoading;
    public ObservableCollection<WindowsAccount> Accounts { get; } = [];
    public string Status { get => _status; private set => Set(ref _status, value); }
    public string FailedLogins { get => _failedLogins; private set => Set(ref _failedLogins, value); }
    public string PrivilegeChanges { get => _privilegeChanges; private set => Set(ref _privilegeChanges, value); }
    public string Sessions { get => _sessions; private set => Set(ref _sessions, value); }
    public string PasswordPolicySummary { get => _passwordPolicy; private set => Set(ref _passwordPolicy, value); }
    public bool IsLoading { get => _isLoading; private set { if (Set(ref _isLoading, value)) OnPropertyChanged(nameof(CanAudit)); } }
    public bool CanAudit => !IsLoading;
    public RelayCommand AuditCommand { get; }
    public IdentityViewModel(DesktopSession session) { _session = session; AuditCommand = new(_ => _ = AuditAsync()); }

    private async Task AuditAsync()
    {
        if (IsLoading) return;
        IsLoading = true;
        try
        {
            var result = await Task.Run(() =>
            {
                var auditor = new AccountAuditor();
                var accounts = auditor.Audit();
                var sessions = new SafelyAI.Identity.SessionMonitoring.SessionMonitor();
                var policy = SafeReadPolicy();
                return (accounts, alerts: auditor.FindSuspicious(accounts), failed: sessions.FailedLogins(), changes: sessions.PrivilegeChanges(),
                    sessionsText: SafeRead(sessions.CurrentSessions), policy);
            });
            Accounts.Clear(); foreach (var account in result.accounts) Accounts.Add(account);
            FailedLogins = result.failed < 0 ? "Non accessible" : result.failed.ToString();
            PrivilegeChanges = result.changes < 0 ? "Non accessible" : result.changes.ToString();
            Sessions = string.IsNullOrWhiteSpace(result.sessionsText) ? "Aucune session remontée" : result.sessionsText;
            PasswordPolicySummary = result.policy is null ? "Politique non accessible (droits requis ou secedit indisponible)." :
                $"Minimum {result.policy.MinLength} caractères · expiration {result.policy.MaxAgeDays} jours · complexité {(result.policy.ComplexityRequired ? "exigée" : "non exigée")} · seuil de verrouillage {result.policy.LockoutThreshold}";
            Status = result.alerts.Count == 0
                ? $"Audit terminé · {Accounts.Count} compte(s) local(aux)"
                : $"Audit terminé · {result.alerts.Count} point(s) à examiner : {string.Join("; ", result.alerts)}";
            _session.AddActivity("Identité", "Audit des comptes terminé", Status);
            if (result.alerts.Count > 0) _session.AddNotification("Audit des comptes", Status, "Avertissement");
        }
        catch (Exception ex) { Status = $"Audit indisponible : {ex.Message}"; }
        finally { IsLoading = false; }
    }

    private static string SafeRead(Func<string> read) { try { return read(); } catch (Exception ex) { return ex.Message; } }
    private static PasswordPolicy? SafeReadPolicy() { try { return new PasswordPolicyChecker().Read(); } catch { return null; } }
}

public sealed class WebProtectionViewModel : ObservableObject
{
    private readonly DesktopSession _session;
    private string _url = "";
    private string _status = "Les vérifications de réputation et de phishing sont locales et heuristiques.";
    private string _riskLevel = "Aucune analyse";
    private int _riskScore;
    private string _certificateSummary = "Certificat non vérifié";
    private string _downloadSummary = "Aucun fichier analysé";
    private bool _isWorking;
    public ObservableCollection<string> Findings { get; } = [];
    public string Url { get => _url; set { if (Set(ref _url, value)) OnPropertyChanged(nameof(CanCheckCertificate)); } }
    public string Status { get => _status; private set => Set(ref _status, value); }
    public string RiskLevel { get => _riskLevel; private set => Set(ref _riskLevel, value); }
    public int RiskScore { get => _riskScore; private set => Set(ref _riskScore, value); }
    public string CertificateSummary { get => _certificateSummary; private set => Set(ref _certificateSummary, value); }
    public string DownloadSummary { get => _downloadSummary; private set => Set(ref _downloadSummary, value); }
    public bool IsWorking { get => _isWorking; private set { if (Set(ref _isWorking, value)) OnPropertyChanged(nameof(CanCheckCertificate)); } }
    public bool CanCheckCertificate => !IsWorking && Uri.TryCreate(Url, UriKind.Absolute, out var uri) && uri.Scheme == Uri.UriSchemeHttps;
    public RelayCommand AnalyzeUrlCommand { get; }
    public RelayCommand CheckCertificateCommand { get; }
    public RelayCommand AnalyzeDownloadCommand { get; }
    public WebProtectionViewModel(DesktopSession session)
    {
        _session = session;
        AnalyzeUrlCommand = new(_ => AnalyzeUrl());
        CheckCertificateCommand = new(_ => _ = CheckCertificateAsync());
        AnalyzeDownloadCommand = new(_ => _ = AnalyzeDownloadAsync());
    }

    private void AnalyzeUrl()
    {
        var candidate = Url.Trim();
        if (string.IsNullOrWhiteSpace(candidate)) { Status = "Saisissez une adresse à analyser."; return; }
        if (!candidate.Contains("://", StringComparison.Ordinal)) candidate = "https://" + candidate;
        var urlResult = new UrlAnalyzer().Analyze(candidate);
        var phishing = new PhishingDetector().Analyze(candidate);
        var reputation = new DomainReputationChecker().Analyze(candidate);
        SetFindings(urlResult.Risks.Concat(phishing.Findings).Concat(reputation.Findings));
        if (Findings.Count == 0) Findings.Add("Aucun signal heuristique trouvé. Cela ne garantit pas que le site est sûr.");
        RiskScore = Math.Max(urlResult.RiskScore, Math.Max(phishing.RiskScore, reputation.RiskScore));
        RiskLevel = RiskScore >= 60 ? "Élevé" : RiskScore >= 20 ? "Modéré" : "Faible";
        Status = $"Analyse locale terminée pour {candidate} · aucune réputation Internet n’a été consultée.";
        Url = candidate;
        _session.AddActivity("Protection Web", "URL analysée localement", $"{RiskLevel} · {candidate}");
    }

    private async Task CheckCertificateAsync()
    {
        if (!Uri.TryCreate(Url, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
        { CertificateSummary = "Saisissez une URL HTTPS valide avant de vérifier le certificat."; return; }
        IsWorking = true;
        try
        {
            var result = await new CertificateAnalyzer().AnalyzeAsync(Url);
            CertificateSummary = result.ConnectionSuccessful
                ? $"{result.RiskLevel} · expire le {result.ExpirationDate:dd/MM/yyyy} · émis par {result.Issuer}"
                : string.Join(" ", result.Findings);
            _session.AddActivity("Protection Web", "Certificat HTTPS vérifié", $"{uri.Host} · {result.RiskLevel}");
        }
        catch (Exception ex) { CertificateSummary = $"Vérification impossible : {ex.Message}"; }
        finally { IsWorking = false; }
    }

    private async Task AnalyzeDownloadAsync()
    {
        var dialog = new OpenFileDialog { Title = "Choisir un téléchargement à examiner", CheckFileExists = true, Multiselect = false };
        if (dialog.ShowDialog() != true) return;
        IsWorking = true;
        Status = "Lecture du fichier et calcul de son empreinte…";
        try
        {
            var result = await Task.Run(() => new DownloadAnalyzer().Analyze(dialog.FileName));
            DownloadSummary = $"{result.FileName} · {FormatBytes(result.FileSize)} · risque {result.RiskLevel} ({result.RiskScore}/100) · SHA-256 {result.SHA256}";
            SetFindings(result.Findings);
            RiskLevel = result.RiskLevel; RiskScore = result.RiskScore;
            Status = "Analyse locale du fichier terminée · aucune signature antivirus n’a été vérifiée.";
            _session.AddActivity("Protection Web", "Téléchargement analysé localement", $"{result.FileName} · risque {result.RiskLevel}");
        }
        catch (Exception ex) { Status = $"Analyse du fichier impossible : {ex.Message}"; }
        finally { IsWorking = false; }
    }
    private void SetFindings(IEnumerable<string> findings)
    {
        Findings.Clear();
        foreach (var finding in findings.Distinct()) Findings.Add(finding);
    }
    private static string FormatBytes(long size) => size >= 1_000_000 ? $"{size / 1_000_000d:0.0} Mo" : $"{size / 1_000d:0} Ko";
}

public sealed class CleanupCandidate : ObservableObject
{
    private bool _isSelected;
    public string Path { get; }
    public string Name => System.IO.Path.GetFileName(Path);
    public long Size { get; }
    public bool IsSelected { get => _isSelected; set => Set(ref _isSelected, value); }
    public CleanupCandidate(string path, long size) { Path = path; Size = size; }
}

public sealed class MaintenanceViewModel : ObservableObject
{
    private readonly DesktopSession _session;
    private string _status = "Lancez une analyse pour examiner les fichiers temporaires.";
    private string _systemSummary = "Diagnostic système non lancé";
    private string _updateStatus = "Mise à jour Windows non vérifiée";
    private bool _isLoading;
    public ObservableCollection<CleanupCandidate> Candidates { get; } = [];
    public string Status { get => _status; private set => Set(ref _status, value); }
    public string SystemSummary { get => _systemSummary; private set => Set(ref _systemSummary, value); }
    public string UpdateStatus { get => _updateStatus; private set => Set(ref _updateStatus, value); }
    public bool IsLoading { get => _isLoading; private set { if (Set(ref _isLoading, value)) { OnPropertyChanged(nameof(CanAnalyze)); OnPropertyChanged(nameof(CanClean)); } } }
    public int SelectedCount => Candidates.Count(x => x.IsSelected);
    public bool CanAnalyze => !IsLoading;
    public bool CanClean => SelectedCount > 0 && !IsLoading;
    public RelayCommand AnalyzeCommand { get; }
    public RelayCommand CleanSelectedCommand { get; }
    public MaintenanceViewModel(DesktopSession session)
    {
        _session = session;
        AnalyzeCommand = new(_ => _ = AnalyzeAsync());
        CleanSelectedCommand = new(_ => CleanSelected());
        Candidates.CollectionChanged += (_, _) => OnPropertyChanged(nameof(SelectedCount));
    }
    private async Task AnalyzeAsync()
    {
        if (IsLoading) return;
        IsLoading = true;
        try
        {
            var result = await Task.Run(() => (system: new SystemDiagnostics().Analyze(), temp: new SystemOptimizer().AnalyzeTemporaryFiles(), updates: ReadWindowsUpdateStatus()));
            var s = result.system;
            SystemSummary = s.Success
                ? $"{s.ComputerName} · {s.OperatingSystem} · RAM {s.AvailableMemoryGB:0.0}/{s.TotalMemoryGB:0.0} Go disponibles · disque système {s.FreeDiskSpaceGB:0.0}/{s.TotalDiskSpaceGB:0.0} Go libres"
                : s.Status;
            UpdateStatus = result.updates;
            Candidates.Clear(); foreach (var file in result.temp.Files)
            {
                try
                {
                    var candidate = new CleanupCandidate(file, new FileInfo(file).Length);
                    candidate.PropertyChanged += (_, _) => { OnPropertyChanged(nameof(SelectedCount)); OnPropertyChanged(nameof(CanClean)); };
                    Candidates.Add(candidate);
                }
                catch { }
            }
            Status = result.temp.Success
                ? $"Analyse terminée sans suppression · {result.temp.FilesFound} fichier(s) · {FormatBytes(result.temp.TotalSize)} · {result.temp.SkippedFiles} ignoré(s)"
                : result.temp.Message;
            _session.AddActivity("Maintenance", "Analyse des fichiers temporaires", Status);
            OnPropertyChanged(nameof(SelectedCount));
            OnPropertyChanged(nameof(CanClean));
        }
        catch (Exception ex) { Status = $"Diagnostic impossible : {ex.Message}"; }
        finally { IsLoading = false; }
    }
    private void CleanSelected()
    {
        var selected = Candidates.Where(c => c.IsSelected).Select(c => c.Path).ToList();
        if (selected.Count == 0) { Status = "Sélectionnez au moins un fichier temporaire."; return; }
        var answer = MessageBox.Show($"Supprimer {selected.Count} fichier(s) sélectionné(s) du dossier temporaire ? Cette action ne peut pas être annulée.", "Confirmer le nettoyage", MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (answer != MessageBoxResult.Yes) return;
        var result = new SystemOptimizer().CleanTemporaryFiles(selected, confirmed: true);
        foreach (var item in Candidates.Where(c => selected.Contains(c.Path)).ToList()) Candidates.Remove(item);
        Status = $"{result.FilesDeleted} fichier(s) supprimé(s) · {result.SkippedFiles} ignoré(s) · {FormatBytes(result.TotalSize)} libérés";
        _session.AddActivity("Maintenance", "Nettoyage confirmé", Status);
        _session.AddNotification("Nettoyage terminé", Status, "Information");
        OnPropertyChanged(nameof(SelectedCount));
        OnPropertyChanged(nameof(CanClean));
    }
    private static string FormatBytes(long size) => size >= 1_000_000_000 ? $"{size / 1_000_000_000d:0.00} Go" : $"{size / 1_000_000d:0.0} Mo";

    private static string ReadWindowsUpdateStatus()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install");
            var value = key?.GetValue("LastSuccessTime")?.ToString();
            return DateTime.TryParse(value, out var date) ? $"Dernière installation réussie : {date:dd/MM/yyyy HH:mm}" : "Aucune date de réussite disponible dans le registre.";
        }
        catch (Exception ex) { return $"État des mises à jour indisponible : {ex.Message}"; }
    }
}

public sealed class ReportsViewModel(DesktopSession session) : ObservableObject
{
    public ObservableCollection<ScanHistoryEntry> ScanHistory => session.ScanHistory;
    public ObservableCollection<ActivityEntry> Activity => session.Activity;
    public RelayCommand ExportCommand { get; } = new(_ => Export(session));
    private static void Export(DesktopSession session)
    {
        var dialog = new SaveFileDialog { Title = "Enregistrer le rapport SAFELY AI", FileName = $"safelyai-rapport-{DateTime.Now:yyyyMMdd-HHmm}.txt", Filter = "Rapport texte (*.txt)|*.txt" };
        if (dialog.ShowDialog() != true) return;
        var lines = new List<string> { "SAFELY AI — Rapport de sécurité", $"Généré le {DateTime.Now:dd/MM/yyyy à HH:mm}", "", "NOTE : Les résultats heuristiques sont à vérifier. La base locale comprend EICAR et les signatures SHA-256 ajoutées par l’utilisateur.", "", "SESSIONS D’ANALYSE" };
        lines.AddRange(session.ScanHistory.Select(x => $"{x.FinishedAt:dd/MM/yyyy HH:mm} | {x.Type} | {x.Scope} | {x.FilesScanned} fichiers analysés | {x.ThreatsFound} indicateur(s)"));
        lines.AddRange(["", "ACTIVITÉ RÉCENTE"]);
        lines.AddRange(session.Activity.Select(x => $"{x.CreatedAt:dd/MM/yyyy HH:mm:ss} | {x.Category} | {x.Title} | {x.Details}"));
        try
        {
            File.WriteAllLines(dialog.FileName, lines);
            session.AddNotification("Rapport exporté", $"Enregistré dans {dialog.FileName}", "Information");
        }
        catch (Exception ex) { session.AddNotification("Export du rapport impossible", ex.Message, "Avertissement"); }
    }
}
