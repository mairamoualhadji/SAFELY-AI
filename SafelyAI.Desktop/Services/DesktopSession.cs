using System.IO;
using System.Collections.ObjectModel;
using SafelyAI.Desktop.Helpers;
using SafelyAI.Desktop.Models;
using SafelyAI.Antivirus.FileScanner;
using SafelyAI.Antivirus.RansomwareProtection;
using SafelyAI.Antivirus.Quarantine;
using SafelyAI.Antivirus.SignatureEngine;

namespace SafelyAI.Desktop.Services;

public sealed record ScanHistoryEntry(string Type, string Scope, int FilesScanned, int ThreatsFound, DateTime FinishedAt);
public sealed record ActivityEntry(string Category, string Title, string Details, DateTime CreatedAt);
public sealed record DesktopNotification(string Title, string Message, string Level, DateTime CreatedAt);

/// <summary>Shared state for desktop scans, threat findings, and the local quarantine.</summary>
public sealed class DesktopSession : ObservableObject
{
    private readonly IScanService _scanner = new AntivirusScanService();
    private readonly QuarantineManager _quarantine = new();
    private readonly FileBackupManager _backups = new();
    private readonly ScanHistoryStore _scanHistoryStore = new();
    private readonly ActivityHistoryStore _activityHistoryStore = new();
    private readonly DefenderScanHistoryStore _defenderScanHistoryStore = new();
    private readonly ThreatHistoryStore _threatHistoryStore = new();
    private readonly FileChangeHistoryStore _fileChangeHistoryStore = new();
    private DownloadMonitor? _downloadMonitor;
    private FileBehaviorMonitor? _fileBehaviorMonitor;
    private CancellationTokenSource? _scanCancellation;
    private bool _isScanRunning;
    private int _scanProgress;
    private string _scanStatus = "Aucune analyse lancée";
    private string _scanScope = "";
    private ScanHistoryEntry? _lastScan;
    private string _protectionMode = "Équilibré";

    public ObservableCollection<ScanHistoryEntry> ScanHistory { get; } = [];
    public ObservableCollection<ActivityEntry> Activity { get; } = [];
    public ObservableCollection<ActivityEntry> ActivityHistory { get; } = [];
    public ObservableCollection<DefenderScanHistoryEntry> DefenderScanHistory { get; } = [];
    public ObservableCollection<DesktopNotification> Notifications { get; } = [];
    public ObservableCollection<ThreatListItem> Threats { get; } = [];
    public ObservableCollection<ThreatHistoryRecord> ThreatHistory { get; } = [];
    public ObservableCollection<QuarantineListItem> Quarantine { get; } = [];
    public ObservableCollection<BackupListItem> Backups { get; } = [];
    public ObservableCollection<FileChangeListItem> FileChanges { get; } = [];
    private bool _isDownloadMonitoring;
    private bool _isFolderMonitoring;
    private bool _activityPersistenceWarningShown;
    public bool IsDownloadMonitoring { get => _isDownloadMonitoring; private set => Set(ref _isDownloadMonitoring, value); }
    public bool IsFolderMonitoring { get => _isFolderMonitoring; private set => Set(ref _isFolderMonitoring, value); }
    public string MonitoredFolder { get; private set; } = "Aucun dossier surveillé";

    public bool IsScanRunning { get => _isScanRunning; private set => Set(ref _isScanRunning, value); }
    public bool CanStartScan => !IsScanRunning;
    public int ScanProgress { get => _scanProgress; private set => Set(ref _scanProgress, value); }
    public string ScanStatus { get => _scanStatus; private set => Set(ref _scanStatus, value); }
    public string ScanScope { get => _scanScope; private set => Set(ref _scanScope, value); }
    public ScanHistoryEntry? LastScan { get => _lastScan; private set => Set(ref _lastScan, value); }
    public string ProtectionMode
    {
        get => _protectionMode;
        set
        {
            if (!Set(ref _protectionMode, value)) return;
            _downloadMonitor?.SetPollingInterval(DownloadMonitorInterval);
            OnPropertyChanged(nameof(DownloadMonitorIntervalLabel));
        }
    }
    private TimeSpan DownloadMonitorInterval => ProtectionMode switch
    {
        "Économie de ressources" => TimeSpan.FromSeconds(3),
        "Protection maximale" => TimeSpan.FromMilliseconds(500),
        _ => TimeSpan.FromSeconds(1)
    };
    public string DownloadMonitorIntervalLabel => $"Vérification des téléchargements : toutes les {DownloadMonitorInterval.TotalSeconds:0.##} s";
    public int NotificationCount => Notifications.Count;
    public DateTime? SignatureFeedUpdatedAtUtc => _scanner.MalwareBazaarUpdatedAtUtc;

    public DesktopSession()
    {
        Notifications.CollectionChanged += (_, _) => OnPropertyChanged(nameof(NotificationCount));
        RefreshQuarantine();
        RefreshBackups();
        var savedActivity = _activityHistoryStore.Read().Take(2_000).ToArray();
        foreach (var item in savedActivity.Reverse()) ActivityHistory.Add(item);
        foreach (var item in savedActivity.Take(100).Reverse()) Activity.Add(item);
        foreach (var item in _defenderScanHistoryStore.Read().Take(500).Reverse()) DefenderScanHistory.Add(item);
        foreach (var item in _scanHistoryStore.Read()) ScanHistory.Add(new(item.Type, item.Scope, item.FilesScanned, item.ThreatsFound, item.FinishedAt));
        LastScan = ScanHistory.FirstOrDefault();
        foreach (var finding in _threatHistoryStore.Read())
        {
            ThreatHistory.Add(finding);
            if (finding.Status == "À examiner")
                Threats.Add(new(finding.Name, finding.Location, finding.Severity, finding.DetectedAt, finding.Sha256));
        }
        foreach (var item in _fileChangeHistoryStore.Read()) FileChanges.Add(new(item.Path, item.ChangeType, item.OccurredAt));
        AddNotification("Protection locale prête", "La détection locale inclut le fichier de test EICAR. Ajoutez vos signatures SHA-256 approuvées au fichier local de signatures.", "Information");
    }

    public async Task<ScanHistoryEntry?> RunScanAsync(ScanType type, string? path = null)
    {
        if (IsScanRunning) return null;
        _scanCancellation = new CancellationTokenSource();
        IsScanRunning = true;
        OnPropertyChanged(nameof(CanStartScan));
        ScanProgress = 0;
        ScanScope = type is ScanType.Custom or ScanType.Usb ? path ?? "Dossier" : type == ScanType.Quick ? "Bureau, Téléchargements, Documents, Temp" : "Volumes fixes";
        ScanStatus = "Analyse locale en cours…";
        AddActivity("Analyse", $"{ScanLabel(type)} démarrée", $"Portée : {ScanScope}");
        try
        {
            var progress = new Progress<ScanProgress>(p =>
            {
                ScanProgress = p.Percent;
                ScanStatus = p.Message;
            });
            var result = await _scanner.RunAsync(type, path, progress, _scanCancellation.Token);
            AddFindings(result.Threats);
            var entry = new ScanHistoryEntry(ScanLabel(type), ScanScope, result.FilesScanned, result.ThreatsFound, result.FinishedAt);
            ScanHistory.Insert(0, entry);
            try { _scanHistoryStore.Append(new(entry.Type, entry.Scope, result.FilesScanned, result.ThreatsFound, result.SkippedFiles, result.BytesScanned, result.FinishedAt)); } catch { }
            LastScan = entry;
            ScanProgress = 100;
            ScanStatus = $"Terminée · {result.FilesScanned:N0} fichier(s) analysé(s) · {result.ThreatsFound} indicateur(s) · {result.SkippedFiles} ignoré(s)";
            AddActivity("Analyse", "Analyse locale terminée", $"{result.FilesScanned:N0} fichiers · {result.ThreatsFound} indicateur(s) · {result.BytesScanned / 1_000_000d:0.0} Mo lus");
            AddNotification("Analyse terminée", $"{ScanLabel(type)} : {result.FilesScanned:N0} fichier(s), {result.ThreatsFound} indicateur(s).", result.ThreatsFound > 0 ? "Avertissement" : "Information");
            return entry;
        }
        catch (OperationCanceledException)
        {
            ScanStatus = "Analyse annulée";
            AddActivity("Analyse", "Analyse annulée", ScanScope);
            AddNotification("Analyse annulée", "L’analyse a été arrêtée à votre demande.", "Information");
            return null;
        }
        catch (Exception ex)
        {
            ScanStatus = "Impossible de lancer l’analyse";
            AddNotification("Erreur d’analyse", ex.Message, "Avertissement");
            return null;
        }
        finally
        {
            IsScanRunning = false;
            OnPropertyChanged(nameof(CanStartScan));
            _scanCancellation?.Dispose();
            _scanCancellation = null;
        }
    }

    public void CancelScan() => _scanCancellation?.Cancel();

    public Task<SignatureFeedUpdateResult> UpdateSignatureFeedAsync(string authKey, CancellationToken cancellationToken = default) =>
        _scanner.UpdateSignaturesAsync(authKey, cancellationToken);

    public void QuarantineThreat(ThreatListItem threat)
    {
        var item = _quarantine.Quarantine(threat.Location, threat.Sha256);
        Threats.Remove(threat);
        SetThreatStatus(threat.Sha256, threat.Location, "En quarantaine");
        RefreshQuarantine();
        AddActivity("Antivirus", "Élément mis en quarantaine", threat.Location);
        AddNotification("Élément isolé", $"{threat.Name} a été déplacé en quarantaine.", "Information");
    }

    public void RegisterThreatSignature(ThreatListItem threat)
    {
        _scanner.RegisterSignature(threat.Sha256, threat.Name);
        AddActivity("Antivirus", "Signature locale ajoutée", $"{threat.Name} · SHA-256 {threat.Sha256}");
        AddNotification("Signature enregistrée", "L’empreinte SHA-256 sera reconnue lors des prochains scans sur cet ordinateur.", "Information");
    }

    public void RestoreQuarantine(QuarantineListItem item)
    {
        var restored = _quarantine.Restore(item.Id);
        SetThreatStatus(item.Sha256, item.OriginalPath, "Restaurée");
        RefreshQuarantine();
        AddActivity("Antivirus", "Élément restauré", restored);
        AddNotification("Restauration terminée", $"Fichier restauré dans {restored}.", "Information");
    }

    public void DeleteQuarantine(QuarantineListItem item)
    {
        _quarantine.DeletePermanently(item.Id);
        SetThreatStatus(item.Sha256, item.OriginalPath, "Supprimée");
        RefreshQuarantine();
        AddActivity("Antivirus", "Élément supprimé définitivement", item.Name);
        AddNotification("Suppression terminée", $"{item.Name} a été supprimé de la quarantaine.", "Information");
    }

    private void RefreshQuarantine()
    {
        Quarantine.Clear();
        foreach (var item in _quarantine.GetItems()) Quarantine.Add(new(item.Id, item.Name, item.OriginalPath, item.Sha256, item.IsolatedAt, "Isolé"));
    }

    public void AddNotification(string title, string message, string level)
    {
        Notifications.Insert(0, new DesktopNotification(title, message, level, DateTime.Now));
        if (Notifications.Count > 30) Notifications.RemoveAt(Notifications.Count - 1);
    }

    public void ClearNotifications() => Notifications.Clear();

    public void RefreshThreatHistory()
    {
        if (!_threatHistoryStore.TryRead(out var records))
        {
            AddNotification("Actualisation de l’historique impossible", "Le fichier local des menaces n’a pas pu être lu; les résultats actuellement affichés ont été conservés.", "Avertissement");
            return;
        }
        ThreatHistory.Clear();
        Threats.Clear();
        foreach (var record in records)
        {
            ThreatHistory.Add(record);
            if (record.Status == "À examiner")
                Threats.Add(new(record.Name, record.Location, record.Severity, record.DetectedAt, record.Sha256));
        }
    }

    public void AddActivity(string category, string title, string details)
    {
        category = Limit(category, 80, "Général");
        title = Limit(title, 200, "Événement");
        details = Limit(details, 8_000, "");
        var entry = new ActivityEntry(category, title, details, DateTime.Now);
        Activity.Insert(0, entry);
        if (Activity.Count > 100) Activity.RemoveAt(Activity.Count - 1);
        ActivityHistory.Insert(0, entry);
        if (ActivityHistory.Count > 2_000) ActivityHistory.RemoveAt(ActivityHistory.Count - 1);
        try { _activityHistoryStore.Append(entry); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException or System.Text.Json.JsonException)
        {
            if (_activityPersistenceWarningShown) return;
            _activityPersistenceWarningShown = true;
            AddNotification("Historique local indisponible", $"Les événements restent visibles pendant cette session, mais ne seront pas conservés après fermeture : {exception.Message}", "Avertissement");
        }
    }

    private static string Limit(string? value, int maximumLength, string fallback)
    {
        if (string.IsNullOrWhiteSpace(value)) return fallback;
        var trimmed = value.Trim();
        return trimmed.Length <= maximumLength ? trimmed : trimmed[..maximumLength];
    }

    public void RecordDefenderScan(ScanType type, string? path, DefenderScanResult result)
    {
        var record = new DefenderScanHistoryEntry(
            ScanLabel(type),
            string.IsNullOrWhiteSpace(path) ? (type == ScanType.Quick ? "Portée rapide Windows" : "Ordinateur") : Limit(path, 2_000, "Chemin personnalisé"),
            result.Outcome == DefenderScanOutcome.Completed ? "Commande terminée · vérifiez Sécurité Windows" : "À vérifier dans Sécurité Windows",
            Limit(result.Message, 2_000, "Résultat non fourni"),
            result.ExitCode,
            DateTime.Now);
        DefenderScanHistory.Insert(0, record);
        if (DefenderScanHistory.Count > 500) DefenderScanHistory.RemoveAt(DefenderScanHistory.Count - 1);
        try { _defenderScanHistoryStore.Append(record); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or System.Security.SecurityException or System.Text.Json.JsonException)
        {
            AddNotification("Historique des scans Defender indisponible", $"Le résultat reste visible dans l’activité de cette session : {exception.Message}", "Avertissement");
        }
        AddActivity("Microsoft Defender", record.Type, $"{record.Outcome} · code {record.ExitCode} · {record.Message}");
    }

    public static string ScanLabel(ScanType type) => type switch
    {
        ScanType.Quick => "Analyse rapide", ScanType.Full => "Analyse complète", ScanType.Usb => "Analyse USB", _ => "Analyse personnalisée"
    };

    public void ToggleDownloadMonitoring()
    {
        if (_downloadMonitor is not null)
        {
            _downloadMonitor.Dispose(); _downloadMonitor = null; IsDownloadMonitoring = false;
            AddActivity("Antivirus", "Surveillance des téléchargements arrêtée", ""); return;
        }
        _downloadMonitor = new DownloadMonitor(pollingInterval: DownloadMonitorInterval);
        _downloadMonitor.DownloadReady += (_, e) => _ = ScanDownloadedFileAsync(e.Path);
        _downloadMonitor.MonitoringError += message => System.Windows.Application.Current.Dispatcher.BeginInvoke(() => AddNotification("Surveillance des téléchargements dégradée", message, "Avertissement"));
        _downloadMonitor.Start(); IsDownloadMonitoring = true;
        AddActivity("Antivirus", "Surveillance des téléchargements activée", _downloadMonitor.DirectoryPath);
        AddNotification("Téléchargements surveillés", "Les nouveaux fichiers terminés dans Téléchargements seront analysés localement.", "Information");
    }

    private async Task ScanDownloadedFileAsync(string path)
    {
        try
        {
            var result = await _scanner.RunAsync(ScanType.Custom, path);
            await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
            {
                AddFindings(result.Threats);
                AddActivity("Antivirus", "Téléchargement analysé", $"{path} · {result.ThreatsFound} indicateur(s)");
                if (result.Threats.Any()) AddNotification("Indicateur dans un téléchargement", $"{Path.GetFileName(path)} : {string.Join(", ", result.Threats.Select(t => t.Name))}", "Avertissement");
            });

            // Exact signatures are high-confidence hash matches. Heuristic-only findings are never
            // auto-isolated; the user can review those in the threat list and decide what to do.
            foreach (var confirmed in result.Threats.Where(item => item.Severity == FileThreatSeverity.High))
            {
                try
                {
                    _quarantine.Quarantine(confirmed.Path, confirmed.Sha256);
                    await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                    {
                        var listed = Threats.FirstOrDefault(item => SameFinding(item.Sha256, item.Location, confirmed.Sha256, confirmed.Path));
                        if (listed is not null) Threats.Remove(listed);
                        SetThreatStatus(confirmed.Sha256, confirmed.Path, "En quarantaine");
                        RefreshQuarantine();
                        AddActivity("Antivirus", "Téléchargement connu isolé automatiquement", confirmed.Path);
                        AddNotification("Téléchargement connu mis en quarantaine", $"La correspondance SHA-256 exacte a été isolée. Le fichier est restaurable dans la quarantaine : {Path.GetFileName(confirmed.Path)}.", "Avertissement");
                    });
                }
                catch (Exception quarantineError)
                {
                    await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                        AddNotification("Menace connue détectée, isolement impossible", $"{confirmed.Path} · {quarantineError.Message}", "Avertissement"));
                }
            }
        }
        catch (Exception ex) { await System.Windows.Application.Current.Dispatcher.InvokeAsync(() => AddNotification("Analyse du téléchargement impossible", ex.Message, "Avertissement")); }
    }

    private void AddFindings(IEnumerable<FileThreat> findings)
    {
        foreach (var threat in findings)
        {
            ThreatHistoryRecord? record = null;
            try { record = _threatHistoryStore.RecordDetection(threat); }
            catch (Exception exception) { AddNotification("Historique de menace indisponible", exception.Message, "Avertissement"); }
            if (record is not null) UpsertThreatHistory(record);

            var listed = Threats.FirstOrDefault(item => SameFinding(item.Sha256, item.Location, threat.Sha256, threat.Path));
            if (listed is not null) Threats.Remove(listed);
            Threats.Insert(0, new ThreatListItem(threat.Name, threat.Path, threat.Severity.ToString(), threat.DetectedAt, threat.Sha256));
        }
    }

    private void SetThreatStatus(string sha256, string location, string status)
    {
        try
        {
            var record = _threatHistoryStore.SetStatus(sha256, location, status);
            if (record is null) return;
            UpsertThreatHistory(record);
            if (status != "À examiner")
            {
                var listed = Threats.FirstOrDefault(item => SameFinding(item.Sha256, item.Location, sha256, location));
                if (listed is not null) Threats.Remove(listed);
            }
        }
        catch (Exception exception) { AddNotification("Mise à jour de l’historique impossible", exception.Message, "Avertissement"); }
    }

    private void UpsertThreatHistory(ThreatHistoryRecord record)
    {
        var index = -1;
        for (var i = 0; i < ThreatHistory.Count; i++)
            if (SameFinding(ThreatHistory[i].Sha256, ThreatHistory[i].Location, record.Sha256, record.Location)) { index = i; break; }
        if (index >= 0) ThreatHistory.RemoveAt(index);
        ThreatHistory.Insert(0, record);
        if (ThreatHistory.Count > 2_000) ThreatHistory.RemoveAt(ThreatHistory.Count - 1);
    }

    private static bool SameFinding(string leftHash, string leftPath, string rightHash, string rightPath) =>
        StringComparer.OrdinalIgnoreCase.Equals(leftHash, rightHash)
        && StringComparer.OrdinalIgnoreCase.Equals(NormalizePath(leftPath), NormalizePath(rightPath));

    private static string NormalizePath(string path)
    {
        try { return Path.GetFullPath(path); }
        catch { return path; }
    }

    public void ToggleFolderMonitoring(string folder)
    {
        if (_fileBehaviorMonitor is not null)
        {
            _fileBehaviorMonitor.Dispose(); _fileBehaviorMonitor = null; IsFolderMonitoring = false; MonitoredFolder = "Aucun dossier surveillé";
            AddActivity("Antivirus", "Surveillance du dossier arrêtée", folder); OnPropertyChanged(nameof(MonitoredFolder)); return;
        }
        _fileBehaviorMonitor = new FileBehaviorMonitor(folder);
        _fileBehaviorMonitor.FileChanged += (_, e) => System.Windows.Application.Current.Dispatcher.BeginInvoke(() =>
        {
            var record = new FileChangeRecord(e.Path, e.ChangeType, e.OccurredAt);
            FileChanges.Insert(0, new(record.Path, record.ChangeType, record.OccurredAt)); if (FileChanges.Count > 1000) FileChanges.RemoveAt(FileChanges.Count - 1);
            try { _fileChangeHistoryStore.Append(record); } catch { }
            AddActivity("Fichier", record.ChangeType, record.Path);
        });
        _fileBehaviorMonitor.MonitoringError += message => System.Windows.Application.Current.Dispatcher.BeginInvoke(() => AddNotification("Surveillance des fichiers dégradée", message, "Avertissement"));
        _fileBehaviorMonitor.SuspiciousBurstDetected += (_, burst) => System.Windows.Application.Current.Dispatcher.BeginInvoke(() =>
        {
            var assessment = new RansomwareDetector().Assess(burst);
            if (assessment.IsSuspicious) AddNotification($"Activité de fichiers suspecte · {assessment.Severity}", assessment.Explanation, "Avertissement");
        });
        _fileBehaviorMonitor.Start(); IsFolderMonitoring = true; MonitoredFolder = Path.GetFullPath(folder); OnPropertyChanged(nameof(MonitoredFolder));
        AddActivity("Antivirus", "Surveillance de modifications activée", MonitoredFolder);
    }

    public void CreateBackup(string path)
    {
        var item = _backups.CreateSnapshot(path); RefreshBackups();
        AddActivity("Antivirus", "Copie de sécurité créée", path); AddNotification("Sauvegarde créée", $"Une copie locale de {item.Name} a été enregistrée.", "Information");
    }
    public void RestoreBackup(BackupListItem item)
    {
        var restored = _backups.Restore(item.Id); AddActivity("Antivirus", "Copie de sécurité restaurée", restored);
        AddNotification("Restauration terminée", $"Copie restaurée dans {restored}.", "Information");
    }
    private void RefreshBackups()
    {
        Backups.Clear(); foreach (var item in _backups.GetItems()) Backups.Add(new(item.Id, item.Name, item.OriginalPath, item.CreatedAt));
    }

    public void Dispose()
    {
        _downloadMonitor?.Dispose(); _fileBehaviorMonitor?.Dispose();
    }
}

public sealed record ThreatListItem(string Name, string Location, string Severity, DateTime DetectedAt, string Sha256);
public sealed record QuarantineListItem(string Id, string Name, string OriginalPath, string Sha256, DateTime IsolatedAt, string Status);
public sealed record BackupListItem(string Id, string Name, string OriginalPath, DateTime CreatedAt);
public sealed record FileChangeListItem(string Path, string ChangeType, DateTime OccurredAt);
