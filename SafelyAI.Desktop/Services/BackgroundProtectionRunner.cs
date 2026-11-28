using System.Text;
using System.IO;
using SafelyAI.Antivirus.FileScanner;
using SafelyAI.Antivirus.Quarantine;
using SafelyAI.Antivirus.SignatureEngine;

namespace SafelyAI.Desktop.Services;

/// <summary>
/// Per-user background guard started by the current user's Run key. This is user-mode monitoring,
/// not a kernel minifilter and cannot guarantee interception before a file is opened or executed.
/// </summary>
public sealed class BackgroundProtectionRunner
{
    public const string StartupArgument = "--background-protection";
    public const string StopEventName = "Local\\SAFELY_AI_BACKGROUND_STOP";
    public const string MutexName = "Local\\SAFELY_AI_BACKGROUND_SINGLE_INSTANCE";

    private readonly string _downloads = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
    private readonly string _logPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SafelyAI", "Logs", "background-protection.log");

    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows()) return;
        Directory.CreateDirectory(_downloads);
        Directory.CreateDirectory(Path.GetDirectoryName(_logPath)!);

        using var singleInstance = new Mutex(false, MutexName);
        if (!singleInstance.WaitOne(0)) return;
        using var stopEvent = new EventWaitHandle(false, EventResetMode.ManualReset, StopEventName);
        stopEvent.Reset();
        using var linkedCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var stopWait = ThreadPool.RegisterWaitForSingleObject(stopEvent, (_, _) => linkedCancellation.Cancel(), null, Timeout.Infinite, true);
        var signatures = new SignatureDatabase();
        var scanner = new FileScannerService(signatures);
        var defender = new MicrosoftDefenderService();
        var quarantine = new QuarantineManager();
        var threatHistory = new ThreatHistoryStore();
        using var feed = new MalwareBazaarSignatureFeed(signatures);
        using var monitor = new DownloadMonitor(_downloads, GetPollingInterval(AppPreferencesStore.Load().ProtectionMode));
        using var scanLock = new SemaphoreSlim(1, 1);

        monitor.MonitoringError += message => WriteLog("WARN", message);
        monitor.DownloadReady += (_, item) => _ = ScanAndRespondAsync(item.Path, item.IsReconciliation);
        try
        {
            monitor.Start();
            WriteLog("INFO", $"Protection en arrière-plan active pour {Environment.UserName}; dossier surveillé : {_downloads}.");
            if (WindowsCredentialStore.TryRead(out var apiKey))
                await TryUpdateFeedAsync(apiKey, feed, linkedCancellation.Token);
            else
                WriteLog("INFO", "Aucune clé MalwareBazaar configurée. Le guard utilise les signatures déjà présentes et EICAR.");

            using var timer = new PeriodicTimer(TimeSpan.FromMinutes(45));
            while (await timer.WaitForNextTickAsync(linkedCancellation.Token))
            {
                if (!WindowsCredentialStore.TryRead(out var refreshKey)) continue;
                await TryUpdateFeedAsync(refreshKey, feed, linkedCancellation.Token);
            }
        }
        catch (OperationCanceledException) when (linkedCancellation.IsCancellationRequested) { }
        finally
        {
            stopWait.Unregister(null);
            monitor.Stop();
            WriteLog("INFO", "Protection en arrière-plan arrêtée.");
        }

        async Task ScanAndRespondAsync(string path, bool isReconciliation)
        {
            try
            {
                await scanLock.WaitAsync(linkedCancellation.Token);
                try
                {
                    if (!File.Exists(path)) return;
                    if (!isReconciliation)
                    {
                        var defenderResult = await defender.RunBackgroundFileScanAsync(path, linkedCancellation.Token);
                        if (defenderResult.Outcome == DefenderScanOutcome.Completed)
                            WriteLog("INFO", $"Commande de scan personnalisé Microsoft Defender terminée pour {path}; vérifiez Sécurité Windows pour le verdict.");
                        else
                            WriteLog("WARN", $"Scan Defender non réalisé pour {path}; le scanner SAFELY AI continue. {defenderResult.Message}");
                    }

                    if (!File.Exists(path))
                    {
                        WriteLog("INFO", $"Le fichier a disparu après la demande de scan Defender : {path}; consultez Sécurité Windows pour voir si une action a été appliquée.");
                        return;
                    }

                    var result = await scanner.ScanAsync([path], cancellationToken: linkedCancellation.Token);
                    if (result.Threats.Count == 0)
                    {
                        WriteLog("INFO", $"Téléchargement analysé : {path}; aucun match SHA-256, {result.SkippedFiles} fichier(s) ignoré(s).");
                        return;
                    }

                    foreach (var finding in result.Threats)
                    {
                        try { threatHistory.RecordDetection(finding); }
                        catch (Exception exception) { WriteLog("WARN", $"Historique de détection indisponible : {finding.Name}; {exception.Message}"); }

                        if (finding.Severity != FileThreatSeverity.High) continue;
                        try
                        {
                            var isolated = quarantine.Quarantine(finding.Path, finding.Sha256);
                            try { threatHistory.SetStatus(finding.Sha256, finding.Path, "En quarantaine"); }
                            catch (Exception exception) { WriteLog("WARN", $"État de quarantaine non enregistré dans l’historique : {finding.Name}; {exception.Message}"); }
                            WriteLog("ALERT", $"Match SHA-256 exact isolé : {finding.Name}; fichier {isolated.Name}; id quarantaine {isolated.Id}; SHA-256 {finding.Sha256}.");
                        }
                        catch (Exception exception)
                        {
                            WriteLog("CRITICAL", $"Match SHA-256 exact détecté mais isolement impossible : {finding.Path}; {exception.Message}");
                        }
                    }
                    foreach (var finding in result.Threats.Where(item => item.Severity != FileThreatSeverity.High))
                        WriteLog("WARN", $"Indicateur heuristique à vérifier : {finding.Name}; {finding.Path}; {finding.Details}");
                }
                finally { scanLock.Release(); }
            }
            catch (OperationCanceledException) { }
            catch (Exception exception) { WriteLog("ERROR", $"Analyse du téléchargement impossible : {path}; {exception.Message}"); }
        }
    }

    private async Task TryUpdateFeedAsync(string apiKey, MalwareBazaarSignatureFeed feed, CancellationToken cancellationToken)
    {
        try
        {
            var result = await feed.UpdateAsync(apiKey, cancellationToken);
            WriteLog("INFO", $"Flux MalwareBazaar mis à jour : {result.SignatureCount} SHA-256; {result.UpdatedAtUtc:O}.");
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (Exception exception) { WriteLog("WARN", $"Mise à jour du flux échouée; la base locale précédente est conservée : {exception.Message}"); }
    }

    private static TimeSpan GetPollingInterval(string? protectionMode) => protectionMode switch
    {
        "Économie de ressources" => TimeSpan.FromSeconds(3),
        "Protection maximale" => TimeSpan.FromMilliseconds(500),
        _ => TimeSpan.FromSeconds(1)
    };

    private void WriteLog(string level, string message)
    {
        try
        {
            var line = $"{DateTimeOffset.Now:O} [{level}] {message}{Environment.NewLine}";
            File.AppendAllText(_logPath, line, Encoding.UTF8);
            var info = new FileInfo(_logPath);
            if (info.Length > 2_000_000)
            {
                var previous = _logPath + ".1";
                File.Move(_logPath, previous, true);
            }
        }
        catch { /* Monitoring must keep running even if diagnostic logging is unavailable. */ }
    }
}
