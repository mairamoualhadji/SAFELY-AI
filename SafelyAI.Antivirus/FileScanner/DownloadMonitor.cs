using System.Collections.Concurrent;

namespace SafelyAI.Antivirus.FileScanner;

public sealed record DownloadReadyEventArgs(string Path, DateTime DetectedAt, bool IsReconciliation);

/// <summary>Opt-in watcher for top-level files in the user's Downloads folder; reconciles up to 20,000 files on start and emits only after sizes settle.</summary>
public sealed class DownloadMonitor : IDisposable
{
    private const int MaxStartupReconciliationFiles = 20_000;
    private readonly FileSystemWatcher _watcher;
    private readonly ConcurrentDictionary<string, (long Length, int StableChecks, bool IsReconciliation)> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly Timer _timer;
    private int _checking;
    public event EventHandler<DownloadReadyEventArgs>? DownloadReady;
    public event Action<string>? MonitoringError;
    public DownloadMonitor(string? directory = null, TimeSpan? pollingInterval = null)
    {
        var downloads = directory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        if (!Directory.Exists(downloads)) Directory.CreateDirectory(downloads);
        _watcher = new FileSystemWatcher(downloads) { IncludeSubdirectories = false, InternalBufferSize = 32 * 1024, NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite, EnableRaisingEvents = false };
        _watcher.Created += QueueFile; _watcher.Changed += QueueFile; _watcher.Renamed += QueueRenamed; _watcher.Error += OnWatcherError;
        var interval = pollingInterval ?? TimeSpan.FromSeconds(1);
        _timer = new Timer(_ => CheckPending(), null, interval, interval);
    }
    public string DirectoryPath => _watcher.Path;
    public void Start()
    {
        _watcher.EnableRaisingEvents = true;
        try
        {
            int queued = 0;
            foreach (var path in Directory.EnumerateFiles(_watcher.Path))
            {
                if (queued == MaxStartupReconciliationFiles)
                {
                    MonitoringError?.Invoke($"Le dossier Téléchargements contient plus de {MaxStartupReconciliationFiles:N0} fichiers; le contrôle initial est partiel.");
                    break;
                }

                Queue(path, isReconciliation: true);
                queued++;
            }

            if (queued > 0)
                MonitoringError?.Invoke($"Contrôle initial de {queued:N0} fichier(s) déjà présent(s) dans Téléchargements après stabilisation de leur taille.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            MonitoringError?.Invoke($"Le contrôle initial de Téléchargements a échoué : {exception.Message}");
        }
    }
    public void Stop() => _watcher.EnableRaisingEvents = false;
    public void SetPollingInterval(TimeSpan interval) => _timer.Change(interval, interval);
    private void QueueRenamed(object sender, RenamedEventArgs e) => Queue(e.FullPath);
    private void QueueFile(object sender, FileSystemEventArgs e) => Queue(e.FullPath);
    private void Queue(string path, bool isReconciliation = false)
    {
        if (Directory.Exists(path)) return;
        _pending.AddOrUpdate(path, (-1, 0, isReconciliation), (_, previous) => (-1, 0, previous.IsReconciliation && isReconciliation));
    }
    private void OnWatcherError(object sender, ErrorEventArgs e)
    {
        try
        {
            // FileSystemWatcher can overflow and lose events; reconcile existing downloads instead
            // of silently claiming continuous coverage.
            int queued = 0;
            foreach (var path in Directory.EnumerateFiles(_watcher.Path))
            {
                if (queued == MaxStartupReconciliationFiles)
                {
                    MonitoringError?.Invoke($"Windows a perdu des événements du dossier Téléchargements. Le dossier contient plus de {MaxStartupReconciliationFiles:N0} fichiers; la resynchronisation est partielle et la surveillance doit être vérifiée.");
                    return;
                }
                Queue(path, isReconciliation: true); queued++;
            }
            MonitoringError?.Invoke("Windows a perdu des événements du dossier Téléchargements. Les fichiers présents sont rebalayés; vérifiez les dernières alertes.");
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            MonitoringError?.Invoke($"La surveillance des téléchargements a perdu des événements et le dossier n’a pas pu être resynchronisé : {ex.Message}");
        }
    }
    private void CheckPending()
    {
        if (Interlocked.Exchange(ref _checking, 1) != 0) return;
        try
        {
            foreach (var pair in _pending.ToArray())
            {
                try
                {
                    if (!File.Exists(pair.Key)) { _pending.TryRemove(pair.Key, out _); continue; }
                    var length = new FileInfo(pair.Key).Length;
                    var stable = length == pair.Value.Length ? pair.Value.StableChecks + 1 : 0;
                    if (stable >= 2)
                    {
                        if (_pending.TryRemove(pair.Key, out var removed))
                            DownloadReady?.Invoke(this, new(pair.Key, DateTime.Now, removed.IsReconciliation));
                    }
                    else _pending[pair.Key] = (length, stable, pair.Value.IsReconciliation);
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { _pending.TryRemove(pair.Key, out _); }
            }
        }
        finally { Volatile.Write(ref _checking, 0); }
    }
    public void Dispose() { _watcher.Dispose(); _timer.Dispose(); _pending.Clear(); }
}
