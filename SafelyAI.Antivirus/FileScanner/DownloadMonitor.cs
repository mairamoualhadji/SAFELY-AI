using System.Collections.Concurrent;

namespace SafelyAI.Antivirus.FileScanner;

public sealed record DownloadReadyEventArgs(string Path, DateTime DetectedAt);

/// <summary>Opt-in watcher for the user's Downloads folder; emits files only after their size settles.</summary>
public sealed class DownloadMonitor : IDisposable
{
    private readonly FileSystemWatcher _watcher;
    private readonly ConcurrentDictionary<string, (long Length, int StableChecks)> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly Timer _timer;
    private int _checking;
    public event EventHandler<DownloadReadyEventArgs>? DownloadReady;
    public DownloadMonitor(string? directory = null, TimeSpan? pollingInterval = null)
    {
        var downloads = directory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads");
        if (!Directory.Exists(downloads)) Directory.CreateDirectory(downloads);
        _watcher = new FileSystemWatcher(downloads) { IncludeSubdirectories = false, NotifyFilter = NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.LastWrite, EnableRaisingEvents = false };
        _watcher.Created += QueueFile; _watcher.Renamed += QueueRenamed;
        var interval = pollingInterval ?? TimeSpan.FromSeconds(1);
        _timer = new Timer(_ => CheckPending(), null, interval, interval);
    }
    public string DirectoryPath => _watcher.Path;
    public void Start() => _watcher.EnableRaisingEvents = true;
    public void Stop() => _watcher.EnableRaisingEvents = false;
    public void SetPollingInterval(TimeSpan interval) => _timer.Change(interval, interval);
    private void QueueRenamed(object sender, RenamedEventArgs e) => Queue(e.FullPath);
    private void QueueFile(object sender, FileSystemEventArgs e) => Queue(e.FullPath);
    private void Queue(string path)
    {
        if (Directory.Exists(path)) return;
        _pending[path] = (-1, 0);
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
                        if (_pending.TryRemove(pair.Key, out _)) DownloadReady?.Invoke(this, new(pair.Key, DateTime.Now));
                    }
                    else _pending[pair.Key] = (length, stable);
                }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { _pending.TryRemove(pair.Key, out _); }
            }
        }
        finally { Volatile.Write(ref _checking, 0); }
    }
    public void Dispose() { _watcher.Dispose(); _timer.Dispose(); _pending.Clear(); }
}
