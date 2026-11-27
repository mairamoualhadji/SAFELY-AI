namespace SafelyAI.Antivirus.RansomwareProtection;

public sealed record FileActivityBurst(string Directory, int ChangedFiles, TimeSpan Window, DateTime DetectedAt, int DeletedFiles, int RenamedFiles);
public sealed record FileChangeEvent(string Path, string ChangeType, DateTime OccurredAt);

/// <summary>Opt-in watcher for a user-selected folder. It raises an alert only and never blocks or deletes files.</summary>
public sealed class FileBehaviorMonitor : IDisposable
{
    private readonly FileSystemWatcher _watcher;
    private readonly Queue<DateTime> _changes = new();
    private readonly Queue<(DateTime At, string Kind)> _changeKinds = new();
    private readonly object _gate = new();
    private readonly int _threshold;
    private readonly TimeSpan _window;
    public event EventHandler<FileActivityBurst>? SuspiciousBurstDetected;
    public event EventHandler<FileChangeEvent>? FileChanged;
    public FileBehaviorMonitor(string selectedDirectory, int threshold = 40, TimeSpan? window = null)
    {
        if (!Directory.Exists(selectedDirectory)) throw new DirectoryNotFoundException(selectedDirectory);
        _threshold = threshold; _window = window ?? TimeSpan.FromSeconds(10);
        _watcher = new FileSystemWatcher(Path.GetFullPath(selectedDirectory)) { IncludeSubdirectories = true, NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size, EnableRaisingEvents = false };
        _watcher.Changed += OnChange; _watcher.Created += OnChange; _watcher.Renamed += OnRename; _watcher.Deleted += OnChange;
    }
    public void Start() => _watcher.EnableRaisingEvents = true;
    private void OnRename(object sender, RenamedEventArgs e) { Record(e.FullPath, "Renamed"); }
    private void OnChange(object sender, FileSystemEventArgs e) { Record(e.FullPath, e.ChangeType.ToString()); }
    private void Record(string path, string kind)
    {
        var now = DateTime.Now;
        FileChanged?.Invoke(this, new(path, kind, now));
        lock (_gate)
        {
            _changes.Enqueue(now); _changeKinds.Enqueue((now, kind));
            while (_changes.Count > 0 && now - _changes.Peek() > _window) _changes.Dequeue();
            while (_changeKinds.Count > 0 && now - _changeKinds.Peek().At > _window) _changeKinds.Dequeue();
            if (_changes.Count >= _threshold && _changes.Count % _threshold == 0)
            {
                var deleted = _changeKinds.Count(x => x.Kind == "Deleted");
                var renamed = _changeKinds.Count(x => x.Kind == "Renamed");
                SuspiciousBurstDetected?.Invoke(this, new(_watcher.Path, _changes.Count, _window, now, deleted, renamed));
            }
        }
    }
    public void Dispose() => _watcher.Dispose();
}
