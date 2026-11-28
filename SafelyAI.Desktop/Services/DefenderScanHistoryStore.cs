using System.IO;
using System.Security;
using System.Text.Json;

namespace SafelyAI.Desktop.Services;

public sealed record DefenderScanHistoryEntry(
    string Type,
    string Scope,
    string Outcome,
    string Message,
    int ExitCode,
    DateTime FinishedAt);

/// <summary>Bounded, user-local history of on-demand Microsoft Defender scans.</summary>
public sealed class DefenderScanHistoryStore(string? path = null)
{
    private const string MutexName = "Local\\SAFELY_AI_DEFENDER_SCAN_HISTORY_STORE";
    private const int MaximumEntries = 500;
    private readonly string _path = path ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SafelyAI", "History", "defender-scans.json");
    private readonly object _gate = new();

    public IReadOnlyList<DefenderScanHistoryEntry> Read()
    {
        try { return WithLock(ReadUnsafe); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SecurityException or JsonException)
        {
            return [];
        }
    }

    public void Append(DefenderScanHistoryEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        WithLock(() =>
        {
            var entries = ReadUnsafe();
            entries.Insert(0, entry);
            if (entries.Count > MaximumEntries) entries.RemoveRange(MaximumEntries, entries.Count - MaximumEntries);
            var directory = Path.GetDirectoryName(_path)
                ?? throw new IOException("Le dossier de l’historique Defender est invalide.");
            Directory.CreateDirectory(directory);
            var temporary = $"{_path}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
            try
            {
                File.WriteAllText(temporary, JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true }));
                File.Move(temporary, _path, true);
            }
            finally
            {
                try { if (File.Exists(temporary)) File.Delete(temporary); } catch { }
            }
            return 0;
        });
    }

    private List<DefenderScanHistoryEntry> ReadUnsafe()
    {
        if (!File.Exists(_path)) return [];
        return JsonSerializer.Deserialize<List<DefenderScanHistoryEntry>>(File.ReadAllText(_path),
            new JsonSerializerOptions { MaxDepth = 8 }) ?? [];
    }

    private T WithLock<T>(Func<T> action)
    {
        lock (_gate)
        {
            using var mutex = new Mutex(false, MutexName);
            var acquired = false;
            try
            {
                try { acquired = mutex.WaitOne(TimeSpan.FromSeconds(10)); }
                catch (AbandonedMutexException) { acquired = true; }
                if (!acquired) throw new IOException("L’historique des scans Defender est utilisé par un autre processus.");
                return action();
            }
            finally
            {
                if (acquired) mutex.ReleaseMutex();
            }
        }
    }
}
