using System.IO;
using System.Security;
using System.Text.Json;

namespace SafelyAI.Desktop.Services;

/// <summary>Bounded local history of user-visible actions and scan outcomes.</summary>
public sealed class ActivityHistoryStore(string? path = null)
{
    private const string MutexName = "Local\\SAFELY_AI_ACTIVITY_HISTORY_STORE";
    private const int MaximumEntries = 2_000;
    private readonly string _path = path ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SafelyAI", "History", "activity.json");
    private readonly object _gate = new();

    public IReadOnlyList<ActivityEntry> Read()
    {
        try { return WithLock(ReadUnsafe); }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SecurityException or JsonException)
        {
            return [];
        }
    }

    public void Append(ActivityEntry entry)
    {
        ArgumentNullException.ThrowIfNull(entry);
        if (string.IsNullOrWhiteSpace(entry.Category) || entry.Category.Length > 80
            || string.IsNullOrWhiteSpace(entry.Title) || entry.Title.Length > 200
            || entry.Details is null || entry.Details.Length > 8_000)
            throw new ArgumentException("L’événement d’activité contient des champs invalides.", nameof(entry));

        WithLock(() =>
        {
            var entries = ReadUnsafe();
            entries.Insert(0, entry);
            if (entries.Count > MaximumEntries) entries.RemoveRange(MaximumEntries, entries.Count - MaximumEntries);

            var directory = Path.GetDirectoryName(_path)
                ?? throw new IOException("Le dossier de l’historique d’activité est invalide.");
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

    private List<ActivityEntry> ReadUnsafe()
    {
        if (!File.Exists(_path)) return [];
        var entries = JsonSerializer.Deserialize<List<ActivityEntry>>(File.ReadAllText(_path),
            new JsonSerializerOptions { MaxDepth = 8 });
        return entries ?? [];
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
                if (!acquired) throw new IOException("L’historique d’activité est utilisé par un autre processus.");
                return action();
            }
            finally
            {
                if (acquired) mutex.ReleaseMutex();
            }
        }
    }
}
