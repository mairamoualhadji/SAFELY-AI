using System.IO;
using System.Security;
using System.Text.Json;
using SafelyAI.Antivirus.FileScanner;

namespace SafelyAI.Desktop.Services;

public sealed record ThreatHistoryRecord(
    string Name,
    string Location,
    string Severity,
    DateTime DetectedAt,
    string Sha256,
    string Status,
    DateTime? StatusChangedAt);

/// <summary>Durable local finding history shared by the UI and the per-user background guard.</summary>
public sealed class ThreatHistoryStore(string? path = null)
{
    private const string MutexName = "Local\\SAFELY_AI_THREAT_HISTORY_STORE";
    private readonly string _path = path ?? Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SafelyAI", "History", "threats.json");
    private readonly object _gate = new();

    public IReadOnlyList<ThreatHistoryRecord> Read()
    {
        return TryRead(out var entries) ? entries : [];
    }

    public bool TryRead(out IReadOnlyList<ThreatHistoryRecord> entries)
    {
        try
        {
            entries = WithLock(ReadUnsafe);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SecurityException or JsonException)
        {
            entries = [];
            return false;
        }
    }

    public ThreatHistoryRecord RecordDetection(FileThreat finding)
    {
        ArgumentNullException.ThrowIfNull(finding);
        if (finding.Sha256.Length != 64 || !finding.Sha256.All(Uri.IsHexDigit))
            throw new ArgumentException("L’historique exige une empreinte SHA-256 valide.", nameof(finding));

        return WithLock(() =>
        {
            var entries = ReadUnsafe();
            var index = entries.FindIndex(entry => Same(entry.Sha256, finding.Sha256)
                && StringComparer.OrdinalIgnoreCase.Equals(Normalize(entry.Location), Normalize(finding.Path)));
            var record = new ThreatHistoryRecord(finding.Name, finding.Path, finding.Severity.ToString(),
                finding.DetectedAt, finding.Sha256.ToUpperInvariant(), "À examiner", null);
            if (index >= 0) entries.RemoveAt(index);
            entries.Insert(0, record);
            Trim(entries);
            WriteUnsafe(entries);
            return record;
        });
    }

    public ThreatHistoryRecord? SetStatus(string sha256, string location, string status)
    {
        if (sha256.Length != 64 || !sha256.All(Uri.IsHexDigit)) return null;
        if (status is not ("À examiner" or "En quarantaine" or "Restaurée" or "Supprimée"))
            throw new ArgumentOutOfRangeException(nameof(status));

        return WithLock(() =>
        {
            var entries = ReadUnsafe();
            var index = entries.FindIndex(entry => Same(entry.Sha256, sha256)
                && StringComparer.OrdinalIgnoreCase.Equals(Normalize(entry.Location), Normalize(location)));
            if (index < 0) return null;
            var record = entries[index] with { Status = status, StatusChangedAt = DateTime.Now };
            entries[index] = record;
            WriteUnsafe(entries);
            return record;
        });
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
                if (!acquired) throw new IOException("L’historique des détections est utilisé par un autre processus.");
                return action();
            }
            finally
            {
                if (acquired) mutex.ReleaseMutex();
            }
        }
    }

    private List<ThreatHistoryRecord> ReadUnsafe()
    {
        if (!File.Exists(_path)) return [];
        var entries = JsonSerializer.Deserialize<List<ThreatHistoryRecord>>(File.ReadAllText(_path), new JsonSerializerOptions { MaxDepth = 8 });
        return entries ?? [];
    }

    private void WriteUnsafe(List<ThreatHistoryRecord> entries)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
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
    }

    private static void Trim(List<ThreatHistoryRecord> entries)
    {
        if (entries.Count > 2_000) entries.RemoveRange(2_000, entries.Count - 2_000);
    }

    private static bool Same(string left, string right) => StringComparer.OrdinalIgnoreCase.Equals(left, right);
    private static string Normalize(string path)
    {
        try { return Path.GetFullPath(path); }
        catch { return path; }
    }
}
