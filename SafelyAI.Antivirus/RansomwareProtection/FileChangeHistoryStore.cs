using System.Text.Json;

namespace SafelyAI.Antivirus.RansomwareProtection;

public sealed record FileChangeRecord(string Path, string ChangeType, DateTime OccurredAt);

public sealed class FileChangeHistoryStore(string? path = null)
{
    private readonly string _path = path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SafelyAI", "History", "file-changes.jsonl");
    private readonly object _gate = new();
    public IReadOnlyList<FileChangeRecord> Read()
    {
        lock (_gate)
        {
            try
            {
                if (!File.Exists(_path)) return [];
                return File.ReadLines(_path).TakeLast(1000).Reverse().Select(line => JsonSerializer.Deserialize<FileChangeRecord>(line)).Where(item => item is not null).Cast<FileChangeRecord>().ToArray();
            }
            catch (IOException) { return []; }
            catch (JsonException) { return []; }
        }
    }
    public void Append(FileChangeRecord record)
    {
        lock (_gate)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.AppendAllText(_path, JsonSerializer.Serialize(record) + Environment.NewLine);
        }
    }
}
