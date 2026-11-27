using System.Text.Json;

namespace SafelyAI.Antivirus.FileScanner;

public sealed record ScanHistoryRecord(string Type, string Scope, int FilesScanned, int ThreatsFound, int SkippedFiles, long BytesScanned, DateTime FinishedAt);

public sealed class ScanHistoryStore(string? path = null)
{
    private readonly string _path = path ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SafelyAI", "History", "scans.json");
    private readonly object _gate = new();
    public IReadOnlyList<ScanHistoryRecord> Read()
    {
        lock (_gate)
        {
            try { return File.Exists(_path) ? JsonSerializer.Deserialize<List<ScanHistoryRecord>>(File.ReadAllText(_path)) ?? [] : []; }
            catch (IOException) { return []; }
            catch (JsonException) { return []; }
        }
    }
    public void Append(ScanHistoryRecord record)
    {
        lock (_gate)
        {
            var items = Read().ToList(); items.Insert(0, record); if (items.Count > 500) items.RemoveRange(500, items.Count - 500);
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            var temp = _path + ".tmp"; File.WriteAllText(temp, JsonSerializer.Serialize(items, new JsonSerializerOptions { WriteIndented = true })); File.Move(temp, _path, true);
        }
    }
}
