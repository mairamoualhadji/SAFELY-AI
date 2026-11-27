using System.Security.Cryptography;
using System.Text.Json;

namespace SafelyAI.Antivirus.Quarantine;

public sealed record FileBackupItem(string Id, string Name, string OriginalPath, string SnapshotPath, string Sha256, DateTime CreatedAt);

/// <summary>Explicit local file snapshots; this does not silently copy whole folders.</summary>
public sealed class FileBackupManager
{
    private readonly string _root;
    private readonly string _manifest;
    private readonly object _gate = new();
    public FileBackupManager(string? root = null)
    {
        _root = root ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SafelyAI", "FileBackups");
        Directory.CreateDirectory(_root); _manifest = Path.Combine(_root, "manifest.json");
    }
    public IReadOnlyList<FileBackupItem> GetItems() { lock (_gate) return Read().OrderByDescending(x => x.CreatedAt).ToArray(); }
    public FileBackupItem CreateSnapshot(string path)
    {
        var source = Path.GetFullPath(path);
        if (!File.Exists(source)) throw new FileNotFoundException("Le fichier à sauvegarder est introuvable.", source);
        lock (_gate)
        {
            var id = Guid.NewGuid().ToString("N"); var target = Path.Combine(_root, id + ".snapshot");
            File.Copy(source, target, false);
            var item = new FileBackupItem(id, Path.GetFileName(source), source, target, Hash(target), DateTime.Now);
            var items = Read(); items.Add(item); Write(items); return item;
        }
    }
    public string Restore(string id)
    {
        lock (_gate)
        {
            var item = Read().FirstOrDefault(x => x.Id == id) ?? throw new InvalidOperationException("Sauvegarde introuvable.");
            var snapshotPath = ResolveSnapshotPath(item);
            if (!File.Exists(snapshotPath) || !StringComparer.OrdinalIgnoreCase.Equals(Hash(snapshotPath), item.Sha256))
                throw new InvalidDataException("L’empreinte de la sauvegarde ne correspond pas; restauration refusée.");
            var directory = Path.GetDirectoryName(item.OriginalPath)!; Directory.CreateDirectory(directory);
            var destination = item.OriginalPath;
            if (File.Exists(destination))
                destination = Path.Combine(directory, $"{Path.GetFileNameWithoutExtension(destination)}-restaure-{item.CreatedAt:yyyyMMddHHmmss}-{item.Id[..8]}{Path.GetExtension(destination)}");
            File.Copy(snapshotPath, destination, false); return destination;
        }
    }
    private List<FileBackupItem> Read() => File.Exists(_manifest) ? JsonSerializer.Deserialize<List<FileBackupItem>>(File.ReadAllText(_manifest)) ?? [] : [];
    private void Write(List<FileBackupItem> items)
    {
        var temp = _manifest + ".tmp"; File.WriteAllText(temp, JsonSerializer.Serialize(items, new JsonSerializerOptions { WriteIndented = true })); File.Move(temp, _manifest, true);
    }
    private string ResolveSnapshotPath(FileBackupItem item)
    {
        if (item.Id.Length != 32 || !item.Id.All(Uri.IsHexDigit)) throw new InvalidDataException("Identifiant de sauvegarde invalide.");
        var expected = Path.GetFullPath(Path.Combine(_root, item.Id + ".snapshot"));
        if (!StringComparer.OrdinalIgnoreCase.Equals(expected, Path.GetFullPath(item.SnapshotPath))) throw new InvalidDataException("Le chemin de copie ne correspond pas à son identifiant.");
        return expected;
    }
    private static string Hash(string path) { using var s = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(s)); }
}
