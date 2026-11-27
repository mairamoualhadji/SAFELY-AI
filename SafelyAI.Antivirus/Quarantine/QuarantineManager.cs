using System.Security.Cryptography;
using System.Text.Json;

namespace SafelyAI.Antivirus.Quarantine;

/// <summary>Reversible local isolation with a manifest and hash checks on restore.</summary>
public sealed class QuarantineManager
{
    private readonly string _root;
    private readonly string _manifest;
    private readonly object _gate = new();
    public QuarantineManager(string? root = null)
    {
        _root = root ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SafelyAI", "Quarantine");
        Directory.CreateDirectory(_root);
        _manifest = Path.Combine(_root, "manifest.json");
    }
    public IReadOnlyList<QuarantineItem> GetItems()
    {
        lock (_gate) return ReadManifest();
    }
    public QuarantineItem Quarantine(string sourcePath)
    {
        var source = Path.GetFullPath(sourcePath);
        if (!File.Exists(source)) throw new FileNotFoundException("Le fichier à isoler est introuvable.", source);
        lock (_gate)
        {
            var id = Guid.NewGuid().ToString("N"); var target = Path.Combine(_root, id + ".quarantined");
            var hash = Hash(source);
            File.Move(source, target);
            var item = new QuarantineItem(id, Path.GetFileName(source), source, target, hash, DateTime.Now);
            try { var items = ReadManifest().ToList(); items.Insert(0, item); WriteManifest(items); return item; }
            catch
            {
                if (File.Exists(target) && !File.Exists(source)) File.Move(target, source);
                throw;
            }
        }
    }
    public string Restore(string id)
    {
        lock (_gate)
        {
            var items = ReadManifest().ToList(); var item = items.FirstOrDefault(x => x.Id == id) ?? throw new InvalidOperationException("Élément de quarantaine introuvable.");
            var storedPath = ResolveStoredPath(item);
            if (!File.Exists(storedPath) || !StringComparer.OrdinalIgnoreCase.Equals(Hash(storedPath), item.Sha256)) throw new InvalidDataException("L’empreinte du fichier isolé ne correspond plus; restauration refusée.");
            var directory = Path.GetDirectoryName(item.OriginalPath)!; Directory.CreateDirectory(directory);
            var destination = item.OriginalPath;
            if (File.Exists(destination)) destination = Path.Combine(directory, $"{Path.GetFileNameWithoutExtension(destination)}-restaure-{DateTime.Now:yyyyMMddHHmmss}{Path.GetExtension(destination)}");
            File.Move(storedPath, destination); items.Remove(item); WriteManifest(items); return destination;
        }
    }
    public void DeletePermanently(string id)
    {
        lock (_gate)
        {
            var items = ReadManifest().ToList(); var item = items.FirstOrDefault(x => x.Id == id) ?? throw new InvalidOperationException("Élément de quarantaine introuvable.");
            var storedPath = ResolveStoredPath(item);
            if (File.Exists(storedPath)) File.Delete(storedPath);
            items.Remove(item); WriteManifest(items);
        }
    }
    private List<QuarantineItem> ReadManifest() => File.Exists(_manifest) ? JsonSerializer.Deserialize<List<QuarantineItem>>(File.ReadAllText(_manifest)) ?? [] : [];
    private void WriteManifest(List<QuarantineItem> items)
    {
        var temp = _manifest + ".tmp"; File.WriteAllText(temp, JsonSerializer.Serialize(items, new JsonSerializerOptions { WriteIndented = true })); File.Move(temp, _manifest, true);
    }
    private string ResolveStoredPath(QuarantineItem item)
    {
        if (item.Id.Length != 32 || !item.Id.All(Uri.IsHexDigit)) throw new InvalidDataException("Identifiant de quarantaine invalide.");
        var expected = Path.GetFullPath(Path.Combine(_root, item.Id + ".quarantined"));
        if (!StringComparer.OrdinalIgnoreCase.Equals(expected, Path.GetFullPath(item.StoredPath))) throw new InvalidDataException("Le chemin de quarantaine ne correspond pas à son identifiant.");
        return expected;
    }
    private static string Hash(string path) { using var stream = File.OpenRead(path); return Convert.ToHexString(SHA256.HashData(stream)); }
}
