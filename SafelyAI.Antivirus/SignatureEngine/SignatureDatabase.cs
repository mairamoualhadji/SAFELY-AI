using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SafelyAI.Antivirus.SignatureEngine;

/// <summary>Small local demo signature set. Production deployments should load a maintained, signed database.</summary>
public sealed class SignatureDatabase
{
    private sealed record SignatureEntry(string Sha256, string Name);
    private readonly HashSet<string> _sha256;
    private readonly Dictionary<string, string> _names = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _databasePath;
    private readonly object _gate = new();
    public SignatureDatabase(IEnumerable<string>? sha256 = null)
    {
        _databasePath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SafelyAI", "Signatures", "signatures.json");
        _sha256 = new HashSet<string>(sha256 ?? [], StringComparer.OrdinalIgnoreCase);
        // Harmless antivirus test pattern, not a production malware feed.
        const string eicarTestPattern = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
        var eicarHash = Convert.ToHexString(SHA256.HashData(Encoding.ASCII.GetBytes(eicarTestPattern)));
        _sha256.Add(eicarHash);
        _names[eicarHash] = "Signature de test EICAR";
        foreach (var hash in _sha256) _names.TryAdd(hash, "Signature locale");
        Load();
    }
    public bool TryMatch(string sha256, out string name)
    {
        lock (_gate) return _names.TryGetValue(sha256, out name!);
    }
    public void AddSha256(string sha256, string name = "Signature locale")
    {
        if (sha256.Length != 64 || !sha256.All(Uri.IsHexDigit)) throw new ArgumentException("Une empreinte SHA-256 valide est requise.", nameof(sha256));
        if (string.IsNullOrWhiteSpace(name) || name.Length > 120) throw new ArgumentException("Un nom de signature entre 1 et 120 caractères est requis.", nameof(name));
        lock (_gate)
        {
            _sha256.Add(sha256);
            _names[sha256] = name.Trim();
            Save();
        }
    }

    public IReadOnlyDictionary<string, string> Entries { get { lock (_gate) return new Dictionary<string, string>(_names, StringComparer.OrdinalIgnoreCase); } }

    private void Load()
    {
        try
        {
            if (!File.Exists(_databasePath)) return;
            var entries = JsonSerializer.Deserialize<List<SignatureEntry>>(File.ReadAllText(_databasePath)) ?? [];
            foreach (var item in entries)
                if (item.Sha256.Length == 64 && item.Sha256.All(Uri.IsHexDigit) && !string.IsNullOrWhiteSpace(item.Name))
                { _sha256.Add(item.Sha256); _names[item.Sha256] = item.Name; }
        }
        catch (JsonException) { /* Ignore a malformed local database; the EICAR test signature remains available. */ }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_databasePath)!);
        var temporary = _databasePath + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(_names.Select(x => new SignatureEntry(x.Key, x.Value)), new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temporary, _databasePath, true);
    }
}
