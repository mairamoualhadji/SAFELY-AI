using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace SafelyAI.Antivirus.SignatureEngine;

/// <summary>Small local demo signature set. Production deployments should load a maintained, signed database.</summary>
public sealed class SignatureDatabase
{
    private sealed record SignatureEntry(string Sha256, string Name, string? Source = null);
    private sealed record SignatureDocument(int SchemaVersion, DateTime? FeedUpdatedAtUtc, List<SignatureEntry> Entries);
    private readonly HashSet<string> _sha256;
    private readonly Dictionary<string, string> _names = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _sources = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _databasePath;
    private DateTime? _feedUpdatedAtUtc;
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
        _sources[eicarHash] = "builtin";
        foreach (var hash in _sha256) { _names.TryAdd(hash, "Signature locale"); _sources.TryAdd(hash, "local"); }
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
            _sources[sha256] = "local";
            Save();
        }
    }

    public int ReplaceMalwareBazaarFeed(IEnumerable<string> sha256Hashes)
    {
        ArgumentNullException.ThrowIfNull(sha256Hashes);
        var validated = sha256Hashes.Where(hash => hash is not null && hash.Length == 64 && hash.All(Uri.IsHexDigit))
            .Distinct(StringComparer.OrdinalIgnoreCase).Take(100_001).ToArray();
        if (validated.Length == 0) throw new InvalidDataException("Le flux ne contient aucune empreinte SHA-256 valide; la base existante a été conservée.");
        if (validated.Length > 100_000) throw new InvalidDataException("Le flux dépasse la limite de 100 000 empreintes.");

        lock (_gate)
        {
            var previousHashes = new HashSet<string>(_sha256, StringComparer.OrdinalIgnoreCase);
            var previousNames = new Dictionary<string, string>(_names, StringComparer.OrdinalIgnoreCase);
            var previousSources = new Dictionary<string, string>(_sources, StringComparer.OrdinalIgnoreCase);
            try
            {
                foreach (var old in _sources.Where(pair => pair.Value == "malwarebazaar").Select(pair => pair.Key).ToArray())
                {
                    _sources.Remove(old);
                    _names.Remove(old);
                    _sha256.Remove(old);
                }
                foreach (var hash in validated)
                {
                    if (_sources.TryGetValue(hash, out var existingSource) && existingSource == "local") continue;
                    _sha256.Add(hash);
                    _names[hash] = "MalwareBazaar · menace référencée (SHA-256)";
                    _sources[hash] = "malwarebazaar";
                }
                Save();
                return validated.Length;
            }
            catch
            {
                _sha256.Clear(); _sha256.UnionWith(previousHashes);
                _names.Clear(); foreach (var pair in previousNames) _names[pair.Key] = pair.Value;
                _sources.Clear(); foreach (var pair in previousSources) _sources[pair.Key] = pair.Value;
                throw;
            }
        }
    }

    public IReadOnlyDictionary<string, string> Entries { get { lock (_gate) return new Dictionary<string, string>(_names, StringComparer.OrdinalIgnoreCase); } }
    public DateTime? MalwareBazaarUpdatedAtUtc { get { lock (_gate) return _feedUpdatedAtUtc; } }

    public int ReplaceMalwareBazaarFeed(IEnumerable<string> sha256Hashes, DateTime updatedAtUtc)
    {
        ArgumentNullException.ThrowIfNull(sha256Hashes);
        if (updatedAtUtc.Kind != DateTimeKind.Utc) throw new ArgumentException("L’horodatage du flux doit être en UTC.", nameof(updatedAtUtc));
        var validated = sha256Hashes.Where(hash => hash is not null && hash.Length == 64 && hash.All(Uri.IsHexDigit))
            .Distinct(StringComparer.OrdinalIgnoreCase).Take(100_001).ToArray();
        if (validated.Length == 0) throw new InvalidDataException("Le flux ne contient aucune empreinte SHA-256 valide; la base existante a été conservée.");
        if (validated.Length > 100_000) throw new InvalidDataException("Le flux dépasse la limite de 100 000 empreintes.");

        lock (_gate)
        {
            var previousHashes = new HashSet<string>(_sha256, StringComparer.OrdinalIgnoreCase);
            var previousNames = new Dictionary<string, string>(_names, StringComparer.OrdinalIgnoreCase);
            var previousSources = new Dictionary<string, string>(_sources, StringComparer.OrdinalIgnoreCase);
            var previousUpdatedAt = _feedUpdatedAtUtc;
            try
            {
                foreach (var old in _sources.Where(pair => pair.Value == "malwarebazaar").Select(pair => pair.Key).ToArray())
                {
                    _sources.Remove(old);
                    _names.Remove(old);
                    _sha256.Remove(old);
                }
                foreach (var hash in validated)
                {
                    if (_sources.TryGetValue(hash, out var existingSource) && existingSource == "local") continue;
                    _sha256.Add(hash);
                    _names[hash] = "MalwareBazaar · menace référencée (SHA-256)";
                    _sources[hash] = "malwarebazaar";
                }
                _feedUpdatedAtUtc = updatedAtUtc;
                Save();
                return validated.Length;
            }
            catch
            {
                _sha256.Clear(); _sha256.UnionWith(previousHashes);
                _names.Clear(); foreach (var pair in previousNames) _names[pair.Key] = pair.Value;
                _sources.Clear(); foreach (var pair in previousSources) _sources[pair.Key] = pair.Value;
                _feedUpdatedAtUtc = previousUpdatedAt;
                throw;
            }
        }
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_databasePath)) return;
            using var document = JsonDocument.Parse(File.ReadAllText(_databasePath), new JsonDocumentOptions { MaxDepth = 8 });
            List<SignatureEntry> entries;
            if (document.RootElement.ValueKind == JsonValueKind.Array)
            {
                // Migrate the original list-only schema without losing user signatures.
                entries = JsonSerializer.Deserialize<List<SignatureEntry>>(document.RootElement.GetRawText()) ?? [];
            }
            else if (document.RootElement.ValueKind == JsonValueKind.Object)
            {
                var saved = JsonSerializer.Deserialize<SignatureDocument>(document.RootElement.GetRawText());
                if (saved is null || saved.SchemaVersion != 1 || saved.Entries is null) return;
                entries = saved.Entries;
                _feedUpdatedAtUtc = saved.FeedUpdatedAtUtc is { Kind: DateTimeKind.Utc } updated ? updated : null;
            }
            else return;

            foreach (var item in entries)
                if (item.Sha256 is { Length: 64 } && item.Sha256.All(Uri.IsHexDigit) && !string.IsNullOrWhiteSpace(item.Name))
                { _sha256.Add(item.Sha256); _names[item.Sha256] = item.Name; _sources[item.Sha256] = item.Source is "builtin" or "malwarebazaar" ? item.Source : "local"; }
        }
        catch (JsonException) { /* Ignore malformed local state; the built-in EICAR test signature remains available. */ }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    private void Save()
    {
        Directory.CreateDirectory(Path.GetDirectoryName(_databasePath)!);
        var temporary = _databasePath + ".tmp";
        var saved = new SignatureDocument(1, _feedUpdatedAtUtc,
            _names.Select(x => new SignatureEntry(x.Key, x.Value, _sources.GetValueOrDefault(x.Key, "local"))).ToList());
        File.WriteAllText(temporary, JsonSerializer.Serialize(saved, new JsonSerializerOptions { WriteIndented = true }));
        File.Move(temporary, _databasePath, true);
    }
}
