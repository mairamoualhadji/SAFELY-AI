using System.Text.Json;

namespace SafelyAI.AI.AnomalyDetection;

public class AnomalyDetector
{
    private readonly object _gate = new();
    public class Stat
    {
        public long N { get; set; }
        public double Mean { get; set; }
        public double M2 { get; set; }
    }

    private Dictionary<string, Stat> _stats = new();

    private int _minSamples = 30;

    public int MinSamples
    {
        get => _minSamples;
        set
        {
            if (value < 2)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "Il faut au moins deux échantillons.");
            }

            _minSamples = value;
        }
    }

    public void Learn(string metric, double value)
    {
        ValidateSample(metric, value);

        lock (_gate)
        {
            if (!_stats.TryGetValue(metric, out var stat))
            {
                _stats[metric] = stat = new Stat();
            }

            stat.N++;
            var delta = value - stat.Mean;
            stat.Mean += delta / stat.N;
            stat.M2 += delta * (value - stat.Mean);
        }
    }

    public bool IsAnomaly(string metric, double value, double threshold = 3.0)
    {
        ValidateSample(metric, value);
        if (threshold <= 0 || double.IsNaN(threshold) || double.IsInfinity(threshold))
        {
            throw new ArgumentOutOfRangeException(nameof(threshold));
        }

        lock (_gate)
        {
            if (!_stats.TryGetValue(metric, out var stat) || stat.N < MinSamples)
            {
                return false;
            }

            var standardDeviation = Math.Sqrt(stat.M2 / (stat.N - 1));
            standardDeviation = Math.Max(standardDeviation, Math.Abs(stat.Mean) * 0.05 + 0.01);
            return Math.Abs(value - stat.Mean) / standardDeviation > threshold;
        }
    }

    public IReadOnlyDictionary<string, Stat> Snapshot()
    {
        lock (_gate)
        {
            return _stats.ToDictionary(
                pair => pair.Key,
                pair => new Stat { N = pair.Value.N, Mean = pair.Value.Mean, M2 = pair.Value.M2 });
        }
    }

    public void Save(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temporaryPath = fullPath + ".tmp";
        File.WriteAllText(temporaryPath, JsonSerializer.Serialize(Snapshot()));
        File.Move(temporaryPath, fullPath, true);
    }

    public void Load(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        if (!File.Exists(path))
        {
            return;
        }

        try
        {
            var loaded = JsonSerializer.Deserialize<Dictionary<string, Stat>>(File.ReadAllText(path)) ?? new();
            lock (_gate)
            {
                _stats = loaded;
            }
        }
        catch (JsonException)
        {
            lock (_gate)
            {
                _stats = new();
            }
        }
    }

    public void Reset()
    {
        lock (_gate)
        {
            _stats = new();
        }
    }

    private static void ValidateSample(string metric, double value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(metric);
        if (double.IsNaN(value) || double.IsInfinity(value))
        {
            throw new ArgumentOutOfRangeException(nameof(value), "La valeur doit être un nombre fini.");
        }
    }
}
