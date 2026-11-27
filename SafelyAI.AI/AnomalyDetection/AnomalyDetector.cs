using System.Text.Json;
namespace SafelyAI.AI.AnomalyDetection;

// Apprend les habitudes normales du PC (moyenne et écart-type par mesure) puis signale ce qui s'en écarte.
public class AnomalyDetector
{
    public class Stat
    {
        public long N { get; set; }
        public double Mean { get; set; }
        public double M2 { get; set; }
    }

    private Dictionary<string, Stat> _stats = new();
    public int MinSamples { get; set; } = 30;

    public void Learn(string metric, double value)
    {
        if (!_stats.TryGetValue(metric, out var s)) _stats[metric] = s = new Stat();
        s.N++;
        var delta = value - s.Mean;
        s.Mean += delta / s.N;
        s.M2 += delta * (value - s.Mean);
    }

    public bool IsAnomaly(string metric, double value, double threshold = 3.0)
    {
        if (!_stats.TryGetValue(metric, out var s) || s.N < MinSamples) return false; // pas assez de données
        var sd = Math.Sqrt(s.M2 / (s.N - 1));
        sd = Math.Max(sd, Math.Abs(s.Mean) * 0.05 + 0.01);
        return Math.Abs(value - s.Mean) / sd > threshold;
    }

    public void Save(string path) => File.WriteAllText(path, JsonSerializer.Serialize(_stats));

    public void Load(string path)
    {
        if (!File.Exists(path)) return;
        _stats = JsonSerializer.Deserialize<Dictionary<string, Stat>>(File.ReadAllText(path)) ?? new();
    }
}
