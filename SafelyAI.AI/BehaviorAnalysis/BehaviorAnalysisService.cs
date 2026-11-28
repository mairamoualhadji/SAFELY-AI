using SafelyAI.AI.AnomalyDetection;
using SafelyAI.AI.ThreatClassification;

namespace SafelyAI.AI.BehaviorAnalysis;

public sealed class BehaviorAnalysisService
{
    private readonly BehaviorAnalyzer _behaviorAnalyzer;
    private readonly AnomalyDetector _anomalyDetector;
    private readonly ThreatExplanation _threatExplanation;

    public BehaviorAnalysisService(
        BehaviorAnalyzer behaviorAnalyzer,
        AnomalyDetector anomalyDetector,
        ThreatExplanation threatExplanation)
    {
        _behaviorAnalyzer = behaviorAnalyzer ?? throw new ArgumentNullException(nameof(behaviorAnalyzer));
        _anomalyDetector = anomalyDetector ?? throw new ArgumentNullException(nameof(anomalyDetector));
        _threatExplanation = threatExplanation ?? throw new ArgumentNullException(nameof(threatExplanation));
    }

    public bool LearnAfterAnalysis { get; set; } = true;

    public async Task<BehaviorAnalysisResult> AnalyzeAsync(
        ProcessBehavior process,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(process);
        cancellationToken.ThrowIfCancellationRequested();

        var behavior = _behaviorAnalyzer.Analyze(process);
        var anomalyReasons = DetectAnomalies(process);
        var allReasons = behavior.Reasons.Concat(anomalyReasons).ToList();
        var score = Math.Min(100, behavior.Score + anomalyReasons.Count * 10);
        var adjustedBehavior = behavior with { Score = score, Reasons = allReasons };
        var level = ThreatClassifier.FromScore(score);

        if (LearnAfterAnalysis)
        {
            Learn(process);
        }

        cancellationToken.ThrowIfCancellationRequested();
        var explanation = await _threatExplanation.ExplainAsync(
            process.Name,
            level,
            allReasons,
            cancellationToken);

        return new BehaviorAnalysisResult(adjustedBehavior, level, anomalyReasons, explanation);
    }

    private List<string> DetectAnomalies(ProcessBehavior process)
    {
        var anomalies = new List<string>();

        AddAnomaly(MetricKey(process, "cpu"), process.CpuPercent, "utilisation CPU", anomalies);
        AddAnomaly(MetricKey(process, "memory"), process.MemoryMb, "consommation mémoire", anomalies);
        AddAnomaly(MetricKey(process, "network"), process.NetworkConnections, "connexions réseau", anomalies);

        return anomalies;
    }

    private void AddAnomaly(
        string metric,
        double value,
        string label,
        ICollection<string> anomalies)
    {
        if (_anomalyDetector.IsAnomaly(metric, value))
        {
            anomalies.Add($"Valeur anormale pour la {label} ({value:0.##})");
        }
    }

    private void Learn(ProcessBehavior process)
    {
        _anomalyDetector.Learn(MetricKey(process, "cpu"), process.CpuPercent);
        _anomalyDetector.Learn(MetricKey(process, "memory"), process.MemoryMb);
        _anomalyDetector.Learn(MetricKey(process, "network"), process.NetworkConnections);
    }

    private static string MetricKey(ProcessBehavior process, string metric) =>
        $"process:{process.Name.Trim().ToLowerInvariant()}:{metric}";
}
