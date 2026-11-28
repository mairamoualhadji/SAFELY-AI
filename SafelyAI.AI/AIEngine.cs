using SafelyAI.AI.AnomalyDetection;
using SafelyAI.AI.BehaviorAnalysis;
using SafelyAI.AI.Configuration;
using SafelyAI.AI.Conversation;
using SafelyAI.AI.FileAnalysis;
using SafelyAI.AI.OllamaClient;
using SafelyAI.AI.Reporting;
using SafelyAI.AI.ThreatClassification;

namespace SafelyAI.AI;

public sealed class AIEngine
{
    public AIEngine(AIOptions? options = null)
    {
        Options = options ?? new AIOptions();
        Options.Validate();

        Ollama = new OllamaService(Options.Model, Options.OllamaBaseUrl);
        Models = new AIModelManager(Options.OllamaBaseUrl);
        AnomalyDetector = new AnomalyDetector();
        AnomalyDetector.Load(Options.AnomalyStorePath);

        var explanation = new ThreatExplanation(Ollama);
        BehaviorAnalyzer = new BehaviorAnalyzer();
        BehaviorAnalysis = new BehaviorAnalysisService(
            BehaviorAnalyzer,
            AnomalyDetector,
            explanation);
        ProcessCollector = new ProcessBehaviorCollector();
        SystemAnalysis = new SystemAnomalyAnalyzer(AnomalyDetector);
        FileAnalysis = new FileAnalysisService(new FileSuspicionAnalyzer(), explanation);
        Assistant = new SecurityAssistant(Ollama, Options.MaxConversationMessages);
        Reports = new SecurityReportGenerator(explanation);
    }

    public AIOptions Options { get; }

    public OllamaService Ollama { get; }

    public AIModelManager Models { get; }

    public AnomalyDetector AnomalyDetector { get; }

    public BehaviorAnalyzer BehaviorAnalyzer { get; }

    public BehaviorAnalysisService BehaviorAnalysis { get; }

    public ProcessBehaviorCollector ProcessCollector { get; }

    public SystemAnomalyAnalyzer SystemAnalysis { get; }

    public FileAnalysisService FileAnalysis { get; }

    public SecurityAssistant Assistant { get; }

    public SecurityReportGenerator Reports { get; }

    public Task<bool> EnsureConfiguredModelAsync(CancellationToken cancellationToken = default) =>
        Models.EnsureModelAsync(Options.Model, cancellationToken);

    public void SaveLearningModel() => AnomalyDetector.Save(Options.AnomalyStorePath);
}
