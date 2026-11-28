using System.Net;
using System.Text;
using SafelyAI.AI;
using SafelyAI.AI.AnomalyDetection;
using SafelyAI.AI.BehaviorAnalysis;
using SafelyAI.AI.Configuration;
using SafelyAI.AI.Conversation;
using SafelyAI.AI.FileAnalysis;
using SafelyAI.AI.OllamaClient;
using SafelyAI.AI.Reporting;
using SafelyAI.AI.ThreatClassification;

var tests = new List<(string Name, Func<Task> Run)>
{
    ("Configuration valide", TestConfigurationAsync),
    ("Client Ollama et gestionnaire de modèles", TestOllamaClientAsync),
    ("Analyse comportementale", TestBehaviorAnalysisAsync),
    ("Apprentissage et anomalies", TestAnomalyDetectorAsync),
    ("Analyse locale de fichier", TestFileAnalysisAsync),
    ("Assistant hors ligne", TestOfflineAssistantAsync),
    ("Conversion en menace Core", TestThreatFactoryAsync),
    ("Rapport de sécurité", TestReportAsync),
    ("Validation du collecteur", TestCollectorValidationAsync),
    ("Collecte des processus Windows", TestProcessCollectorAsync),
    ("Analyse des anomalies système", TestSystemAnalysisAsync),
    ("Façade AIEngine", TestEngineAsync)
};

if (Environment.GetEnvironmentVariable("SAFELYAI_LIVE_OLLAMA") == "1")
{
    tests.Add(("Ollama réel qwen2.5:7b", TestLiveOllamaAsync));
}

var passed = 0;
foreach (var test in tests)
{
    try
    {
        await test.Run();
        Console.WriteLine($"PASS : {test.Name}");
        passed++;
    }
    catch (Exception exception)
    {
        Console.Error.WriteLine($"FAIL : {test.Name}\n{exception}");
        Environment.ExitCode = 1;
    }
}

Console.WriteLine($"{passed}/{tests.Count} tests réussis.");

static Task TestConfigurationAsync()
{
    var options = new AIOptions { OllamaBaseUrl = "http://localhost:11434", Model = "qwen2.5:7b" };
    options.Validate();
    Assert(options.MaxConversationMessages >= 2, "La taille de l'historique est invalide.");
    return Task.CompletedTask;
}

static async Task TestOllamaClientAsync()
{
    var handler = new FakeOllamaHandler();
    using var http = new HttpClient(handler) { BaseAddress = new Uri("http://localhost:11434") };
    var ollama = new OllamaService(http);

    Assert(await ollama.IsAvailableAsync(), "Ollama simulé devrait être disponible.");
    Assert(await ollama.GetVersionAsync() == "0.1-test", "La version Ollama est incorrecte.");
    Assert(await ollama.GenerateAsync("Bonjour") == "Réponse generate", "Generate est incorrect.");
    Assert(await ollama.ChatAsync(new[] { OllamaService.ChatMessage.User("Bonjour") }) == "Réponse chat", "Chat est incorrect.");

    var manager = new AIModelManager(http);
    Assert(await manager.IsModelInstalledAsync("qwen2.5:7b"), "Le modèle simulé devrait être détecté.");
    Assert(await manager.EnsureModelAsync("qwen2.5:7b"), "EnsureModel devrait réussir.");
    Assert(handler.Requests.Any(request => request.RequestUri?.AbsolutePath == "/api/chat"), "L'appel chat n'a pas été envoyé.");
}

static Task TestBehaviorAnalysisAsync()
{
    var analyzer = new BehaviorAnalyzer();
    var result = analyzer.Analyze(new ProcessBehavior(
        "svchost",
        123,
        @"C:\Users\Test\Downloads\svchost.exe",
        95,
        2500,
        60));

    Assert(result.Score >= 80, "Le comportement fortement suspect n'a pas reçu un score suffisant.");
    Assert(result.Reasons.Count >= 3, "Les indices comportementaux sont incomplets.");
    Assert(ThreatClassifier.FromScore(result.Score) == ThreatLevel.Critical, "La gravité est incorrecte.");
    return Task.CompletedTask;
}

static Task TestAnomalyDetectorAsync()
{
    var detector = new AnomalyDetector { MinSamples = 5 };
    for (var value = 10; value < 15; value++)
    {
        detector.Learn("cpu", value);
    }

    Assert(detector.IsAnomaly("cpu", 100), "La valeur extrême devrait être une anomalie.");
    Assert(!detector.IsAnomaly("memory", 100), "Une métrique sans historique ne devrait pas être une anomalie.");

    var path = Path.Combine(Path.GetTempPath(), "safely-ai-anomaly-" + Guid.NewGuid().ToString("N") + ".json");
    try
    {
        detector.Save(path);
        var loaded = new AnomalyDetector { MinSamples = 5 };
        loaded.Load(path);
        Assert(loaded.IsAnomaly("cpu", 100), "L'apprentissage sauvegardé n'a pas été rechargé.");
    }
    finally
    {
        if (File.Exists(path)) File.Delete(path);
    }

    return Task.CompletedTask;
}

static async Task TestFileAnalysisAsync()
{
    var folder = Path.Combine(Path.GetTempPath(), "SafelyAI-AI-Tests-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(folder);
    var path = Path.Combine(folder, "facture.pdf.exe");
    await File.WriteAllTextAsync(path, "fichier de test inoffensif");

    try
    {
        using var http = CreateUnavailableHttpClient();
        var explanation = new ThreatExplanation(new OllamaService(http));
        var service = new FileAnalysisService(new FileSuspicionAnalyzer(), explanation);
        var result = await service.AnalyzeAsync(path);

        Assert(result.Exists && result.Accessible, "Le fichier de test devrait être accessible.");
        Assert(result.Sha256.Length == 64, "Le SHA-256 n'a pas été calculé.");
        Assert(result.IsSuspicious, "La double extension devrait être signalée.");
        Assert(result.Recommendations.Count > 0, "Les recommandations hors ligne sont absentes.");
    }
    finally
    {
        Directory.Delete(folder, true);
    }
}

static async Task TestOfflineAssistantAsync()
{
    using var http = CreateUnavailableHttpClient();
    var assistant = new SecurityAssistant(new OllamaService(http));
    var reply = await assistant.AskAsync("Que faire face à une menace suspecte ?");
    Assert(!reply.UsedLocalModel, "Le mode hors ligne aurait dû être utilisé.");
    Assert(reply.Answer.Contains("Isole", StringComparison.OrdinalIgnoreCase), "La réponse hors ligne est insuffisante.");
    Assert(assistant.History.Count >= 3, "L'historique de conversation n'est pas conservé.");
}

static Task TestThreatFactoryAsync()
{
    var analysis = new BehaviorAnalysisResult(
        new BehaviorReport(
            new ProcessBehavior("demo", 42, @"C:\Temp\demo.exe", 90, 10, 0),
            85,
            new[] { "Indice de test" }),
        ThreatLevel.Critical,
        new[] { "Anomalie de test" },
        "Explication de test");

    var threat = SecurityThreatFactory.FromBehavior(analysis);
    Assert(threat.Severity == "Critique", "La gravité Core n'est pas convertie.");
    Assert(threat.Source.Contains("PID 42", StringComparison.Ordinal), "La source du processus est absente.");
    return Task.CompletedTask;
}

static async Task TestReportAsync()
{
    var folder = Path.Combine(Path.GetTempPath(), "SafelyAI-AI-Report-" + Guid.NewGuid().ToString("N"));
    Directory.CreateDirectory(folder);
    var reportPath = Path.Combine(folder, "report.json");

    try
    {
        using var http = CreateUnavailableHttpClient();
        var explanation = new ThreatExplanation(new OllamaService(http));
        var behavior = new BehaviorAnalysisResult(
            new BehaviorReport(
                new ProcessBehavior("suspect", 7, null, 90, 3000, 51),
                80,
                new[] { "Processus de test suspect" }),
            ThreatLevel.Critical,
            Array.Empty<string>(),
            "Explication locale");
        var report = await new SecurityReportGenerator(explanation)
            .GenerateAsync(new[] { behavior });

        SecurityReportGenerator.SaveJson(report, reportPath);
        Assert(report.OverallLevel == ThreatLevel.Critical, "Le niveau global du rapport est incorrect.");
        Assert(report.SuspiciousProcessCount == 1, "Le processus suspect n'est pas comptabilisé.");
        Assert(File.Exists(reportPath), "Le rapport JSON n'a pas été écrit.");
    }
    finally
    {
        Directory.Delete(folder, true);
    }
}

static Task TestCollectorValidationAsync()
{
    var collector = new ProcessBehaviorCollector();
    return AssertThrowsAsync<ArgumentOutOfRangeException>(
        () => collector.CollectAsync(TimeSpan.FromMilliseconds(50)),
        "L'intervalle invalide devrait être refusé.");
}

static async Task TestProcessCollectorAsync()
{
    var processes = await new ProcessBehaviorCollector()
        .CollectAsync(TimeSpan.FromMilliseconds(100));
    Assert(processes.Count > 0, "Aucun processus Windows n'a été collecté.");
    Assert(processes.All(process => process.Pid > 0), "Un PID collecté est invalide.");
}

static async Task TestSystemAnalysisAsync()
{
    var detector = new AnomalyDetector { MinSamples = 2 };
    var report = await new SystemAnomalyAnalyzer(detector).AnalyzeAsync(100);
    Assert(report.Snapshot.CpuPercent is >= 0 and <= 100, "Le CPU système est hors limites.");
    Assert(report.Snapshot.RamUsedPercent is >= 0 and <= 100, "La RAM système est hors limites.");
}

static Task TestEngineAsync()
{
    var path = Path.Combine(Path.GetTempPath(), "safely-ai-engine-" + Guid.NewGuid().ToString("N") + ".json");
    try
    {
        var engine = new AIEngine(new AIOptions { AnomalyStorePath = path });
        engine.AnomalyDetector.Learn("test", 1);
        engine.SaveLearningModel();
        Assert(File.Exists(path), "Le modèle d'apprentissage de la façade n'est pas sauvegardé.");
        return Task.CompletedTask;
    }
    finally
    {
        if (File.Exists(path)) File.Delete(path);
    }
}

static async Task TestLiveOllamaAsync()
{
    var ollama = new OllamaService();
    Assert(await ollama.IsAvailableAsync(), "Le serveur Ollama local ne répond pas.");
    Assert(!string.IsNullOrWhiteSpace(await ollama.GetVersionAsync()), "La version Ollama est absente.");
    var response = await ollama.GenerateAsync("Réponds uniquement par le mot OK.");
    Assert(!string.IsNullOrWhiteSpace(response), "Ollama n'a renvoyé aucune réponse.");
}

static HttpClient CreateUnavailableHttpClient() =>
    new(new AlwaysUnavailableHandler()) { BaseAddress = new Uri("http://localhost:11434") };

static void Assert(bool condition, string message)
{
    if (!condition) throw new InvalidOperationException(message);
}

static async Task AssertThrowsAsync<TException>(Func<Task> action, string message)
    where TException : Exception
{
    try
    {
        await action();
    }
    catch (TException)
    {
        return;
    }

    throw new InvalidOperationException(message);
}

sealed class AlwaysUnavailableHandler : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        return Task.FromResult(new HttpResponseMessage(HttpStatusCode.ServiceUnavailable));
    }
}

sealed class FakeOllamaHandler : HttpMessageHandler
{
    public List<HttpRequestMessage> Requests { get; } = new();

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken)
    {
        Requests.Add(request);
        var path = request.RequestUri?.AbsolutePath;
        var json = path switch
        {
            "/" => "Ollama is running",
            "/api/version" => "{\"version\":\"0.1-test\"}",
            "/api/generate" => "{\"response\":\"Réponse generate\"}",
            "/api/chat" => "{\"message\":{\"role\":\"assistant\",\"content\":\"Réponse chat\"}}",
            "/api/tags" => "{\"models\":[{\"name\":\"qwen2.5:7b\"}]}",
            "/api/pull" => "{\"status\":\"success\"}",
            _ => "{}"
        };

        return new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(json, Encoding.UTF8, "application/json")
        };
    }
}
