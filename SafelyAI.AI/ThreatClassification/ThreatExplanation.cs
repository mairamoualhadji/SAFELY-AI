using SafelyAI.AI.OllamaClient;

namespace SafelyAI.AI.ThreatClassification;

public class ThreatExplanation
{
    private readonly OllamaService _ollama;

    public ThreatExplanation(OllamaService ollama)
    {
        _ollama = ollama;
    }

    public async Task<string> ExplainAsync(
        string threatName,
        ThreatLevel level,
        IEnumerable<string> reasons,
        CancellationToken cancellationToken = default)
    {
        var advice = await AdviseAsync(threatName, level, reasons, cancellationToken);
        return advice.Summary;
    }

    public async Task<ThreatAdvice> AdviseAsync(
        string threatName,
        ThreatLevel level,
        IEnumerable<string> reasons,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(threatName);
        ArgumentNullException.ThrowIfNull(reasons);

        var list = reasons.ToList();

        cancellationToken.ThrowIfCancellationRequested();
        if (!await _ollama.IsAvailableAsync(cancellationToken))
        {
            return OfflineAdvice(threatName, level, list);
        }

        var prompt = $"Menace : {threatName}\nGravité : {level}\nIndices :\n- {string.Join("\n- ", list)}\n\n" +
                     "Explique en français simple (3 phrases maximum) pourquoi c'est dangereux, puis donne 3 recommandations courtes.";

        try
        {
            var explanation = await _ollama.GenerateAsync(
                prompt,
                "Tu es l'assistant de sécurité de l'antivirus SAFELY AI. Tu réponds en français, clairement, pour un non-spécialiste.",
                cancellationToken);
            return string.IsNullOrWhiteSpace(explanation)
                ? OfflineAdvice(threatName, level, list)
                : SecurityRecommendationEngine.Build(threatName, level, list, explanation, true);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return OfflineAdvice(threatName, level, list);
        }
    }

    private static ThreatAdvice OfflineAdvice(string name, ThreatLevel level, List<string> reasons)
    {
        var summary = $"{name} (gravité : {level}). Raisons : {string.Join(" ; ", reasons)}. " +
                      "Le modèle IA local n'est pas disponible pour une explication détaillée.";
        return SecurityRecommendationEngine.Build(name, level, reasons, summary, false);
    }
}
