using SafelyAI.AI.OllamaClient;
namespace SafelyAI.AI.ThreatClassification;

// Explique une menace en langage simple. Utilise le modèle local, sinon un texte de secours.
public class ThreatExplanation
{
    private readonly OllamaService _ollama;
    public ThreatExplanation(OllamaService ollama) => _ollama = ollama;

    public async Task<string> ExplainAsync(string threatName, ThreatLevel level, IEnumerable<string> reasons)
    {
        var list = reasons.ToList();
        if (!await _ollama.IsAvailableAsync()) return Fallback(threatName, level, list);

        var prompt = $"Menace : {threatName}\nGravité : {level}\nIndices :\n- {string.Join("\n- ", list)}\n\n" +
                     "Explique en français simple (3 phrases maximum) pourquoi c'est dangereux, puis donne 3 recommandations courtes.";
        try
        {
            return await _ollama.GenerateAsync(prompt,
                "Tu es l'assistant de sécurité de l'antivirus SAFELY AI. Tu réponds en français, clairement, pour un non-spécialiste.");
        }
        catch { return Fallback(threatName, level, list); }
    }

    private static string Fallback(string name, ThreatLevel level, List<string> reasons) =>
        $"{name} (gravité : {level}). Raisons : {string.Join(" ; ", reasons)}. Le modèle IA local n'est pas disponible pour une explication détaillée.";
}
