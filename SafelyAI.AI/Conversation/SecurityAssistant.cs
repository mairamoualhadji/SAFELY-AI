using SafelyAI.AI.OllamaClient;

namespace SafelyAI.AI.Conversation;

public sealed class SecurityAssistant
{
    private const string SystemPrompt =
        "Tu es l'assistant de sécurité local de SAFELY AI. " +
        "Réponds en français simple, ne prétends jamais avoir effectué une action qui n'a pas été faite, " +
        "et recommande une confirmation humaine avant toute suppression ou modification système.";

    private readonly OllamaService _ollama;
    private readonly int _maxMessages;
    private readonly List<OllamaService.ChatMessage> _history = new();

    public SecurityAssistant(OllamaService ollama, int maxMessages = 12)
    {
        _ollama = ollama ?? throw new ArgumentNullException(nameof(ollama));
        if (maxMessages < 2 || maxMessages > 100)
        {
            throw new ArgumentOutOfRangeException(nameof(maxMessages));
        }

        _maxMessages = maxMessages;
        _history.Add(OllamaService.ChatMessage.System(SystemPrompt));
    }

    public IReadOnlyList<OllamaService.ChatMessage> History => _history.AsReadOnly();

    public async Task<AssistantReply> AskAsync(
        string question,
        string? securityContext = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(question);
        cancellationToken.ThrowIfCancellationRequested();

        var userContent = string.IsNullOrWhiteSpace(securityContext)
            ? question.Trim()
            : $"Contexte de sécurité local :\n{securityContext.Trim()}\n\nQuestion :\n{question.Trim()}";

        _history.Add(OllamaService.ChatMessage.User(userContent));
        TrimHistory();

        if (await _ollama.IsAvailableAsync(cancellationToken))
        {
            try
            {
                var answer = await _ollama.ChatAsync(_history, cancellationToken);
                if (!string.IsNullOrWhiteSpace(answer))
                {
                    _history.Add(OllamaService.ChatMessage.Assistant(answer));
                    TrimHistory();
                    return new AssistantReply(answer.Trim(), true, DateTime.UtcNow);
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                // Le mode hors ligne prend le relais si Ollama est indisponible.
            }
        }

        var offlineAnswer = OfflineAnswer(question);
        _history.Add(OllamaService.ChatMessage.Assistant(offlineAnswer));
        TrimHistory();
        return new AssistantReply(offlineAnswer, false, DateTime.UtcNow);
    }

    public void Reset()
    {
        _history.Clear();
        _history.Add(OllamaService.ChatMessage.System(SystemPrompt));
    }

    private void TrimHistory()
    {
        while (_history.Count > _maxMessages)
        {
            _history.RemoveAt(1);
        }
    }

    private static string OfflineAnswer(string question)
    {
        var lower = question.ToLowerInvariant();
        if (lower.Contains("ollama") || lower.Contains("ia"))
        {
            return "Le modèle IA local n'est pas disponible. Les règles locales de SAFELY AI restent actives, " +
                   "mais les explications conversationnelles détaillées nécessitent Ollama.";
        }

        if (lower.Contains("scan") || lower.Contains("analy"))
        {
            return "Lance d'abord un scan adapté, puis examine les éléments signalés avant toute suppression. " +
                   "Un résultat heuristique est un indice et doit être confirmé par le contexte du fichier ou du processus.";
        }

        if (lower.Contains("menace") || lower.Contains("virus") || lower.Contains("suspect"))
        {
            return "Isole l'élément suspect, évite de l'ouvrir et conserve les journaux. " +
                   "Si la gravité est élevée, déconnecte temporairement la machine du réseau et lance un scan complet.";
        }

        return "Je peux expliquer une menace, interpréter un score de risque ou proposer les étapes d'un scan. " +
               "Le modèle local n'est pas disponible pour cette question, mais les protections heuristiques continuent de fonctionner.";
    }
}
