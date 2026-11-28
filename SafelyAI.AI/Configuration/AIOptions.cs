namespace SafelyAI.AI.Configuration;

public sealed class AIOptions
{
    public string OllamaBaseUrl { get; set; } = "http://localhost:11434";

    public string Model { get; set; } = "qwen2.5:7b";

    public string AnomalyStorePath { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "SafelyAI",
        "AI",
        "anomalies.json");

    public int MaxConversationMessages { get; set; } = 12;

    public void Validate()
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(OllamaBaseUrl);
        ArgumentException.ThrowIfNullOrWhiteSpace(Model);

        if (!Uri.TryCreate(OllamaBaseUrl, UriKind.Absolute, out var uri) ||
            uri.Scheme is not ("http" or "https"))
        {
            throw new ArgumentException("L'URL Ollama doit être une adresse HTTP ou HTTPS.", nameof(OllamaBaseUrl));
        }

        if (MaxConversationMessages < 2 || MaxConversationMessages > 100)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaxConversationMessages),
                "Le nombre de messages doit être compris entre 2 et 100.");
        }
    }
}
