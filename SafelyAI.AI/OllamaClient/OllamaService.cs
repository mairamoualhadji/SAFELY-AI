using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace SafelyAI.AI.OllamaClient;

public class OllamaService : IDisposable
{
    private readonly HttpClient _http;

    public string Model { get; set; }

    public OllamaService(string model = "llama3.2", string baseUrl = "http://localhost:11434")
    {
        if (!Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttp || !uri.IsLoopback)
            throw new ArgumentException("Le modèle local doit être servi par une adresse HTTP de boucle locale.", nameof(baseUrl));
        _http = new HttpClient { BaseAddress = uri, Timeout = TimeSpan.FromSeconds(45) };
        Model = model;
    }

    // Vérifie qu'Ollama tourne sur le PC (fonctionne hors ligne).
    public async Task<bool> IsAvailableAsync()
    {
        try
        {
            var response = await _http.GetAsync("/");
            return response.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // Envoie une question au modèle local et renvoie sa réponse complète.
    public async Task<string> GenerateAsync(string prompt, string? system = null)
    {
        var request = new GenerateRequest(Model, prompt, system, false);
        var response = await _http.PostAsJsonAsync("/api/generate", request);
        response.EnsureSuccessStatusCode();
        var data = await response.Content.ReadFromJsonAsync<GenerateResponse>();
        return data?.Response ?? string.Empty;
    }

    public void Dispose() => _http.Dispose();

    private record GenerateRequest(
        [property: JsonPropertyName("model")] string Model,
        [property: JsonPropertyName("prompt")] string Prompt,
        [property: JsonPropertyName("system"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? System,
        [property: JsonPropertyName("stream")] bool Stream);

    private record GenerateResponse([property: JsonPropertyName("response")] string Response);
}
