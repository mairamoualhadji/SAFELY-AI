using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace SafelyAI.AI.OllamaClient;

public class OllamaService
{
    private readonly HttpClient _http;

    public string Model { get; set; }

    public OllamaService(string model = "qwen2.5:7b", string baseUrl = "http://localhost:11434")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(baseUrl);
        _http = new HttpClient
        {
            BaseAddress = new Uri(baseUrl, UriKind.Absolute),
            Timeout = TimeSpan.FromMinutes(2)
        };
        Model = model;
    }

    public OllamaService(HttpClient httpClient, string model = "qwen2.5:7b")
    {
        _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        if (_http.BaseAddress is null)
        {
            throw new ArgumentException("L'HttpClient doit avoir une BaseAddress.", nameof(httpClient));
        }

        Model = model;
    }

    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await _http.GetAsync("/", cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return false;
        }
    }

    public async Task<string> GenerateAsync(
        string prompt,
        string? system = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(prompt);
        ArgumentException.ThrowIfNullOrWhiteSpace(Model);

        var request = new GenerateRequest(Model, prompt, system, false);
        var response = await _http.PostAsJsonAsync("/api/generate", request, cancellationToken);
        response.EnsureSuccessStatusCode();
        var data = await response.Content.ReadFromJsonAsync<GenerateResponse>(cancellationToken);
        return data?.Response ?? string.Empty;
    }

    public async Task<string> ChatAsync(
        IReadOnlyList<ChatMessage> messages,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(messages);
        if (messages.Count == 0)
        {
            throw new ArgumentException("La conversation doit contenir au moins un message.", nameof(messages));
        }

        ArgumentException.ThrowIfNullOrWhiteSpace(Model);
        var request = new ChatRequest(Model, messages, false);
        var response = await _http.PostAsJsonAsync("/api/chat", request, cancellationToken);
        response.EnsureSuccessStatusCode();
        var data = await response.Content.ReadFromJsonAsync<ChatResponse>(cancellationToken);
        return data?.Message?.Content ?? string.Empty;
    }

    public async Task<string?> GetVersionAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var data = await _http.GetFromJsonAsync<VersionResponse>("/api/version", cancellationToken);
            return data?.Version;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    public sealed record ChatMessage(
        [property: JsonPropertyName("role")] string Role,
        [property: JsonPropertyName("content")] string Content)
    {
        public static ChatMessage System(string content) => new("system", content);
        public static ChatMessage User(string content) => new("user", content);
        public static ChatMessage Assistant(string content) => new("assistant", content);
    }

    private record GenerateRequest(
        [property: JsonPropertyName("model")] string Model,
        [property: JsonPropertyName("prompt")] string Prompt,
        [property: JsonPropertyName("system"), JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)] string? System,
        [property: JsonPropertyName("stream")] bool Stream);

    private record GenerateResponse([property: JsonPropertyName("response")] string Response);

    private record ChatRequest(
        [property: JsonPropertyName("model")] string Model,
        [property: JsonPropertyName("messages")] IReadOnlyList<ChatMessage> Messages,
        [property: JsonPropertyName("stream")] bool Stream);

    private record ChatResponse([property: JsonPropertyName("message")] ChatMessage? Message);

    private record VersionResponse([property: JsonPropertyName("version")] string Version);
}
