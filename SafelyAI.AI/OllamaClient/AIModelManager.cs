using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace SafelyAI.AI.OllamaClient;

public class AIModelManager
{
    private readonly HttpClient _http;

    public AIModelManager(string baseUrl = "http://localhost:11434")
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(baseUrl);
        _http = new HttpClient
        {
            BaseAddress = new Uri(baseUrl, UriKind.Absolute),
            Timeout = TimeSpan.FromMinutes(30)
        };
    }

    public AIModelManager(HttpClient httpClient)
    {
        _http = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        if (_http.BaseAddress is null)
        {
            throw new ArgumentException("L'HttpClient doit avoir une BaseAddress.", nameof(httpClient));
        }
    }

    public async Task<List<string>> ListModelsAsync(CancellationToken cancellationToken = default)
    {
        var data = await _http.GetFromJsonAsync<TagsResponse>("/api/tags", cancellationToken);
        return data?.Models?.Select(m => m.Name).ToList() ?? new List<string>();
    }

    public async Task<bool> IsModelInstalledAsync(string model, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(model);
        var models = await ListModelsAsync(cancellationToken);
        return models.Any(name =>
            name.Equals(model, StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith(model + ":", StringComparison.OrdinalIgnoreCase));
    }

    public async Task<bool> PullModelAsync(string model, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(model);
        var response = await _http.PostAsJsonAsync("/api/pull", new PullRequest(model, false), cancellationToken);
        return response.IsSuccessStatusCode;
    }

    public async Task<bool> EnsureModelAsync(string model, CancellationToken cancellationToken = default)
    {
        if (await IsModelInstalledAsync(model, cancellationToken))
        {
            return true;
        }

        return await PullModelAsync(model, cancellationToken);
    }

    private record PullRequest(
        [property: JsonPropertyName("model")] string Model,
        [property: JsonPropertyName("stream")] bool Stream);

    private record TagsResponse([property: JsonPropertyName("models")] List<ModelInfo>? Models);

    private record ModelInfo([property: JsonPropertyName("name")] string Name);
}
