using System.Net.Http.Json;
using System.Text.Json.Serialization;

namespace SafelyAI.AI.OllamaClient;

public class AIModelManager
{
    private readonly HttpClient _http;

    public AIModelManager(string baseUrl = "http://localhost:11434")
    {
        _http = new HttpClient { BaseAddress = new Uri(baseUrl), Timeout = TimeSpan.FromMinutes(30) };
    }

    public async Task<List<string>> ListModelsAsync()
    {
        var data = await _http.GetFromJsonAsync<TagsResponse>("/api/tags");
        return data?.Models?.Select(m => m.Name).ToList() ?? new List<string>();
    }

    public async Task<bool> IsModelInstalledAsync(string model)
    {
        var models = await ListModelsAsync();
        return models.Any(name =>
            name.Equals(model, StringComparison.OrdinalIgnoreCase) ||
            name.StartsWith(model + ":", StringComparison.OrdinalIgnoreCase));
    }

    public async Task<bool> PullModelAsync(string model)
    {
        var response = await _http.PostAsJsonAsync("/api/pull", new PullRequest(model, false));
        return response.IsSuccessStatusCode;
    }

    public async Task<bool> EnsureModelAsync(string model)
    {
        if (await IsModelInstalledAsync(model)) return true;
        return await PullModelAsync(model);
    }

    private record PullRequest(
        [property: JsonPropertyName("model")] string Model,
        [property: JsonPropertyName("stream")] bool Stream);

    private record TagsResponse([property: JsonPropertyName("models")] List<ModelInfo>? Models);

    private record ModelInfo([property: JsonPropertyName("name")] string Name);
}
