
using System.Net.Http;
using System.Text.Json;

namespace SafelyAI.Infrastructure.Updates;

public class UpdateManager
{
    private readonly HttpClient _httpClient;

    public UpdateManager()
    {
        _httpClient = new HttpClient();
        _httpClient.Timeout = TimeSpan.FromSeconds(15);
    }

    public async Task<string?> CheckForUpdatesAsync(string versionUrl)
    {
        if (!Uri.TryCreate(versionUrl, UriKind.Absolute, out Uri? uri))
            throw new ArgumentException("URL de mise à jour invalide.");

        if (uri.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException("Une URL HTTPS est obligatoire.");

        using HttpResponseMessage response =
            await _httpClient.GetAsync(uri);

        response.EnsureSuccessStatusCode();

        string json = await response.Content.ReadAsStringAsync();

        using JsonDocument document = JsonDocument.Parse(json);

        if (!document.RootElement.TryGetProperty(
            "version", out JsonElement versionElement))
        {
            return null;
        }

        return versionElement.GetString();
    }

    public bool IsUpdateAvailable(string currentVersion, string? latestVersion)
    {
        if (string.IsNullOrWhiteSpace(currentVersion) ||
            string.IsNullOrWhiteSpace(latestVersion))
        {
            return false;
        }

        if (!Version.TryParse(currentVersion, out Version? current) ||
            !Version.TryParse(latestVersion, out Version? latest))
        {
            return false;
        }

        return latest > current;
    }

    public void Dispose()
    {
        _httpClient.Dispose();
    }
}
