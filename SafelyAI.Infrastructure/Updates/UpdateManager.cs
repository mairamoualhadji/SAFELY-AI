
using System.Net.Http;
using System.Text.Json;

namespace SafelyAI.Infrastructure.Updates;

public class UpdateManager
{
    private readonly HttpClient _httpClient;
    private readonly bool _ownsHttpClient;

    public UpdateManager(HttpClient? httpClient = null)
    {
        _ownsHttpClient = httpClient == null;
        _httpClient = httpClient ?? new HttpClient();
        _httpClient.Timeout = TimeSpan.FromSeconds(15);
    }

    public sealed record UpdateManifest(string Version, string? RulesUrl, string? RulesSha256, string? RulesSignature = null, string? PublicKeyPem = null);

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

    public async Task<UpdateManifest?> GetManifestAsync(string manifestUrl, CancellationToken cancellationToken = default)
    {
        if (!Uri.TryCreate(manifestUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException("Une URL HTTPS de manifeste est obligatoire.", nameof(manifestUrl));

        using var response = await _httpClient.GetAsync(uri, cancellationToken);
        response.EnsureSuccessStatusCode();
        await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
        return await JsonSerializer.DeserializeAsync<UpdateManifest>(stream, cancellationToken: cancellationToken);
    }

    public async Task<string> DownloadVerifiedRulesAsync(
        string rulesUrl,
        string expectedSha256,
        string destinationPath,
        CancellationToken cancellationToken = default,
        string? signatureBase64 = null,
        string? publicKeyPem = null)
    {
        if (!Uri.TryCreate(rulesUrl, UriKind.Absolute, out var uri) || uri.Scheme != Uri.UriSchemeHttps)
            throw new ArgumentException("Une URL HTTPS de règles est obligatoire.", nameof(rulesUrl));
        if (string.IsNullOrWhiteSpace(expectedSha256) || expectedSha256.Length != 64)
            throw new ArgumentException("Empreinte SHA-256 attendue invalide.", nameof(expectedSha256));

        byte[] content = await _httpClient.GetByteArrayAsync(uri, cancellationToken);
        string actual = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(content));
        if (!actual.Equals(expectedSha256, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Les règles téléchargées ne correspondent pas à leur empreinte SHA-256.");
        if (!string.IsNullOrWhiteSpace(signatureBase64) || !string.IsNullOrWhiteSpace(publicKeyPem))
        {
            if (string.IsNullOrWhiteSpace(signatureBase64) || string.IsNullOrWhiteSpace(publicKeyPem))
                throw new InvalidDataException("La signature et la clé publique sont nécessaires ensemble.");
            using var rsa = System.Security.Cryptography.RSA.Create();
            rsa.ImportFromPem(publicKeyPem);
            byte[] signature = Convert.FromBase64String(signatureBase64);
            if (!rsa.VerifyData(content, signature, System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1))
                throw new InvalidDataException("La signature des règles est invalide.");
        }

        string fullPath = Path.GetFullPath(destinationPath);
        string? directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
        string temporaryPath = fullPath + ".download";
        await File.WriteAllBytesAsync(temporaryPath, content, cancellationToken);
        File.Move(temporaryPath, fullPath, true);
        return fullPath;
    }

    public void Dispose()
    {
        if (_ownsHttpClient) _httpClient.Dispose();
    }
}
