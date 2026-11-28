
using System.Text.Json;

namespace SafelyAI.Infrastructure.Configuration;

public class ConfigurationManager
{
    private readonly string _configFilePath;

    public ConfigurationManager(string configFilePath)
    {
        if (string.IsNullOrWhiteSpace(configFilePath))
            throw new ArgumentException("Chemin de configuration invalide.");

        _configFilePath = configFilePath;

        string? directory = Path.GetDirectoryName(_configFilePath);

        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }

    public void Save<T>(T configuration)
    {
        string json = JsonSerializer.Serialize(
            configuration,
            new JsonSerializerOptions { WriteIndented = true }
        );

        File.WriteAllText(_configFilePath, json);
    }

    public T? Load<T>()
    {
        if (!File.Exists(_configFilePath))
            return default;

        string json = File.ReadAllText(_configFilePath);

        return JsonSerializer.Deserialize<T>(json);
    }

    public bool Exists()
    {
        return File.Exists(_configFilePath);
    }

    public bool Delete()
    {
        if (!File.Exists(_configFilePath))
            return false;

        File.Delete(_configFilePath);

        return true;
    }
}
