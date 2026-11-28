using System.IO;
using System.Text.Json;

namespace SafelyAI.Desktop.Services;

public sealed record AppPreferences(bool IsDarkMode, string ProtectionMode)
{
    public static AppPreferences Default { get; } = new(true, "Équilibré");
}

public static class AppPreferencesStore
{
    private static readonly string PreferencesPath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SafelyAI", "preferences.json");

    public static AppPreferences Load()
    {
        try
        {
            if (!File.Exists(PreferencesPath)) return AppPreferences.Default;
            return JsonSerializer.Deserialize<AppPreferences>(File.ReadAllText(PreferencesPath)) ?? AppPreferences.Default;
        }
        catch { return AppPreferences.Default; }
    }

    public static void Save(AppPreferences preferences)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PreferencesPath)!);
            File.WriteAllText(PreferencesPath, JsonSerializer.Serialize(preferences, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch { /* Settings stay active for this session if persistence is unavailable. */ }
    }
}
