using Microsoft.Win32;

namespace SafelyAI.SystemMonitor.RegistryMonitor;

public record RegistryValueSnapshot(string Hive, string KeyPath, string Name, string Value);
public record RegistryChange(string ChangeType, RegistryValueSnapshot Item);

/// <summary>Read-only monitoring of security-sensitive Windows registry locations.</summary>
public sealed class RegistryMonitor
{
    private static readonly (RegistryHive Hive, string Name)[] Locations =
    {
        (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\Run"),
        (RegistryHive.LocalMachine, @"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
    };

    public List<RegistryValueSnapshot> CaptureSnapshot()
    {
        if (!OperatingSystem.IsWindows()) return new();
        var result = new List<RegistryValueSnapshot>();
        foreach (var (hive, path) in Locations)
        {
            try
            {
                using var root = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
                using var key = root.OpenSubKey(path);
                if (key == null) continue;
                foreach (var name in key.GetValueNames())
                    result.Add(new(hive.ToString(), path, name, key.GetValue(name)?.ToString() ?? string.Empty));
            }
            catch (System.Security.SecurityException) { }
            catch (UnauthorizedAccessException) { }
        }
        return result.OrderBy(x => x.Hive).ThenBy(x => x.KeyPath).ThenBy(x => x.Name).ToList();
    }

    public List<RegistryChange> DetectChanges(IEnumerable<RegistryValueSnapshot> before, IEnumerable<RegistryValueSnapshot> after)
    {
        var oldValues = before.ToDictionary(Key, StringComparer.OrdinalIgnoreCase);
        var newValues = after.ToDictionary(Key, StringComparer.OrdinalIgnoreCase);
        var changes = new List<RegistryChange>();
        foreach (var item in after)
        {
            string key = Key(item);
            if (!oldValues.TryGetValue(key, out var previous)) changes.Add(new("Ajout", item));
            else if (!string.Equals(previous.Value, item.Value, StringComparison.Ordinal)) changes.Add(new("Modification", item));
        }
        foreach (var item in before)
            if (!newValues.ContainsKey(Key(item))) changes.Add(new("Suppression", item));
        return changes;
    }

    private static string Key(RegistryValueSnapshot item) => $"{item.Hive}|{item.KeyPath}|{item.Name}";
}
