using Microsoft.Win32;
namespace SafelyAI.SystemMonitor.StartupMonitor;

public record StartupItem(string Source, string Name, string Command);

public class StartupMonitor
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";

    // Programmes lancés au démarrage (clés Run du registre et dossiers Démarrage).
    public List<StartupItem> GetItems()
    {
        var items = new List<StartupItem>();
        ReadKey(Registry.CurrentUser, "HKCU Run", items);
        ReadKey(Registry.LocalMachine, "HKLM Run", items);
        foreach (var folder in new[] { Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                                       Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup) })
            if (Directory.Exists(folder))
                foreach (var file in Directory.GetFiles(folder))
                    items.Add(new StartupItem("Dossier Démarrage", Path.GetFileName(file), file));
        return items;
    }

    // Éléments apparus depuis une liste précédente.
    public List<StartupItem> DetectNew(List<StartupItem> previous) =>
        GetItems().Where(i => !previous.Any(p => p.Source == i.Source && p.Name == i.Name && p.Command == i.Command)).ToList();

    public static bool IsSuspicious(StartupItem item) =>
        item.Command.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
        item.Command.Contains("-enc", StringComparison.OrdinalIgnoreCase) ||
        item.Command.Contains("powershell", StringComparison.OrdinalIgnoreCase);

    private static void ReadKey(RegistryKey root, string source, List<StartupItem> items)
    {
        using var key = root.OpenSubKey(RunKey);
        if (key == null) return;
        foreach (var name in key.GetValueNames())
            items.Add(new StartupItem(source, name, key.GetValue(name)?.ToString() ?? ""));
    }
}
