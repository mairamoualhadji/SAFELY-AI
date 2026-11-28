namespace SafelyAI.AI.FileAnalysis;

public sealed class FileSuspicionAnalyzer
{
    private static readonly HashSet<string> ScriptExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".bat", ".cmd", ".js", ".jse", ".ps1", ".vbe", ".vbs", ".wsf"
    };

    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".apk", ".com", ".dll", ".exe", ".jar", ".msi", ".scr", ".sys"
    };

    public FileSuspicionAssessment Analyze(FileInfo file)
    {
        ArgumentNullException.ThrowIfNull(file);

        var findings = new List<FileSuspicionFinding>();
        var path = file.FullName;
        var extension = file.Extension;

        if (ScriptExtensions.Contains(extension))
        {
            findings.Add(new FileSuspicionFinding(
                "script-extension",
                "Le fichier utilise une extension de script exécutable.",
                25));
        }
        else if (ExecutableExtensions.Contains(extension))
        {
            findings.Add(new FileSuspicionFinding(
                "executable-extension",
                "Le fichier est un exécutable ou un composant système.",
                15));
        }

        var fileName = file.Name;
        var firstDot = fileName.IndexOf('.', StringComparison.Ordinal);
        if (firstDot > 0 && firstDot < fileName.LastIndexOf('.'))
        {
            findings.Add(new FileSuspicionFinding(
                "double-extension",
                "Le nom contient plusieurs extensions, technique souvent utilisée pour masquer un exécutable.",
                30));
        }

        if (ContainsPath(path, "\\Downloads\\") ||
            ContainsPath(path, "\\AppData\\Local\\Temp\\") ||
            ContainsPath(path, "\\AppData\\Roaming\\"))
        {
            findings.Add(new FileSuspicionFinding(
                "user-writable-location",
                "Le fichier se trouve dans un emplacement modifiable par l'utilisateur.",
                20));
        }

        if (ContainsPath(path, "\\Startup\\") || ContainsPath(path, "\\Start Menu\\Programs\\Startup\\"))
        {
            findings.Add(new FileSuspicionFinding(
                "startup-location",
                "Le fichier se trouve dans un dossier de démarrage automatique.",
                25));
        }

        if ((File.GetAttributes(path) & FileAttributes.Hidden) != 0)
        {
            findings.Add(new FileSuspicionFinding(
                "hidden-file",
                "Le fichier possède l'attribut caché.",
                10));
        }

        var score = Math.Min(100, findings.Sum(finding => finding.Score));
        return new FileSuspicionAssessment(score, findings);
    }

    private static bool ContainsPath(string path, string segment) =>
        path.Contains(segment, StringComparison.OrdinalIgnoreCase);
}
