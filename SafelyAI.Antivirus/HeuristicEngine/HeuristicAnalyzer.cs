namespace SafelyAI.Antivirus.HeuristicEngine;

public sealed record HeuristicFinding(string Name, string Details);

/// <summary>Conservative metadata heuristics; findings are indicators, not proof that a file is malicious.</summary>
public sealed class HeuristicAnalyzer
{
    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
        { ".exe", ".dll", ".scr", ".com", ".ps1", ".js", ".vbs", ".bat", ".cmd", ".hta", ".msi" };

    public IReadOnlyList<HeuristicFinding> Analyze(string path, long length)
    {
        var findings = new List<HeuristicFinding>();
        var name = Path.GetFileName(path);
        var ext = Path.GetExtension(name);
        var stem = Path.GetFileNameWithoutExtension(name);
        var misleading = Path.GetExtension(stem);
        if (ExecutableExtensions.Contains(ext) && !string.IsNullOrEmpty(misleading) && !ExecutableExtensions.Contains(misleading) && misleading is ".pdf" or ".doc" or ".docx" or ".jpg" or ".png" or ".txt")
            findings.Add(new("Double extension", "Le nom combine une extension de document/média et une extension exécutable."));
        if (ExecutableExtensions.Contains(ext) && (File.GetAttributes(path) & FileAttributes.Hidden) != 0)
            findings.Add(new("Exécutable masqué", "Fichier exécutable marqué comme masqué."));
        if (length is > 0 and < 1024 && ext is ".exe" or ".scr" or ".dll")
            findings.Add(new("Binaire inhabituellement petit", "Le fichier exécutable est très petit; vérifiez sa provenance."));
        if (length is > 0 and <= 2_000_000 && ext is ".ps1" or ".bat" or ".cmd" or ".vbs" or ".js" or ".hta")
        {
            try
            {
                using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                using var reader = new StreamReader(stream, detectEncodingFromByteOrderMarks: true);
                var content = reader.ReadToEnd();
                var remoteFetch = content.Contains("DownloadString", StringComparison.OrdinalIgnoreCase) || content.Contains("Invoke-WebRequest", StringComparison.OrdinalIgnoreCase) || content.Contains("curl ", StringComparison.OrdinalIgnoreCase);
                var dynamicRun = content.Contains("Invoke-Expression", StringComparison.OrdinalIgnoreCase) || content.Contains("IEX(", StringComparison.OrdinalIgnoreCase) || content.Contains("eval(", StringComparison.OrdinalIgnoreCase);
                var encoded = content.Contains("-EncodedCommand", StringComparison.OrdinalIgnoreCase) || content.Contains("FromBase64String", StringComparison.OrdinalIgnoreCase);
                if (remoteFetch && dynamicRun) findings.Add(new("Téléchargement puis exécution dynamique", "Le script semble récupérer du contenu distant et l’exécuter dynamiquement."));
                if (encoded && (content.Contains("-WindowStyle Hidden", StringComparison.OrdinalIgnoreCase) || content.Contains("-w hidden", StringComparison.OrdinalIgnoreCase)))
                    findings.Add(new("Commande encodée et masquée", "Le script combine une commande encodée avec un mode d’exécution masqué."));
                if ((content.Contains("vssadmin", StringComparison.OrdinalIgnoreCase) && content.Contains("delete shadows", StringComparison.OrdinalIgnoreCase)) ||
                    (content.Contains("wmic shadowcopy", StringComparison.OrdinalIgnoreCase) && content.Contains("delete", StringComparison.OrdinalIgnoreCase)) ||
                    (content.Contains("wbadmin", StringComparison.OrdinalIgnoreCase) && content.Contains("delete catalog", StringComparison.OrdinalIgnoreCase)))
                    findings.Add(new("Suppression des copies de récupération", "Le script appelle des outils Windows associés à la suppression de sauvegardes système."));
            }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        return findings;
    }
}
