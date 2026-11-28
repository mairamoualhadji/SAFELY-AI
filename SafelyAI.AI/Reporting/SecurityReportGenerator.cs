using System.Text.Json;
using SafelyAI.AI.AnomalyDetection;
using SafelyAI.AI.BehaviorAnalysis;
using SafelyAI.AI.FileAnalysis;
using SafelyAI.AI.ThreatClassification;

namespace SafelyAI.AI.Reporting;

public sealed class SecurityReportGenerator
{
    private readonly ThreatExplanation? _threatExplanation;

    public SecurityReportGenerator(ThreatExplanation? threatExplanation = null)
    {
        _threatExplanation = threatExplanation;
    }

    public async Task<SecurityReport> GenerateAsync(
        IEnumerable<BehaviorAnalysisResult>? processResults = null,
        IEnumerable<FileAnalysisResult>? fileResults = null,
        IEnumerable<SystemAnomalyReport>? systemReports = null,
        CancellationToken cancellationToken = default)
    {
        var processes = processResults?.ToArray() ?? Array.Empty<BehaviorAnalysisResult>();
        var files = fileResults?.ToArray() ?? Array.Empty<FileAnalysisResult>();
        var systems = systemReports?.ToArray() ?? Array.Empty<SystemAnomalyReport>();

        var findings = new List<string>();
        findings.AddRange(processes
            .Where(result => result.IsSuspicious)
            .Select(result => $"Processus {result.Behavior.Process.Name} : {string.Join(" ; ", result.Behavior.Reasons)}"));
        findings.AddRange(files
            .Where(result => result.IsSuspicious)
            .Select(result => $"Fichier {Path.GetFileName(result.Path)} : {string.Join(" ; ", result.Findings)}"));
        findings.AddRange(systems
            .SelectMany(report => report.Findings)
            .Select(finding => finding.Description));

        var systemLevel = systems.Any(report => report.HasAnomalies)
            ? ThreatLevel.Medium
            : ThreatLevel.Info;
        var overallLevel = processes.Select(result => result.ThreatLevel)
            .Concat(files.Select(result => result.ThreatLevel))
            .Append(systemLevel)
            .DefaultIfEmpty(ThreatLevel.Info)
            .Max();

        var summary = BuildSummary(processes.Length, files.Length, systems.Length, findings.Count, overallLevel);
        var recommendations = SecurityRecommendationEngine.For(overallLevel, findings);
        var usedLocalModel = false;

        if (_threatExplanation is not null)
        {
            var advice = await _threatExplanation.AdviseAsync(
                "Rapport de sécurité SAFELY AI",
                overallLevel,
                findings.Take(20),
                cancellationToken);
            summary = advice.Summary;
            recommendations = advice.Recommendations;
            usedLocalModel = advice.UsedLocalModel;
        }

        return new SecurityReport(
            DateTime.UtcNow,
            overallLevel,
            processes.Length,
            processes.Count(result => result.IsSuspicious),
            files.Length,
            files.Count(result => result.IsSuspicious),
            systems.Sum(report => report.Findings.Count),
            findings,
            summary,
            recommendations,
            usedLocalModel);
    }

    public static void SaveJson(SecurityReport report, string path)
    {
        ArgumentNullException.ThrowIfNull(report);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);

        var fullPath = Path.GetFullPath(path);
        var directory = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(fullPath, JsonSerializer.Serialize(report, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
    }

    private static string BuildSummary(
        int processCount,
        int fileCount,
        int systemReportCount,
        int findingCount,
        ThreatLevel level) =>
        $"Rapport terminé : {processCount} processus, {fileCount} fichiers et " +
        $"{systemReportCount} relevés système analysés. {findingCount} indice(s) relevé(s). " +
        $"Niveau global : {level}.";
}
