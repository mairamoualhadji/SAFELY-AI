using System.Security.Cryptography;
using SafelyAI.AI.ThreatClassification;

namespace SafelyAI.AI.FileAnalysis;

public sealed class FileAnalysisService
{
    private readonly FileSuspicionAnalyzer _suspicionAnalyzer;
    private readonly ThreatExplanation _threatExplanation;

    public FileAnalysisService(
        FileSuspicionAnalyzer suspicionAnalyzer,
        ThreatExplanation threatExplanation)
    {
        _suspicionAnalyzer = suspicionAnalyzer ?? throw new ArgumentNullException(nameof(suspicionAnalyzer));
        _threatExplanation = threatExplanation ?? throw new ArgumentNullException(nameof(threatExplanation));
    }

    public async Task<FileAnalysisResult> AnalyzeAsync(
        string path,
        CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        cancellationToken.ThrowIfCancellationRequested();

        var fullPath = Path.GetFullPath(path);
        if (!File.Exists(fullPath))
        {
            return new FileAnalysisResult(
                fullPath,
                false,
                false,
                0,
                string.Empty,
                0,
                ThreatLevel.Info,
                new[] { "Le fichier n'existe pas." },
                "Aucune analyse n'a été effectuée.",
                SecurityRecommendationEngine.For(ThreatLevel.Info, Array.Empty<string>()),
                DateTime.UtcNow);
        }

        try
        {
            var file = new FileInfo(fullPath);
            var assessment = _suspicionAnalyzer.Analyze(file);
            var level = ThreatClassifier.FromScore(assessment.Score);
            var findings = assessment.Findings.Select(finding => finding.Description).ToArray();
            var advice = await _threatExplanation.AdviseAsync(
                file.Name,
                level,
                findings,
                cancellationToken);

            var hash = await ComputeSha256Async(file, cancellationToken);
            return new FileAnalysisResult(
                fullPath,
                true,
                true,
                file.Length,
                hash,
                assessment.Score,
                level,
                findings,
                advice.Summary,
                advice.Recommendations,
                DateTime.UtcNow);
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (UnauthorizedAccessException)
        {
            return Inaccessible(fullPath, "Accès refusé pendant l'analyse du fichier.");
        }
        catch (IOException exception)
        {
            return Inaccessible(fullPath, $"Le fichier n'a pas pu être lu : {exception.Message}");
        }
    }

    private static async Task<string> ComputeSha256Async(
        FileInfo file,
        CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(
            file.FullName,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete,
            bufferSize: 64 * 1024,
            options: FileOptions.Asynchronous | FileOptions.SequentialScan);

        var hash = await SHA256.HashDataAsync(stream, cancellationToken);
        return Convert.ToHexString(hash);
    }

    private static FileAnalysisResult Inaccessible(string path, string message) =>
        new(
            path,
            true,
            false,
            0,
            string.Empty,
            0,
            ThreatLevel.Info,
            new[] { message },
            message,
            SecurityRecommendationEngine.For(ThreatLevel.Info, Array.Empty<string>()),
            DateTime.UtcNow);
}
