
namespace SafelyAI.Core.Models;

public class SecurityAnalysisResult
{
    public bool Success { get; set; }

    public int RiskScore { get; set; }

    public string RiskLevel { get; set; } = "Faible";

    public string Message { get; set; } = string.Empty;

    public List<string> Findings { get; set; } = new();

    public DateTime AnalyzedAt { get; set; } = DateTime.Now;
}
