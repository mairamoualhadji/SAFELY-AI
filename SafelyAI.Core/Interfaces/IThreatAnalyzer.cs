
using SafelyAI.Core.Models;

namespace SafelyAI.Core.Interfaces;

public interface IThreatAnalyzer
{
    SecurityAnalysisResult AnalyzeThreat(SecurityThreat threat);

    SecurityAnalysisResult AnalyzeEvent(SecurityEvent securityEvent);

    int CalculateRiskScore(SecurityThreat threat);
}
