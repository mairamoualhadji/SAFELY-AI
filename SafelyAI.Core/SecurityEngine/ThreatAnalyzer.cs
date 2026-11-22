
using SafelyAI.Core.Interfaces;
using SafelyAI.Core.Models;

namespace SafelyAI.Core.SecurityEngine;

public class ThreatAnalyzer : IThreatAnalyzer
{
    public SecurityAnalysisResult AnalyzeThreat(SecurityThreat threat)
    {
        if (threat == null)
        {
            return new SecurityAnalysisResult
            {
                Success = false,
                Message = "La menace à analyser est inexistante."
            };
        }

        int score = CalculateRiskScore(threat);

        return new SecurityAnalysisResult
        {
            Success = true,
            RiskScore = score,
            RiskLevel = GetRiskLevel(score),
            Message = "Analyse de la menace terminée.",
            Findings = new List<string>
            {
                $"Menace : {threat.Name}",
                $"Type : {threat.ThreatType}",
                $"Gravité déclarée : {threat.Severity}"
            }
        };
    }

    public SecurityAnalysisResult AnalyzeEvent(SecurityEvent securityEvent)
    {
        if (securityEvent == null)
        {
            return new SecurityAnalysisResult
            {
                Success = false,
                Message = "L'événement à analyser est inexistant."
            };
        }

        int score = GetScoreFromSeverity(securityEvent.Severity);

        return new SecurityAnalysisResult
        {
            Success = true,
            RiskScore = score,
            RiskLevel = GetRiskLevel(score),
            Message = "Analyse de l'événement terminée.",
            Findings = new List<string>
            {
                $"Type d'événement : {securityEvent.EventType}",
                $"Description : {securityEvent.Description}",
                $"Gravité : {securityEvent.Severity}"
            }
        };
    }

    public int CalculateRiskScore(SecurityThreat threat)
    {
        if (threat == null)
        {
            return 0;
        }

        return GetScoreFromSeverity(threat.Severity);
    }

    private static int GetScoreFromSeverity(string severity)
    {
        return severity?.Trim().ToLowerInvariant() switch
        {
            "faible" => 10,
            "modéré" => 45,
            "élevé" => 70,
            "critique" => 90,
            _ => 0
        };
    }

    private static string GetRiskLevel(int score)
    {
        return score switch
        {
            >= 80 => "Critique",
            >= 60 => "Élevé",
            >= 30 => "Modéré",
            _ => "Faible"
        };
    }
}
