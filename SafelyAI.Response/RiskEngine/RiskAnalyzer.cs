
using System;

namespace SafelyAI.Response.RiskEngine
{
    public class RiskAnalyzer
    {
        public RiskAnalysisResult Analyze(int score)
        {
            var result = new RiskAnalysisResult();

            if (score < 0 || score > 100)
            {
                result.Success = false;
                result.Message = "Le score doit être compris entre 0 et 100.";
                return result;
            }

            result.Success = true;
            result.Score = score;

            if (score >= 80)
            {
                result.Level = "Critique";
                result.Recommendation = "Bloquer la menace et isoler l'élément concerné.";
            }
            else if (score >= 60)
            {
                result.Level = "Élevé";
                result.Recommendation = "Intervenir rapidement et surveiller la menace.";
            }
            else if (score >= 30)
            {
                result.Level = "Modéré";
                result.Recommendation = "Effectuer une analyse complémentaire.";
            }
            else
            {
                result.Level = "Faible";
                result.Recommendation = "Continuer la surveillance.";
            }

            result.Message = "Analyse des risques terminée.";

            return result;
        }
    }

    public class RiskAnalysisResult
    {
        public bool Success { get; set; }

        public int Score { get; set; }

        public string Level { get; set; } = "";

        public string Recommendation { get; set; } = "";

        public string Message { get; set; } = "";
    }
}
