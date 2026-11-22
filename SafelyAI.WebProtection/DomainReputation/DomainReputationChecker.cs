
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace SafelyAI.WebProtection.DomainReputation
{
    public class DomainReputationChecker
    {
        private readonly string[] suspiciousExtensions =
        {
            ".top", ".xyz", ".click", ".work",
            ".tk", ".ml", ".cf", ".gq"
        };

        private readonly string[] suspiciousWords =
        {
            "login", "verify", "secure", "account",
            "bank", "password", "update", "payment"
        };

        public DomainReputationResult Analyze(string url)
        {
            var result = new DomainReputationResult
            {
                Url = url,
                RiskScore = 0,
                Findings = new List<string>()
            };

           if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri)
    || uri == null
    || (uri.Scheme != "http" && uri.Scheme != "https"))
            {
                result.Findings.Add("URL invalide.");
                result.RiskScore = 100;
                result.RiskLevel = "Élevé";
                return result;
            }

            string host = uri.Host.ToLowerInvariant();

            if (IPAddress.TryParse(host, out _))
            {
                result.Findings.Add("Le site utilise une adresse IP directement.");
            }

            if (host.Contains("xn--"))
            {
                result.Findings.Add("Le domaine utilise un encodage international potentiellement trompeur.");
            }

            if (suspiciousExtensions.Any(ext => host.EndsWith(ext)))
            {
                result.Findings.Add("L'extension du domaine nécessite une vigilance particulière.");
            }

            if (suspiciousWords.Any(word => host.Contains(word)))
            {
                result.Findings.Add("Le domaine contient un mot fréquemment utilisé dans les liens sensibles.");
            }

            result.RiskScore = Math.Min(result.Findings.Count * 20, 100);

            result.RiskLevel = result.RiskScore >= 60
                ? "Élevé"
                : result.RiskScore >= 20
                    ? "Modéré"
                    : "Faible";

            return result;
        }
    }

    public class DomainReputationResult
    {
        public string Url { get; set; } = "";
        public int RiskScore { get; set; }
        public string RiskLevel { get; set; } = "";
        public List<string> Findings { get; set; } = new();
    }
}
