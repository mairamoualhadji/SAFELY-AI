
using System;
using System.Collections.Generic;

namespace SafelyAI.WebProtection.UrlAnalysis;

public class UrlAnalyzer
{
    public UrlAnalysisResult Analyze(string url)
    {
        var result = new UrlAnalysisResult
        {
            Url = url,
            IsValid = Uri.TryCreate(url, UriKind.Absolute, out Uri? uri)
                      && (uri.Scheme == Uri.UriSchemeHttp ||
                          uri.Scheme == Uri.UriSchemeHttps)
        };

        if (!result.IsValid || uri == null)
        {
            result.Risks.Add("URL invalide ou protocole non autorisé.");
            return result;
        }

        if (uri.Scheme == Uri.UriSchemeHttp)
            result.Risks.Add("Connexion non sécurisée (HTTP).");

        if (uri.HostNameType == UriHostNameType.IPv4 ||
            uri.HostNameType == UriHostNameType.IPv6)
            result.Risks.Add("L'adresse utilise une IP au lieu d'un nom de domaine.");

        if (uri.Host.Contains('@'))
            result.Risks.Add("Présence d'un caractère potentiellement trompeur.");

        string[] suspiciousWords =
        {
            "login", "verify", "account", "password",
            "banking", "secure", "update"
        };

        foreach (string word in suspiciousWords)
        {
            if (uri.AbsoluteUri.Contains(word,
                StringComparison.OrdinalIgnoreCase))
            {
                result.Risks.Add($"Mot suspect détecté : {word}");
            }
        }

        result.RiskScore = Math.Min(result.Risks.Count * 20, 100);

        result.RiskLevel = result.RiskScore switch
        {
            >= 60 => "Élevé",
            >= 20 => "Modéré",
            _ => "Faible"
        };

        return result;
    }
}

public class UrlAnalysisResult
{
    public string Url { get; set; } = "";
    public bool IsValid { get; set; }
    public int RiskScore { get; set; }
    public string RiskLevel { get; set; } = "Inconnu";
    public List<string> Risks { get; set; } = new();
}
