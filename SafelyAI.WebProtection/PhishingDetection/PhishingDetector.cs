
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;

namespace SafelyAI.WebProtection.PhishingDetection;

public class PhishingDetector
{
    private readonly string[] _protectedBrands =
    {
        "google",
        "microsoft",
        "facebook",
        "paypal",
        "amazon",
        "apple"
    };

    public PhishingAnalysisResult Analyze(string url)
    {
        var result = new PhishingAnalysisResult
        {
            Url = url
        };

        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri) ||
            (uri.Scheme != Uri.UriSchemeHttp &&
             uri.Scheme != Uri.UriSchemeHttps))
        {
            result.Findings.Add("URL invalide.");
            result.RiskLevel = "Invalide";
            return result;
        }

        string host = uri.IdnHost.ToLowerInvariant();
        string[] labels = host.Split('.');

        // Détection des domaines utilisant des caractères Unicode
        if (host.StartsWith("xn--") ||
            host.Contains(".xn--"))
        {
            result.Findings.Add(
                "Nom de domaine internationalisé à vérifier.");
        }

        // Détection des sous-domaines trompeurs
       
bool isIpAddress = IPAddress.TryParse(
    uri.Host, out _);

if (!isIpAddress && labels.Length >= 4)
{
    result.Findings.Add(
        "Nombre élevé de sous-domaines.");
}
        // Vérification des marques protégées
        foreach (string brand in _protectedBrands)
        {
            bool containsBrand = labels.Any(label =>
                label.Contains(brand) && label != brand);

            if (containsBrand)
            {
                result.Findings.Add(
                    $"Le domaine contient une marque : {brand}.");
            }
        }

        // Détection des caractères trompeurs
        if (uri.UserInfo.Length > 0)
        {
            result.Findings.Add(
                "Présence d'informations utilisateur dans l'URL.");
        }

        // Détection des domaines avec beaucoup de tirets
        if (host.Count(c => c == '-') >= 2)
        {
            result.Findings.Add(
                "Nom de domaine contenant plusieurs tirets.");
        }

        // Détection des URL utilisant une adresse IP
        if (uri.HostNameType == UriHostNameType.IPv4 ||
            uri.HostNameType == UriHostNameType.IPv6)
        {
            result.Findings.Add(
                "Utilisation directe d'une adresse IP.");
        }

        result.RiskScore = Math.Min(
            result.Findings.Count * 20, 100);

        result.RiskLevel = result.RiskScore switch
        {
            >= 60 => "Élevé",
            >= 20 => "Modéré",
            _ => "Faible"
        };

        return result;
    }
}

public class PhishingAnalysisResult
{
    public string Url { get; set; } = "";

    public int RiskScore { get; set; }

    public string RiskLevel { get; set; } = "Inconnu";

    public List<string> Findings { get; set; } = new();
}
