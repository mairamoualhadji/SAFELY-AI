namespace SafelyAI.AI.ThreatClassification;

public static class SecurityRecommendationEngine
{
    public static IReadOnlyList<string> For(
        ThreatLevel level,
        IEnumerable<string> reasons)
    {
        ArgumentNullException.ThrowIfNull(reasons);

        var text = string.Join(" ", reasons).ToLowerInvariant();
        var recommendations = new List<string>();

        if (text.Contains("télécharg") || text.Contains("temporaire") || text.Contains("script"))
        {
            recommendations.Add("Ne lance pas le fichier et vérifie sa provenance avant toute ouverture.");
            recommendations.Add("Supprime ou isole le fichier s'il n'est pas nécessaire.");
        }

        if (text.Contains("connexion") || text.Contains("réseau"))
        {
            recommendations.Add("Vérifie les connexions réseau du processus et bloque-les si elles sont inattendues.");
        }

        if (text.Contains("processeur") || text.Contains("mémoire"))
        {
            recommendations.Add("Observe le processus dans le temps et ferme-le seulement si son origine est connue.");
        }

        switch (level)
        {
            case ThreatLevel.Critical:
                recommendations.Add("Isole immédiatement l'élément et lance un scan complet hors ligne.");
                recommendations.Add("Change les mots de passe depuis un appareil sûr si une compromission est possible.");
                break;
            case ThreatLevel.High:
                recommendations.Add("Mets l'élément en quarantaine et vérifie les journaux de sécurité.");
                break;
            case ThreatLevel.Medium:
                recommendations.Add("Effectue une vérification complémentaire avant d'autoriser l'élément.");
                break;
            default:
                recommendations.Add("Continue la surveillance et conserve les mises à jour de sécurité activées.");
                break;
        }

        return recommendations.Distinct(StringComparer.Ordinal).Take(5).ToArray();
    }

    public static ThreatAdvice Build(
        string subject,
        ThreatLevel level,
        IEnumerable<string> reasons,
        string? explanation = null,
        bool usedLocalModel = false)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        ArgumentNullException.ThrowIfNull(reasons);

        var reasonList = reasons.ToArray();
        var summary = string.IsNullOrWhiteSpace(explanation)
            ? $"{subject} présente un niveau de risque {level}."
            : explanation.Trim();

        return new ThreatAdvice(
            summary,
            For(level, reasonList),
            usedLocalModel);
    }
}
