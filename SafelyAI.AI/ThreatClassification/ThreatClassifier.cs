namespace SafelyAI.AI.ThreatClassification;

public enum ThreatLevel { Info, Low, Medium, High, Critical }

public static class ThreatClassifier
{
    // Transforme un score (0 à 100) en niveau de gravité.
    public static ThreatLevel FromScore(int score) => score switch
    {
        >= 80 => ThreatLevel.Critical,
        >= 60 => ThreatLevel.High,
        >= 40 => ThreatLevel.Medium,
        >= 20 => ThreatLevel.Low,
        _ => ThreatLevel.Info
    };
}
