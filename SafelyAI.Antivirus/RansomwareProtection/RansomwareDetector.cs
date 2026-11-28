namespace SafelyAI.Antivirus.RansomwareProtection;

public sealed record RansomwareAssessment(bool IsSuspicious, string Severity, string Explanation);

/// <summary>Conservative rule-based assessment for rapid destructive file activity.</summary>
public sealed class RansomwareDetector
{
    public RansomwareAssessment Assess(FileActivityBurst burst)
    {
        if (burst.ChangedFiles >= 40 && burst.DeletedFiles >= 15)
            return new(true, "Élevée", $"{burst.DeletedFiles} suppressions parmi {burst.ChangedFiles} changements dans {burst.Window.TotalSeconds:0} s.");
        if (burst.ChangedFiles >= 60 && burst.RenamedFiles >= 20)
            return new(true, "Élevée", $"{burst.RenamedFiles} renommages parmi {burst.ChangedFiles} changements dans {burst.Window.TotalSeconds:0} s.");
        if (burst.ChangedFiles >= 40)
            return new(true, "À vérifier", $"{burst.ChangedFiles} changements rapides détectés dans {burst.Window.TotalSeconds:0} s.");
        return new(false, "Faible", "Aucune rafale inhabituelle selon les seuils locaux.");
    }
}
