
namespace SafelyAI.Core.Models;

public class SecurityThreat
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string Name { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public string ThreatType { get; set; } = string.Empty;

    public string Severity { get; set; } = "Faible";

    public string Source { get; set; } = string.Empty;

    public DateTime DetectedAt { get; set; } = DateTime.Now;

    public bool IsQuarantined { get; set; }

    public bool IsBlocked { get; set; }
}
