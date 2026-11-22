
namespace SafelyAI.Core.Models;

public class SecurityEvent
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public string EventType { get; set; } = string.Empty;

    public string Description { get; set; } = string.Empty;

    public string Severity { get; set; } = "Faible";

    public DateTime CreatedAt { get; set; } = DateTime.Now;

    public string Source { get; set; } = string.Empty;

    public bool IsProcessed { get; set; }
}
