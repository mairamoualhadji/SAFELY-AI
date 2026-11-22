
using SafelyAI.Core.Models;

namespace SafelyAI.Core.Events;

public class ThreatDetectedEvent : EventArgs
{
    public SecurityThreat Threat { get; }

    public DateTime DetectedAt { get; }

    public ThreatDetectedEvent(SecurityThreat threat)
    {
        Threat = threat ?? throw new ArgumentNullException(nameof(threat));
        DetectedAt = DateTime.Now;
    }
}
