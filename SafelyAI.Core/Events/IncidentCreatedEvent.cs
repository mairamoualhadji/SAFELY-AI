
using SafelyAI.Core.Models;

namespace SafelyAI.Core.Events;

public class IncidentCreatedEvent : EventArgs
{
    public SecurityIncident Incident { get; }

    public DateTime CreatedAt { get; }

    public IncidentCreatedEvent(SecurityIncident incident)
    {
        Incident = incident
            ?? throw new ArgumentNullException(nameof(incident));

        CreatedAt = DateTime.Now;
    }
}
