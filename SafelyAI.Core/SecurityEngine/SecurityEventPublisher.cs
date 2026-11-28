
using SafelyAI.Core.Events;
using SafelyAI.Core.Models;

namespace SafelyAI.Core.SecurityEngine;

public class SecurityEventPublisher
{
    public event EventHandler<ThreatDetectedEvent>? ThreatDetected;

    public event EventHandler<SecurityEventRaisedEvent>? SecurityEventRaised;

    public event EventHandler<IncidentCreatedEvent>? IncidentCreated;

    public void PublishThreatDetected(SecurityThreat threat)
    {
        ArgumentNullException.ThrowIfNull(threat);

        ThreatDetected?.Invoke(
            this,
            new ThreatDetectedEvent(threat));
    }

    public void PublishSecurityEvent(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);

        SecurityEventRaised?.Invoke(
            this,
            new SecurityEventRaisedEvent(securityEvent));
    }

    public void PublishIncidentCreated(SecurityIncident incident)
    {
        ArgumentNullException.ThrowIfNull(incident);

        IncidentCreated?.Invoke(
            this,
            new IncidentCreatedEvent(incident));
    }
}
