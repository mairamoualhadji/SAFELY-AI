
using SafelyAI.Core.Models;

namespace SafelyAI.Core.Events;

public class SecurityEventRaisedEvent : EventArgs
{
    public SecurityEvent SecurityEvent { get; }

    public DateTime RaisedAt { get; }

    public SecurityEventRaisedEvent(SecurityEvent securityEvent)
    {
        SecurityEvent = securityEvent
            ?? throw new ArgumentNullException(nameof(securityEvent));

        RaisedAt = DateTime.Now;
    }
}
