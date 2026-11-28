
using SafelyAI.Core.Models;

namespace SafelyAI.Core.Interfaces;

public interface IIncidentManager
{
    SecurityIncident CreateIncident(
        string title,
        string description,
        string type,
        string severity);

    List<SecurityIncident> GetAllIncidents();

    SecurityIncident? GetIncidentById(Guid id);

    bool UpdateIncidentStatus(Guid id, string newStatus);
}
