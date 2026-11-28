using SafelyAI.Core.Models;

namespace SafelyAI.Core.Interfaces;

/// <summary>Persistance abstraction for security incidents.</summary>
public interface IIncidentStore
{
    IReadOnlyList<SecurityIncident> Load();
    void Save(SecurityIncident incident);
    void Update(SecurityIncident incident);
}
