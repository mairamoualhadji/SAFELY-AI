using SafelyAI.Core.Interfaces;
using SafelyAI.Core.Models;

namespace SafelyAI.Infrastructure.Database;

public sealed class DatabaseIncidentStore : IIncidentStore
{
    private readonly DatabaseManager database;

    public DatabaseIncidentStore(DatabaseManager database)
    {
        this.database = database;
        database.Initialize();
    }

    public IReadOnlyList<SecurityIncident> Load() => database.LoadIncidents();
    public void Save(SecurityIncident incident) => database.SaveIncident(incident);
    public void Update(SecurityIncident incident) => database.SaveIncident(incident);
}
