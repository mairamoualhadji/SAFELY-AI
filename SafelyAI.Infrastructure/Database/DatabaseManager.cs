
using Microsoft.Data.Sqlite;
using SafelyAI.Core.Models;

namespace SafelyAI.Infrastructure.Database;

public class DatabaseManager
{
    private readonly string _connectionString;

    public DatabaseManager(string databasePath)
    {
        if (string.IsNullOrWhiteSpace(databasePath))
            throw new ArgumentException("Le chemin de la base est obligatoire.", nameof(databasePath));
        var directory = Path.GetDirectoryName(Path.GetFullPath(databasePath));
        if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
        _connectionString = $"Data Source={databasePath}";
    }

    public void Initialize()
    {
        using var connection = new SqliteConnection(_connectionString);
        connection.Open();

        var command = connection.CreateCommand();

        command.CommandText = """
            CREATE TABLE IF NOT EXISTS SecurityEvents (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                EventType TEXT NOT NULL,
                Description TEXT NOT NULL,
                Severity TEXT NOT NULL,
                CreatedAt TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS SecurityIncidents (
                Id TEXT PRIMARY KEY,
                Title TEXT NOT NULL,
                Description TEXT NOT NULL,
                Type TEXT NOT NULL,
                Severity TEXT NOT NULL,
                Status TEXT NOT NULL,
                CreatedAt TEXT NOT NULL,
                UpdatedAt TEXT NULL
            );
            """;

        command.ExecuteNonQuery();
    }

    public bool TestConnection()
    {
        try
        {
            using var connection = new SqliteConnection(_connectionString);
            connection.Open();

            return connection.State == System.Data.ConnectionState.Open;
        }
        catch
        {
            return false;
        }
    }
    public void Close()
{
    SqliteConnection.ClearAllPools();
}

    public void SaveIncident(SecurityIncident incident)
    {
        ArgumentNullException.ThrowIfNull(incident);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = """
            INSERT OR REPLACE INTO SecurityIncidents
            (Id, Title, Description, Type, Severity, Status, CreatedAt, UpdatedAt)
            VALUES ($id, $title, $description, $type, $severity, $status, $created, $updated);
            """;
        AddIncidentParameters(command, incident);
        command.ExecuteNonQuery();
    }

    public IReadOnlyList<SecurityIncident> LoadIncidents()
    {
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Id, Title, Description, Type, Severity, Status, CreatedAt, UpdatedAt FROM SecurityIncidents ORDER BY CreatedAt DESC";
        using var reader = command.ExecuteReader();
        var incidents = new List<SecurityIncident>();
        while (reader.Read())
        {
            incidents.Add(new SecurityIncident
            {
                Id = Guid.Parse(reader.GetString(0)),
                Title = reader.GetString(1),
                Description = reader.GetString(2),
                Type = reader.GetString(3),
                Severity = reader.GetString(4),
                Status = reader.GetString(5),
                CreatedAt = DateTime.Parse(reader.GetString(6), null, System.Globalization.DateTimeStyles.RoundtripKind),
                UpdatedAt = reader.IsDBNull(7) ? null : DateTime.Parse(reader.GetString(7), null, System.Globalization.DateTimeStyles.RoundtripKind)
            });
        }
        return incidents;
    }

    public void SaveEvent(SecurityEvent securityEvent)
    {
        ArgumentNullException.ThrowIfNull(securityEvent);
        using var connection = OpenConnection();
        using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO SecurityEvents (EventType, Description, Severity, CreatedAt) VALUES ($type, $description, $severity, $created)";
        command.Parameters.AddWithValue("$type", securityEvent.EventType);
        command.Parameters.AddWithValue("$description", securityEvent.Description);
        command.Parameters.AddWithValue("$severity", securityEvent.Severity);
        command.Parameters.AddWithValue("$created", securityEvent.CreatedAt.ToString("O"));
        command.ExecuteNonQuery();
    }

    private SqliteConnection OpenConnection()
    {
        var connection = new SqliteConnection(_connectionString);
        connection.Open();
        Initialize();
        return connection;
    }

    private static void AddIncidentParameters(SqliteCommand command, SecurityIncident incident)
    {
        command.Parameters.AddWithValue("$id", incident.Id.ToString());
        command.Parameters.AddWithValue("$title", incident.Title);
        command.Parameters.AddWithValue("$description", incident.Description);
        command.Parameters.AddWithValue("$type", incident.Type);
        command.Parameters.AddWithValue("$severity", incident.Severity);
        command.Parameters.AddWithValue("$status", incident.Status);
        command.Parameters.AddWithValue("$created", incident.CreatedAt.ToString("O"));
        command.Parameters.AddWithValue("$updated", incident.UpdatedAt?.ToString("O") ?? (object)DBNull.Value);
    }
}
