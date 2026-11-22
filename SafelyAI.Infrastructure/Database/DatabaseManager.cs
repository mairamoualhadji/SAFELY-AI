
using Microsoft.Data.Sqlite;

namespace SafelyAI.Infrastructure.Database;

public class DatabaseManager
{
    private readonly string _connectionString;

    public DatabaseManager(string databasePath)
    {
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
}
