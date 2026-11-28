using SafelyAI.Core.Interfaces;
using SafelyAI.Core.Models;
using SafelyAI.Infrastructure.Database;

namespace SafelyAI.Infrastructure.Logging;

public sealed class CompositeSecurityLogger : ISecurityLogger
{
    private readonly ISecurityLogger fileLogger;
    private readonly DatabaseManager database;

    public CompositeSecurityLogger(ISecurityLogger fileLogger, DatabaseManager database)
    {
        this.fileLogger = fileLogger;
        this.database = database;
    }

    public void LogInfo(string message) => fileLogger.LogInfo(message);
    public void LogWarning(string message) => fileLogger.LogWarning(message);
    public void LogError(string message) => fileLogger.LogError(message);

    public void LogEvent(SecurityEvent securityEvent)
    {
        fileLogger.LogEvent(securityEvent);
        try { database.SaveEvent(securityEvent); }
        catch { /* Le journal fichier reste disponible si la base est verrouillée. */ }
    }
}
