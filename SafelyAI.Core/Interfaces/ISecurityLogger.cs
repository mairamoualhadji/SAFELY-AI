
using SafelyAI.Core.Models;

namespace SafelyAI.Core.Interfaces;

public interface ISecurityLogger
{
    void LogInfo(string message);

    void LogWarning(string message);

    void LogError(string message);

    void LogEvent(SecurityEvent securityEvent);
}
