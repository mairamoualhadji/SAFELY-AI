
using System;
using System.IO;
using SafelyAI.Core.Interfaces;
using SafelyAI.Core.Models;

namespace SafelyAI.Infrastructure.Logging;

public class SecurityLogger : ISecurityLogger
{
    private readonly string _logFilePath;

    public SecurityLogger(string logFilePath)
    {
        if (string.IsNullOrWhiteSpace(logFilePath))
            throw new ArgumentException("Chemin du journal invalide.");

        _logFilePath = logFilePath;

        string? directory = Path.GetDirectoryName(_logFilePath);

        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }
    }

    public void LogInfo(string message)
    {
        WriteLog("INFO", message);
    }

    public void LogWarning(string message)
    {
        WriteLog("WARNING", message);
    }

    public void LogError(string message)
    {
        WriteLog("ERROR", message);
    }

    public void LogEvent(SecurityEvent securityEvent)
    {
        if (securityEvent == null)
            throw new ArgumentNullException(nameof(securityEvent));

        WriteLog(
            securityEvent.Severity.ToUpperInvariant(),
            $"[{securityEvent.EventType}] {securityEvent.Description} | Source : {securityEvent.Source}"
        );
    }

    private void WriteLog(string level, string message)
    {
        if (string.IsNullOrWhiteSpace(message))
            throw new ArgumentException("Le message ne peut pas être vide.");

        string logEntry =
            $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level}] {message}";

        File.AppendAllText(
            _logFilePath,
            logEntry + Environment.NewLine
        );
    }
}
