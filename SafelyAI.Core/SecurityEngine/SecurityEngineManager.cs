
using SafelyAI.Core.Models;
using SafelyAI.Core.Interfaces;

namespace SafelyAI.Core.SecurityEngine;

public class SecurityEngineManager
{
    public ThreatAnalyzer ThreatAnalyzer { get; }

    public SecurityEventPublisher EventPublisher { get; }

    private readonly IIncidentManager? _incidentManager;

    // Constructeur conservé pour les anciens tests et modules
    public SecurityEngineManager()
        : this(null)
    {
    }

    // Constructeur permettant de connecter IncidentManager
    public SecurityEngineManager(IIncidentManager? incidentManager)
    {
        ThreatAnalyzer = new ThreatAnalyzer();
        EventPublisher = new SecurityEventPublisher();
        _incidentManager = incidentManager;
    }

    public SecurityAnalysisResult AnalyzeThreat(SecurityThreat threat)
    {
        var result = ThreatAnalyzer.AnalyzeThreat(threat);

        if (result.Success)
        {
            EventPublisher.PublishThreatDetected(threat);
        }

        return result;
    }

    public SecurityAnalysisResult AnalyzeEvent(SecurityEvent securityEvent)
    {
        var result = ThreatAnalyzer.AnalyzeEvent(securityEvent);

        if (result.Success)
        {
            EventPublisher.PublishSecurityEvent(securityEvent);
        }

        return result;
    }

    // Créer un incident à partir d'une menace détectée
    public SecurityIncident? CreateIncidentFromThreat(SecurityThreat threat)
    {
        if (_incidentManager == null)
        {
            return null;
        }

        var result = AnalyzeThreat(threat);

        if (!result.Success)
        {
            return null;
        }

        var incident = _incidentManager.CreateIncident(
            $"Menace détectée : {threat.Name}",
            threat.Description,
            threat.ThreatType,
            threat.Severity
        );

        RegisterIncident(incident);

        return incident;
    }

    public void RegisterIncident(SecurityIncident incident)
    {
        EventPublisher.PublishIncidentCreated(incident);
    }
}
