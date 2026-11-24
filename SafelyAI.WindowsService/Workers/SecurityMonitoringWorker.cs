using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SafelyAI.Core.Interfaces;
using SafelyAI.Core.Models;
using SafelyAI.Maintenance.Diagnostics;
using SafelyAI.Response.RiskEngine;

namespace SafelyAI.WindowsService.Workers;

public class SecurityMonitoringWorker : BackgroundService
{
    private readonly ILogger<SecurityMonitoringWorker> _logger;
    private readonly SystemDiagnostics _diagnostics;
    private readonly IIncidentManager _incidentManager;
    private readonly RiskAnalyzer _riskAnalyzer;
    private readonly TimeSpan _interval;
    private readonly double _lowDiskThresholdPercent;
    private bool _lowDiskAlertActive;

    public SecurityMonitoringWorker(
        ILogger<SecurityMonitoringWorker> logger,
        SystemDiagnostics diagnostics,
        IIncidentManager incidentManager,
        RiskAnalyzer riskAnalyzer,
        IConfiguration configuration)
    {
        _logger = logger;
        _diagnostics = diagnostics;
        _incidentManager = incidentManager;
        _riskAnalyzer = riskAnalyzer;
        _interval = TimeSpan.FromSeconds(Math.Clamp(
            configuration.GetValue("SecurityMonitoring:IntervalSeconds", 60),
            10,
            3600));
        _lowDiskThresholdPercent = Math.Clamp(
            configuration.GetValue("SecurityMonitoring:LowDiskThresholdPercent", 10d),
            1d,
            50d);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("SAFELY AI : surveillance démarrée.");
        using var timer = new PeriodicTimer(_interval);

        do
        {
            stoppingToken.ThrowIfCancellationRequested();
            SystemDiagnosticsResult system = _diagnostics.Analyze();

            if (!system.Success)
            {
                _logger.LogError(
                    "Échec du diagnostic système : {Status}",
                    system.Status);
            }
            else
            {
                double freeDiskPercent = system.TotalDiskSpaceGB > 0
                    ? system.FreeDiskSpaceGB / system.TotalDiskSpaceGB * 100
                    : 100;

                _logger.LogInformation(
                    "Diagnostic système terminé. Disque libre : {FreeDiskPercent:F1} %, mémoire disponible : {AvailableMemoryGB:F2} Go.",
                    freeDiskPercent,
                    system.AvailableMemoryGB);

                if (freeDiskPercent <= _lowDiskThresholdPercent)
                {
                    if (!_lowDiskAlertActive)
                    {
                        CreateLowDiskIncident(freeDiskPercent);
                        _lowDiskAlertActive = true;
                    }
                }
                else
                {
                    _lowDiskAlertActive = false;
                }
            }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));

        _logger.LogInformation("SAFELY AI : surveillance arrêtée.");
    }

    private void CreateLowDiskIncident(double freeDiskPercent)
    {
        int riskScore = (int)Math.Clamp(100 - freeDiskPercent, 0, 100);
        RiskAnalysisResult risk = _riskAnalyzer.Analyze(riskScore);
        SecurityIncident incident = _incidentManager.CreateIncident(
            "Espace disque système faible",
            $"L'espace disque libre est de {freeDiskPercent:F1} %, sous le seuil configuré de {_lowDiskThresholdPercent:F1} %. Score de risque : {risk.Score}/100.",
            "Maintenance système",
            risk.Level);

        _logger.LogWarning(
            "Incident {IncidentId} créé : {Title} (gravité : {Severity}).",
            incident.Id,
            incident.Title,
            incident.Severity);
    }
}
