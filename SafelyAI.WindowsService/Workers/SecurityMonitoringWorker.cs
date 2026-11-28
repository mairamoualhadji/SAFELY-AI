using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SafelyAI.Core.Interfaces;
using SafelyAI.Core.Models;
using SafelyAI.Maintenance.Diagnostics;
using SafelyAI.Response.RiskEngine;
using SafelyAI.Network.TrafficMonitoring;
using SafelyAI.Network.IntrusionDetection;
using SafelyAI.Identity.SessionMonitoring;
using SafelyAI.SystemMonitor.ProcessMonitor;
using SafelyAI.SystemMonitor.RegistryMonitor;
using SafelyAI.SystemMonitor.StartupMonitor;
using SafelyAI.SystemMonitor.HardwareMonitor;

namespace SafelyAI.WindowsService.Workers;

public class SecurityMonitoringWorker : BackgroundService
{
    private readonly ILogger<SecurityMonitoringWorker> _logger;
    private readonly SystemDiagnostics _diagnostics;
    private readonly IIncidentManager _incidentManager;
    private readonly RiskAnalyzer _riskAnalyzer;
    private readonly TimeSpan _interval;
    private readonly double _lowDiskThresholdPercent;
    private readonly int _failedLoginThreshold;
    private readonly ConnectionMonitor _connectionMonitor;
    private readonly SuspiciousConnectionDetector _connectionDetector;
    private readonly SessionMonitor _sessionMonitor;
    private readonly ProcessMonitor _processMonitor;
    private readonly RegistryMonitor _registryMonitor;
    private readonly StartupMonitor _startupMonitor;
    private readonly HardwareMonitor _hardwareMonitor;
    private List<RegistryValueSnapshot>? _registryBaseline;
    private HardwareSecuritySnapshot? _hardwareBaseline;
    private readonly HashSet<string> _createdAlertKeys = new(StringComparer.Ordinal);
    private bool _lowDiskAlertActive;

    public SecurityMonitoringWorker(
        ILogger<SecurityMonitoringWorker> logger,
        SystemDiagnostics diagnostics,
        IIncidentManager incidentManager,
        RiskAnalyzer riskAnalyzer,
        IConfiguration configuration,
        ConnectionMonitor connectionMonitor,
        SuspiciousConnectionDetector connectionDetector,
        SessionMonitor sessionMonitor,
        ProcessMonitor processMonitor,
        RegistryMonitor registryMonitor,
        StartupMonitor startupMonitor,
        HardwareMonitor hardwareMonitor)
    {
        _logger = logger;
        _diagnostics = diagnostics;
        _incidentManager = incidentManager;
        _riskAnalyzer = riskAnalyzer;
        _connectionMonitor = connectionMonitor;
        _connectionDetector = connectionDetector;
        _sessionMonitor = sessionMonitor;
        _processMonitor = processMonitor;
        _registryMonitor = registryMonitor;
        _startupMonitor = startupMonitor;
        _hardwareMonitor = hardwareMonitor;
        _interval = TimeSpan.FromSeconds(Math.Clamp(
            configuration.GetValue("SecurityMonitoring:IntervalSeconds", 60),
            10,
            3600));
        _lowDiskThresholdPercent = Math.Clamp(
            configuration.GetValue("SecurityMonitoring:LowDiskThresholdPercent", 10d),
            1d,
            50d);
        _failedLoginThreshold = Math.Clamp(
            configuration.GetValue("SecurityMonitoring:FailedLoginThreshold", 5),
            1,
            100);
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

            await CheckSecuritySourcesAsync(stoppingToken);
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

    private async Task CheckSecuritySourcesAsync(CancellationToken cancellationToken)
    {
        try
        {
            var connections = _connectionMonitor.GetConnections();
            foreach (var alert in _connectionDetector.Analyze(connections))
                CreateAlertIncident("Connexion réseau suspecte", alert, "Réseau", 70, "network:" + alert);
        }
        catch (Exception ex) { _logger.LogDebug(ex, "Analyse réseau indisponible."); }

        try
        {
            int failedLogins = _sessionMonitor.FailedLogins(1);
            if (failedLogins >= _failedLoginThreshold)
                CreateAlertIncident("Tentatives de connexion échouées", $"{failedLogins} échecs observés durant la dernière heure.", "Identité", 70, "failed-logins");
        }
        catch (Exception ex) { _logger.LogDebug(ex, "Analyse des sessions indisponible."); }

        try
        {
            var currentRegistry = _registryMonitor.CaptureSnapshot();
            if (_registryBaseline == null) _registryBaseline = currentRegistry;
            else
            {
                foreach (var change in _registryMonitor.DetectChanges(_registryBaseline, currentRegistry))
                    CreateAlertIncident("Modification du registre", $"{change.ChangeType} : {change.Item.Hive}\\{change.Item.KeyPath}\\{change.Item.Name}", "Persistance Windows", 70, "registry:" + change.ChangeType + change.Item.Hive + change.Item.KeyPath + change.Item.Name + change.Item.Value);
                _registryBaseline = currentRegistry;
            }
        }
        catch (Exception ex) { _logger.LogDebug(ex, "Surveillance du registre indisponible."); }

        try
        {
            foreach (var item in _startupMonitor.GetItems().Where(StartupMonitor.IsSuspicious))
                CreateAlertIncident("Programme de démarrage suspect", $"{item.Name} : {item.Command}", "Persistance Windows", 70, "startup:" + item.Source + item.Name + item.Command);
        }
        catch (Exception ex) { _logger.LogDebug(ex, "Surveillance du démarrage indisponible."); }

        try
        {
            var hardware = _hardwareMonitor.GetSecuritySnapshot();
            if (_hardwareBaseline != null &&
                (hardware.SecureBoot != _hardwareBaseline.SecureBoot || hardware.Tpm != _hardwareBaseline.Tpm || hardware.BitLocker != _hardwareBaseline.BitLocker))
                CreateAlertIncident("État de sécurité matériel modifié", "Secure Boot, TPM ou BitLocker a changé depuis le démarrage du service.", "Sécurité matérielle", 70, "hardware-security");
            _hardwareBaseline = hardware;
        }
        catch (Exception ex) { _logger.LogDebug(ex, "Surveillance matérielle indisponible."); }

        try
        {
            var processes = await _processMonitor.GetProcessesWithCpuAsync(250);
            foreach (var process in processes.Take(5).Where(p => p.CpuPercent >= 90))
                CreateAlertIncident("Processus fortement consommateur", $"{process.Name} ({process.Pid}) utilise environ {process.CpuPercent:F1} % du CPU.", "Processus Windows", 45, "process:" + process.Pid);
        }
        catch (Exception ex) { _logger.LogDebug(ex, "Surveillance des processus indisponible."); }

        cancellationToken.ThrowIfCancellationRequested();
    }

    private void CreateAlertIncident(string title, string description, string type, int score, string key)
    {
        if (!_createdAlertKeys.Add(key)) return;
        var risk = _riskAnalyzer.Analyze(score);
        var incident = _incidentManager.CreateIncident(title, description, type, risk.Level);
        _logger.LogWarning("Incident {IncidentId} créé : {Title} ({Severity}).", incident.Id, incident.Title, incident.Severity);
    }
}
