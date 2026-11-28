using SafelyAI.Core.Interfaces;
using SafelyAI.Maintenance.Diagnostics;
using SafelyAI.Response.IncidentManager;
using SafelyAI.Response.RiskEngine;
using SafelyAI.WindowsService.Workers;
using SafelyAI.Network.TrafficMonitoring;
using SafelyAI.Network.IntrusionDetection;
using SafelyAI.Identity.SessionMonitoring;
using SafelyAI.SystemMonitor.ProcessMonitor;
using SafelyAI.SystemMonitor.RegistryMonitor;
using SafelyAI.SystemMonitor.StartupMonitor;
using SafelyAI.SystemMonitor.HardwareMonitor;
using SafelyAI.Infrastructure.Database;
using SafelyAI.Infrastructure.Logging;
using SafelyAI.Core.Interfaces;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "SAFELY AI";
});

builder.Services.AddSingleton<SystemDiagnostics>();
string dataDirectory = Path.Combine(
    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
    "SAFELY AI");
Directory.CreateDirectory(dataDirectory);
string databasePath = Path.Combine(dataDirectory, "safelyai.db");
string logPath = Path.Combine(dataDirectory, "safelyai.log");
builder.Services.AddSingleton(new DatabaseManager(databasePath));
builder.Services.AddSingleton<DatabaseIncidentStore>();
builder.Services.AddSingleton<IIncidentStore>(services => services.GetRequiredService<DatabaseIncidentStore>());
builder.Services.AddSingleton<SecurityLogger>(_ => new SecurityLogger(logPath));
builder.Services.AddSingleton<ISecurityLogger>(services =>
    new CompositeSecurityLogger(services.GetRequiredService<SecurityLogger>(), services.GetRequiredService<DatabaseManager>()));
builder.Services.AddSingleton<IIncidentManager, IncidentManager>();
builder.Services.AddSingleton<RiskAnalyzer>();
builder.Services.AddSingleton<ConnectionMonitor>();
builder.Services.AddSingleton<SuspiciousConnectionDetector>();
builder.Services.AddSingleton<SessionMonitor>();
builder.Services.AddSingleton<ProcessMonitor>();
builder.Services.AddSingleton<RegistryMonitor>();
builder.Services.AddSingleton<StartupMonitor>();
builder.Services.AddSingleton<HardwareMonitor>();
builder.Services.AddHostedService<SecurityMonitoringWorker>();

var host = builder.Build();

host.Run();
