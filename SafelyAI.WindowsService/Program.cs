using SafelyAI.Core.Interfaces;
using SafelyAI.Maintenance.Diagnostics;
using SafelyAI.Response.IncidentManager;
using SafelyAI.Response.RiskEngine;
using SafelyAI.WindowsService.Workers;

var builder = Host.CreateApplicationBuilder(args);

builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "SAFELY AI";
});

builder.Services.AddSingleton<SystemDiagnostics>();
builder.Services.AddSingleton<IIncidentManager, IncidentManager>();
builder.Services.AddSingleton<RiskAnalyzer>();
builder.Services.AddHostedService<SecurityMonitoringWorker>();

var host = builder.Build();

host.Run();
