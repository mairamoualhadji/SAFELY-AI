using SafelyAI.WindowsService.Workers;

var builder = Host.CreateApplicationBuilder(args);

// Enregistrement du Worker de surveillance SAFELY AI
builder.Services.AddHostedService<SecurityMonitoringWorker>();

var host = builder.Build();

host.Run();
