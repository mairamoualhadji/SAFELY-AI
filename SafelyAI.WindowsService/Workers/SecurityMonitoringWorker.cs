
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace SafelyAI.WindowsService.Workers
{
    public class SecurityMonitoringWorker : BackgroundService
    {
        private readonly ILogger<SecurityMonitoringWorker> _logger;

        public SecurityMonitoringWorker(
            ILogger<SecurityMonitoringWorker> logger)
        {
            _logger = logger;
        }

        protected override async Task ExecuteAsync(
            CancellationToken stoppingToken)
        {
            _logger.LogInformation(
                "SAFELY AI : surveillance demarree.");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    Process[] processes = Process.GetProcesses();

                    _logger.LogInformation(
                        "SAFELY AI : {Count} processus actifs detectes.",
                        processes.Length);

                    foreach (Process process in processes)
                    {
                        try
                        {
                            _logger.LogInformation(
                                "Processus : {Name} | PID : {Id}",
                                process.ProcessName,
                                process.Id);
                        }
                        catch (Exception ex)
                        {
                            _logger.LogWarning(
                                "Impossible de lire un processus : {Message}",
                                ex.Message);
                        }
                        finally
                        {
                            process.Dispose();
                        }
                    }

                    await Task.Delay(
                        TimeSpan.FromSeconds(30),
                        stoppingToken);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch (Exception ex)
                {
                    _logger.LogError(
                        ex,
                        "Erreur pendant la surveillance SAFELY AI.");
                }
            }

            _logger.LogInformation(
                "SAFELY AI : surveillance arretee.");
        }
    }
}
