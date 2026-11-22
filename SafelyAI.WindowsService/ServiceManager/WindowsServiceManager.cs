
using System;
using System.ServiceProcess;

namespace SafelyAI.WindowsService.ServiceManager
{
    public class WindowsServiceManager
    {
        public ServiceManagerResult GetServiceStatus(string serviceName)
        {
            var result = new ServiceManagerResult();

            if (!OperatingSystem.IsWindows())
            {
                result.Message = "Cette fonctionnalité nécessite Windows.";
                return result;
            }

            if (string.IsNullOrWhiteSpace(serviceName))
            {
                result.Message = "Le nom du service est obligatoire.";
                return result;
            }

            try
            {
                using var service = new ServiceController(serviceName);

                result.Success = true;
                result.Status = service.Status.ToString();
                result.Message = "État du service récupéré.";
            }
            catch (InvalidOperationException)
            {
                result.Message = "Service Windows introuvable.";
            }
            catch (System.ComponentModel.Win32Exception ex)
            {
                result.Message = "Accès refusé ou erreur Windows : " + ex.Message;
            }
            catch (Exception ex)
            {
                result.Message = "Erreur : " + ex.Message;
            }

            return result;
        }

        public ServiceManagerResult StartService(string serviceName)
        {
            return ExecuteServiceAction(serviceName, true);
        }

        public ServiceManagerResult StopService(string serviceName)
        {
            return ExecuteServiceAction(serviceName, false);
        }

        private ServiceManagerResult ExecuteServiceAction(
            string serviceName,
            bool start)
        {
            var result = new ServiceManagerResult();

            if (!OperatingSystem.IsWindows())
            {
                result.Message = "Cette fonctionnalité nécessite Windows.";
                return result;
            }

            if (string.IsNullOrWhiteSpace(serviceName))
            {
                result.Message = "Le nom du service est obligatoire.";
                return result;
            }

            try
            {
                using var service = new ServiceController(serviceName);

                if (start)
                {
                    if (service.Status == ServiceControllerStatus.Running)
                    {
                        result.Success = true;
                        result.Status = "Running";
                        result.Message = "Le service fonctionne déjà.";
                        return result;
                    }

                    service.Start();
                    service.WaitForStatus(
                        ServiceControllerStatus.Running,
                        TimeSpan.FromSeconds(15));
                }
                else
                {
                    if (service.Status == ServiceControllerStatus.Stopped)
                    {
                        result.Success = true;
                        result.Status = "Stopped";
                        result.Message = "Le service est déjà arrêté.";
                        return result;
                    }

                    if (!service.CanStop)
                    {
                        result.Message = "Ce service ne peut pas être arrêté.";
                        return result;
                    }

                    service.Stop();
                    service.WaitForStatus(
                        ServiceControllerStatus.Stopped,
                        TimeSpan.FromSeconds(15));
                }

                result.Success = true;
                result.Status = service.Status.ToString();
                result.Message = start
                    ? "Service démarré avec succès."
                    : "Service arrêté avec succès.";
            }
            catch (System.ComponentModel.Win32Exception ex)
            {
                result.Message = "Erreur Windows ou autorisation insuffisante : " + ex.Message;
            }
            catch (InvalidOperationException ex)
            {
                result.Message = "Opération impossible : " + ex.Message;
            }
            catch (System.TimeoutException)
            {
                result.Message = "Délai dépassé pendant l'opération.";
            }
            catch (Exception ex)
            {
                result.Message = "Erreur : " + ex.Message;
            }

            return result;
        }
    }

    public class ServiceManagerResult
    {
        public bool Success { get; set; }

        public string Status { get; set; } = "";

        public string Message { get; set; } = "";
    }
}
