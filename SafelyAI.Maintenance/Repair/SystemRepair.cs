
using System;
using System.Diagnostics;
using System.Security.Principal;
using System.Threading.Tasks;

namespace SafelyAI.Maintenance.Repair
{
    public class SystemRepair
    {
        public bool IsAdministrator()
        {
            if (!OperatingSystem.IsWindows())
                return false;

            using WindowsIdentity identity = WindowsIdentity.GetCurrent();

            WindowsPrincipal principal = new WindowsPrincipal(identity);

            return principal.IsInRole(
                WindowsBuiltInRole.Administrator
            );
        }

        public async Task<RepairResult> RunSfcAsync(
            bool confirmed = false)
        {
            if (!confirmed)
            {
                return ConfirmationRequired("sfc.exe /scannow");
            }

            return await RunCommandAsync(
                "sfc.exe",
                "/scannow"
            );
        }

        public async Task<RepairResult> RunDismAsync(
            bool confirmed = false)
        {
            if (!confirmed)
            {
                return ConfirmationRequired(
                    "DISM.exe /Online /Cleanup-Image /RestoreHealth");
            }

            return await RunCommandAsync(
                "DISM.exe",
                "/Online /Cleanup-Image /RestoreHealth"
            );
        }

        private static RepairResult ConfirmationRequired(string command)
        {
            return new RepairResult
            {
                Command = command,
                Message = "Opération annulée : confirmation explicite requise."
            };
        }

        private async Task<RepairResult> RunCommandAsync(
            string fileName,
            string arguments)
        {
            var result = new RepairResult
            {
                Command = fileName + " " + arguments
            };

            if (!OperatingSystem.IsWindows())
            {
                result.Message = "Cette opération nécessite Windows.";
                return result;
            }

            if (!IsAdministrator())
            {
                result.Message =
                    "Les droits administrateur sont nécessaires.";

                return result;
            }

            try
            {
                using Process process = new Process();

                process.StartInfo = new ProcessStartInfo
                {
                    FileName = fileName,
                    Arguments = arguments,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                };

                process.Start();

                Task<string> outputTask =
                    process.StandardOutput.ReadToEndAsync();

                Task<string> errorTask =
                    process.StandardError.ReadToEndAsync();

                await process.WaitForExitAsync();

                result.ExitCode = process.ExitCode;
                result.Output = await outputTask;
                result.Error = await errorTask;

                result.Success = process.ExitCode == 0;

                result.Message = result.Success
                    ? "Opération terminée avec succès."
                    : "L'opération s'est terminée avec un code d'erreur.";
            }
            catch (Exception ex)
            {
                result.Message = "Erreur : " + ex.Message;
            }

            return result;
        }
    }

    public class RepairResult
    {
        public string Command { get; set; } = "";
        public bool Success { get; set; }
        public int ExitCode { get; set; }
        public string Message { get; set; } = "";
        public string Output { get; set; } = "";
        public string Error { get; set; } = "";
    }
}
