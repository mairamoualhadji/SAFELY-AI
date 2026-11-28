
using System;
using System.IO;

namespace SafelyAI.WindowsService.Startup
{
    public class StartupManager
    {
        private readonly string startupFolder;

        public StartupManager()
        {
            startupFolder = Environment.GetFolderPath(
                Environment.SpecialFolder.Startup);
        }

        public StartupResult CheckStartup()
        {
            string shortcutPath = GetShortcutPath();

            return new StartupResult
            {
                Success = true,
                IsEnabled = File.Exists(shortcutPath),
                Message = File.Exists(shortcutPath)
                    ? "Démarrage automatique activé."
                    : "Démarrage automatique désactivé."
            };
        }

        public StartupResult EnableStartup(string applicationPath)
        {
            var result = new StartupResult();

            if (!OperatingSystem.IsWindows())
            {
                result.Message = "Cette fonctionnalité nécessite Windows.";
                return result;
            }

            if (string.IsNullOrWhiteSpace(applicationPath) ||
                !File.Exists(applicationPath))
            {
                result.Message = "Fichier de l'application introuvable.";
                return result;
            }

            try
            {
                string shortcutPath = GetShortcutPath();

                // Création du raccourci Windows via PowerShell.
                string script =
                    "$WshShell = New-Object -ComObject WScript.Shell; " +
                    "$Shortcut = $WshShell.CreateShortcut('" +
                    shortcutPath.Replace("'", "''") + "'); " +
                    "$Shortcut.TargetPath = '" +
                    Path.GetFullPath(applicationPath).Replace("'", "''") +
                    "'; " +
                    "$Shortcut.Save()";

                using var process = new System.Diagnostics.Process();

                process.StartInfo.FileName = "powershell.exe";
                process.StartInfo.Arguments =
                    "-NoProfile -NonInteractive -Command \"" +
                    script + "\"";
                process.StartInfo.UseShellExecute = false;
                process.StartInfo.CreateNoWindow = true;
                process.StartInfo.RedirectStandardError = true;

                process.Start();

                string error = process.StandardError.ReadToEnd();
                process.WaitForExit();

                if (process.ExitCode != 0)
                {
                    result.Message = "Erreur : " + error;
                    return result;
                }

                result.Success = File.Exists(shortcutPath);
                result.IsEnabled = result.Success;
                result.Message = result.Success
                    ? "Démarrage automatique activé."
                    : "Impossible de créer le raccourci.";

            }
            catch (Exception ex)
            {
                result.Message = "Erreur : " + ex.Message;
            }

            return result;
        }

        public StartupResult DisableStartup()
        {
            var result = new StartupResult();

            if (!OperatingSystem.IsWindows())
            {
                result.Message = "Cette fonctionnalité nécessite Windows.";
                return result;
            }

            try
            {
                string shortcutPath = GetShortcutPath();

                if (File.Exists(shortcutPath))
                {
                    File.Delete(shortcutPath);
                }

                result.Success = true;
                result.IsEnabled = false;
                result.Message = "Démarrage automatique désactivé.";
            }
            catch (Exception ex)
            {
                result.Message = "Erreur : " + ex.Message;
            }

            return result;
        }

        private string GetShortcutPath()
        {
            return Path.Combine(
                startupFolder,
                "SAFELY AI.lnk");
        }
    }

    public class StartupResult
    {
        public bool Success { get; set; }

        public bool IsEnabled { get; set; }

        public string Message { get; set; } = "";
    }
}
