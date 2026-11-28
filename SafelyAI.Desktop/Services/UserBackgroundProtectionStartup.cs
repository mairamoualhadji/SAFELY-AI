using System.Diagnostics;
using System.IO;
using System.Security;
using Microsoft.Win32;

namespace SafelyAI.Desktop.Services;

/// <summary>Opt-in current-user logon startup for SAFELY AI's user-mode download guard.</summary>
public static class UserBackgroundProtectionStartup
{
    private const string RunKeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "SAFELY AI Background Protection";

    public static bool IsEnabled()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: false);
        return key?.GetValue(ValueName) is string value && !string.IsNullOrWhiteSpace(value);
    }

    public static void EnableAndStart()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Le démarrage automatique nécessite Windows.");
        var processPath = Environment.ProcessPath;
        if (string.IsNullOrWhiteSpace(processPath) || !File.Exists(processPath))
            throw new InvalidOperationException("Impossible de déterminer le chemin de l’application SAFELY AI.");
        var executable = Path.GetFullPath(processPath);
        var launchArguments = new List<string>();
        if (Path.GetFileNameWithoutExtension(executable).Equals("dotnet", StringComparison.OrdinalIgnoreCase))
        {
            var entryAssembly = Environment.GetCommandLineArgs().FirstOrDefault(argument => argument.EndsWith(".dll", StringComparison.OrdinalIgnoreCase));
            if (entryAssembly is null || !File.Exists(entryAssembly))
                throw new InvalidOperationException("L’assembly SAFELY AI n’a pas pu être localisé pour le démarrage en arrière-plan.");
            launchArguments.Add(Path.GetFullPath(entryAssembly));
        }
        launchArguments.Add(BackgroundProtectionRunner.StartupArgument);
        var command = $"\"{executable}\" {string.Join(" ", launchArguments.Select(QuoteArgument))}";

        using (var key = Registry.CurrentUser.CreateSubKey(RunKeyPath, writable: true))
        {
            if (key is null) throw new SecurityException("Impossible d’ouvrir le registre de démarrage de l’utilisateur.");
            key.SetValue(ValueName, command, RegistryValueKind.String);
        }

        try
        {
            var startInfo = new ProcessStartInfo(executable)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden
            };
            foreach (var argument in launchArguments) startInfo.ArgumentList.Add(argument);
            using var guardProcess = Process.Start(startInfo);
        }
        catch
        {
            // Do not leave an automatic-start entry behind when the immediate launch fails.
            Disable();
            throw;
        }
    }

    private static string QuoteArgument(string argument) => $"\"{argument.Replace("\"", "\\\"")}\"";

    public static void Disable()
    {
        if (!OperatingSystem.IsWindows()) return;
        using (var key = Registry.CurrentUser.OpenSubKey(RunKeyPath, writable: true))
            key?.DeleteValue(ValueName, throwOnMissingValue: false);

        try
        {
            using var stopEvent = EventWaitHandle.OpenExisting(BackgroundProtectionRunner.StopEventName);
            stopEvent.Set();
        }
        catch (WaitHandleCannotBeOpenedException) { }
        catch (UnauthorizedAccessException) { }
    }
}
