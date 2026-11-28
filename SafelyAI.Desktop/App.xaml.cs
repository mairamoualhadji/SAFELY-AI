using System.Windows;
using System.IO;
using SafelyAI.Desktop.Services;
using SafelyAI.Desktop.Views;

namespace SafelyAI.Desktop;

public partial class App : Application
{
    protected override async void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        if (e.Args.Any(argument => StringComparer.OrdinalIgnoreCase.Equals(argument, BackgroundProtectionRunner.StartupArgument)))
        {
            ShutdownMode = ShutdownMode.OnExplicitShutdown;
            try { await new BackgroundProtectionRunner().RunAsync(); }
            catch (Exception exception)
            {
                try
                {
                    var logDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "SafelyAI", "Logs");
                    Directory.CreateDirectory(logDirectory);
                    File.AppendAllText(Path.Combine(logDirectory, "background-protection.log"), $"{DateTimeOffset.Now:O} [CRITICAL] Agent impossible à démarrer : {exception.Message}{Environment.NewLine}");
                }
                catch { }
            }
            Shutdown();
            return;
        }

        var mainWindow = new MainWindow();
        MainWindow = mainWindow;
        mainWindow.Show();
    }
}
