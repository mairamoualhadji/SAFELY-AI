using System.Diagnostics;
using System.Security.Principal;
using System.Text;
namespace SafelyAI.Common;

// Outil partagé : lance une commande ou un script PowerShell et renvoie le texte affiché.
public static class Shell
{
    public static string Run(string file, string args, int timeoutMs = 30000)
    {
        try
        {
            var psi = new ProcessStartInfo(file, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };
            using var p = Process.Start(psi)!;
            var output = p.StandardOutput.ReadToEnd();
            p.WaitForExit(timeoutMs);
            return output.Trim();
        }
        catch (Exception ex) { return "ERREUR: " + ex.Message; }
    }

    public static string PowerShell(string script)
    {
        var encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        return Run("powershell.exe", "-NoProfile -NonInteractive -EncodedCommand " + encoded);
    }

    public static List<string> Lines(string text) =>
        text.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).ToList();

    public static bool IsAdmin()
    {
        if (!OperatingSystem.IsWindows()) return false;
        using var id = WindowsIdentity.GetCurrent();
        return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
    }
}
