using System.Diagnostics;
using System.ComponentModel;
using System.IO;
using System.Security;
using System.Text.Json;
using SafelyAI.Desktop.Models;

namespace SafelyAI.Desktop.Services;

public sealed record DefenderProtectionStatus(
    bool Available,
    bool AntivirusEnabled,
    bool RealTimeProtectionEnabled,
    DateTime? SignaturesLastUpdated,
    string EngineVersion,
    string Message)
{
    public static DefenderProtectionStatus Unavailable(string message) =>
        new(false, false, false, null, "", message);
}

public enum DefenderScanOutcome { Completed, AttentionRequired }
public sealed record DefenderScanResult(DefenderScanOutcome Outcome, string Message, int ExitCode);
public sealed record DefenderThreatDetection(string DetectionId, string ThreatId, string[] Resources,
    DateTime? InitialDetectionTime, DateTime? LastThreatStatusChangeTime, int ThreatStatusId,
    bool ActionSuccess, int CleaningActionId, uint AdditionalActionsBitMask)
{
    public string StatusLabel => ThreatStatusId switch
    {
        0 => "Inconnu",
        1 => "Détecté",
        2 => "Nettoyé",
        3 => "En quarantaine",
        4 => "Supprimé",
        5 => "Autorisé",
        6 => "Bloqué",
        102 => "Échec de quarantaine",
        103 => "Échec de suppression",
        104 => "Échec d’autorisation",
        105 => "Abandonné",
        107 => "Échec du blocage",
        _ => $"État Defender {ThreatStatusId}"
    };
    public string ResourcesLabel => Resources.Length == 0 ? "Ressource non fournie" : string.Join("; ", Resources);
    public string ActionLabel => ActionSuccess ? "Réussie" : "Non confirmée";
}
public sealed record DefenderThreatHistoryResult(bool Available, string Message,
    IReadOnlyList<DefenderThreatDetection> Detections, DateTime RetrievedAt);

/// <summary>
/// Read-only status and on-demand scan integration with the Microsoft Defender engine already
/// installed on Windows. SAFELY AI does not change Defender settings or disable another antivirus.
/// </summary>
public sealed class MicrosoftDefenderService
{
    private const int StatusTimeoutMilliseconds = 10_000;
    private const int ThreatHistoryTimeoutMilliseconds = 20_000;
    private const int BackgroundFileScanTimeoutMilliseconds = 300_000;

    public async Task<DefenderProtectionStatus> GetProtectionStatusAsync(CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return DefenderProtectionStatus.Unavailable("Microsoft Defender est disponible uniquement sur Windows.");

        var powerShell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(powerShell))
            return DefenderProtectionStatus.Unavailable("Windows PowerShell est introuvable sur cet appareil.");

        const string script = "try { $s = Get-MpComputerStatus -ErrorAction Stop; [pscustomobject]@{ AntivirusEnabled = [bool]$s.AntivirusEnabled; RealTimeProtectionEnabled = [bool]$s.RealTimeProtectionEnabled; SignaturesLastUpdated = if ($s.AntivirusSignatureLastUpdated) { $s.AntivirusSignatureLastUpdated.ToString('o') } else { $null }; EngineVersion = [string]$s.AMEngineVersion } | ConvertTo-Json -Compress } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }";
        var startInfo = new ProcessStartInfo(powerShell)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows)
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("RemoteSigned");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(script);

        try
        {
            using var process = new Process { StartInfo = startInfo };
            if (!process.Start()) return DefenderProtectionStatus.Unavailable("Impossible d’interroger Microsoft Defender.");
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(StatusTimeoutMilliseconds);
            var outputTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var errorTask = process.StandardError.ReadToEndAsync(timeout.Token);
            try { await process.WaitForExitAsync(timeout.Token); }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                if (cancellationToken.IsCancellationRequested) throw;
                return DefenderProtectionStatus.Unavailable("La lecture de l’état de Microsoft Defender a expiré.");
            }

            var output = await outputTask;
            _ = await errorTask;
            if (process.ExitCode != 0)
                return DefenderProtectionStatus.Unavailable("Windows n’a pas pu fournir l’état de Microsoft Defender par son interface locale. Ouvrez Sécurité Windows pour vérifier la protection.");

            var data = JsonSerializer.Deserialize<DefenderStatusPayload>(output,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            if (data is null) return DefenderProtectionStatus.Unavailable("Microsoft Defender a renvoyé un état illisible.");

            var summary = !data.AntivirusEnabled
                ? "L’antivirus Microsoft Defender n’est pas actif. Vérifiez le fournisseur de sécurité dans Sécurité Windows."
                : !data.RealTimeProtectionEnabled
                    ? "L’antivirus est actif, mais sa protection en temps réel est désactivée."
                    : "Microsoft Defender protège cet appareil en temps réel.";
            return new(true, data.AntivirusEnabled, data.RealTimeProtectionEnabled,
                DateTime.TryParse(data.SignaturesLastUpdated, out var updated) ? updated : null,
                data.EngineVersion ?? "Inconnue", summary);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception ex) when (ex is Win32Exception or IOException or UnauthorizedAccessException or SecurityException or JsonException)
        {
            return DefenderProtectionStatus.Unavailable("L’état de Microsoft Defender n’a pas pu être lu. Ouvrez Sécurité Windows pour vérifier la protection.");
        }
    }

    /// <summary>Reads recent Microsoft Defender detections without changing protection settings or remediation state.</summary>
    public async Task<DefenderThreatHistoryResult> GetThreatHistoryAsync(CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return new(false, "L’historique Microsoft Defender est disponible uniquement sur Windows.", [], DateTime.Now);

        var powerShell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(powerShell))
            return new(false, "Windows PowerShell est introuvable.", [], DateTime.Now);

        const string script = "try { $items = @(Get-MpThreatDetection -ErrorAction Stop | Sort-Object -Property InitialDetectionTime -Descending | Select-Object -First 200); $rows = @($items | ForEach-Object { $d = $_; [pscustomobject]@{ DetectionId = [string]$d.DetectionID; ThreatId = [string]$d.ThreatID; Resources = @($d.Resources | ForEach-Object { [string]$_ }); InitialDetectionTime = if ($d.InitialDetectionTime) { ([datetime]$d.InitialDetectionTime).ToString('o') } else { $null }; LastThreatStatusChangeTime = if ($d.LastThreatStatusChangeTime) { ([datetime]$d.LastThreatStatusChangeTime).ToString('o') } else { $null }; ThreatStatusId = [int]$d.ThreatStatusID; ActionSuccess = [bool]$d.ActionSuccess; CleaningActionId = [int]$d.CleaningActionID; AdditionalActionsBitMask = [uint32]$d.AdditionalActionsBitMask } }); ConvertTo-Json -InputObject $rows -Depth 5 -Compress } catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }";
        var startInfo = new ProcessStartInfo(powerShell)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows)
        };
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("RemoteSigned");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(script);

        try
        {
            using var process = new Process { StartInfo = startInfo };
            if (!process.Start()) return new(false, "Impossible de lire l’historique Microsoft Defender.", [], DateTime.Now);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(ThreatHistoryTimeoutMilliseconds);
            var outputTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var errorTask = process.StandardError.ReadToEndAsync(timeout.Token);
            try { await process.WaitForExitAsync(timeout.Token); }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                if (cancellationToken.IsCancellationRequested) throw;
                return new(false, "La lecture de l’historique Defender a expiré.", [], DateTime.Now);
            }

            var output = await outputTask;
            _ = await errorTask;
            if (process.ExitCode != 0 || output.Length > 2_000_000)
                return new(false, "Windows n’a pas pu fournir l’historique Microsoft Defender. Consultez Sécurité Windows.", [], DateTime.Now);

            var payload = JsonSerializer.Deserialize<List<DefenderThreatDetection>>(output,
                new JsonSerializerOptions { PropertyNameCaseInsensitive = true, MaxDepth = 8 }) ?? [];
            return new(true, $"{payload.Count} détection(s) lue(s) depuis Microsoft Defender.", payload, DateTime.Now);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception) when (exception is Win32Exception or IOException or UnauthorizedAccessException or SecurityException or JsonException)
        {
            return new(false, "L’historique Microsoft Defender n’a pas pu être lu. Consultez Sécurité Windows.", [], DateTime.Now);
        }
    }

    /// <summary>
    /// Requests a one-file Microsoft Defender custom scan from the current user session. This does
    /// not request UAC elevation; if this Windows configuration requires elevation, the caller can
    /// log the failure and continue with its own local scan.
    /// </summary>
    public async Task<DefenderScanResult> RunBackgroundFileScanAsync(string path, CancellationToken cancellationToken = default)
    {
        if (!OperatingSystem.IsWindows())
            return new(DefenderScanOutcome.AttentionRequired, "Le scan Defender automatique nécessite Windows.", -1);
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return new(DefenderScanOutcome.AttentionRequired, "Le téléchargement n’est plus disponible pour le scan Defender.", -1);

        var powerShell = Path.Combine(Environment.SystemDirectory, "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(powerShell))
            return new(DefenderScanOutcome.AttentionRequired, "Windows PowerShell est introuvable; l’analyse locale SAFELY AI peut continuer.", -1);

        const string scanPathVariable = "SAFELY_AI_DEFENDER_SCAN_PATH";
        const string script = "$scanPath = [Environment]::GetEnvironmentVariable('SAFELY_AI_DEFENDER_SCAN_PATH'); if ([string]::IsNullOrWhiteSpace($scanPath) -or -not (Test-Path -LiteralPath $scanPath -PathType Leaf)) { throw 'Le fichier à analyser est introuvable.' }; Start-MpScan -ScanType CustomScan -ScanPath $scanPath -ErrorAction Stop; Write-Output 'SAFELY_DEFENDER_SCAN_COMPLETED'";
        var startInfo = new ProcessStartInfo(powerShell)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            WorkingDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Windows)
        };
        startInfo.Environment[scanPathVariable] = Path.GetFullPath(path);
        startInfo.ArgumentList.Add("-NoLogo");
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-ExecutionPolicy");
        startInfo.ArgumentList.Add("RemoteSigned");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(script);

        try
        {
            using var process = new Process { StartInfo = startInfo };
            if (!process.Start()) return new(DefenderScanOutcome.AttentionRequired, "Impossible de démarrer le scan Defender sans élévation.", -1);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(BackgroundFileScanTimeoutMilliseconds);
            var outputTask = process.StandardOutput.ReadToEndAsync(timeout.Token);
            var errorTask = process.StandardError.ReadToEndAsync(timeout.Token);
            try { await process.WaitForExitAsync(timeout.Token); }
            catch (OperationCanceledException)
            {
                try { process.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
                if (cancellationToken.IsCancellationRequested) throw;
                return new(DefenderScanOutcome.AttentionRequired, "Le scan Defender a dépassé 5 minutes; l’analyse locale SAFELY AI continue.", -1);
            }

            var output = await outputTask;
            var error = await errorTask;
            if (process.ExitCode != 0 || !output.Contains("SAFELY_DEFENDER_SCAN_COMPLETED", StringComparison.Ordinal))
            {
                var detail = error.Length <= 400 ? error.Trim() : error[..400].Trim();
                return new(DefenderScanOutcome.AttentionRequired,
                    string.IsNullOrWhiteSpace(detail)
                        ? "Windows Defender n’a pas accepté le scan sans élévation; l’analyse locale SAFELY AI continue."
                        : $"Windows Defender n’a pas accepté le scan sans élévation : {detail}", process.ExitCode);
            }

            return new(DefenderScanOutcome.Completed,
                "La demande de scan personnalisé Defender s’est terminée. Consultez Sécurité Windows pour le résultat et toute action de correction.", process.ExitCode);
        }
        catch (OperationCanceledException) { throw; }
        catch (Exception exception) when (exception is Win32Exception or IOException or UnauthorizedAccessException or SecurityException)
        {
            return new(DefenderScanOutcome.AttentionRequired,
                $"Scan Defender impossible sans élévation : {exception.Message}", -1);
        }
    }

    public async Task<DefenderScanResult> RunScanAsync(ScanType scanType, string? path = null)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("L’analyse Microsoft Defender nécessite Windows.");
        if (scanType is ScanType.Usb or ScanType.Custom)
        {
            if (string.IsNullOrWhiteSpace(path) || !(File.Exists(path) || Directory.Exists(path)))
                throw new DirectoryNotFoundException("Sélectionnez un fichier ou un dossier accessible avant de lancer l’analyse Defender.");
            path = Path.GetFullPath(path);
        }

        var executable = FindMpCmdRun();
        if (executable is null)
            throw new FileNotFoundException("Microsoft Defender MpCmdRun.exe est introuvable. Vérifiez l’installation de Microsoft Defender dans Sécurité Windows.");

        // Microsoft documents MpCmdRun on-demand scans as requiring elevation. Windows will show
        // its normal UAC prompt; declining it leaves the machine and Defender configuration intact.
        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = Path.GetDirectoryName(executable)!
        };
        startInfo.ArgumentList.Add("-Scan");
        startInfo.ArgumentList.Add("-ScanType");
        startInfo.ArgumentList.Add(scanType switch
        {
            ScanType.Quick => "1",
            ScanType.Full => "2",
            ScanType.Custom or ScanType.Usb => "3",
            _ => throw new ArgumentOutOfRangeException(nameof(scanType))
        });
        if (scanType is ScanType.Custom or ScanType.Usb)
        {
            startInfo.ArgumentList.Add("-File");
            startInfo.ArgumentList.Add(path!);
        }

        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Windows n’a pas pu démarrer l’analyse Defender.");
        await process.WaitForExitAsync();
        return process.ExitCode switch
        {
            0 => new(DefenderScanOutcome.Completed,
                "Analyse Microsoft Defender terminée. Code 0 : aucune menace détectée ou menace corrigée par Defender. Consultez Sécurité Windows pour le détail.", 0),
            2 => new(DefenderScanOutcome.AttentionRequired,
                "Defender signale une menace non corrigée, une action utilisateur requise ou une erreur d’analyse. Ouvrez Sécurité Windows et consultez l’historique de protection.", 2),
            var code => new(DefenderScanOutcome.AttentionRequired,
                $"L’analyse Defender s’est terminée avec le code {code}. Consultez Sécurité Windows pour en connaître la cause.", code)
        };
    }

    public async Task<DefenderScanResult> UpdateSignaturesAsync()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("La mise à jour Microsoft Defender nécessite Windows.");
        var executable = FindMpCmdRun();
        if (executable is null) throw new FileNotFoundException("Microsoft Defender MpCmdRun.exe est introuvable.");
        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
            WorkingDirectory = Path.GetDirectoryName(executable)!
        };
        startInfo.ArgumentList.Add("-SignatureUpdate");
        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Windows n’a pas pu démarrer la mise à jour Defender.");
        await process.WaitForExitAsync();
        return process.ExitCode == 0
            ? new(DefenderScanOutcome.Completed, "La commande de mise à jour Defender s’est terminée. Vérifiez l’heure de mise à jour dans Sécurité Windows.", 0)
            : new(DefenderScanOutcome.AttentionRequired, $"La mise à jour Defender s’est terminée avec le code {process.ExitCode}. Vérifiez Sécurité Windows et Windows Update.", process.ExitCode);
    }

    public static void OpenWindowsSecurity()
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Sécurité Windows est disponible uniquement sur Windows.");
        Process.Start(new ProcessStartInfo("ms-settings:windowsdefender") { UseShellExecute = true });
    }

    private static string? FindMpCmdRun()
    {
        var platformRoot = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Microsoft", "Windows Defender", "Platform");
        try
        {
            var latest = Directory.Exists(platformRoot)
                ? Directory.GetDirectories(platformRoot)
                    .Select(path => (Path: path, Name: Path.GetFileName(path)))
                    .Where(entry => Version.TryParse(entry.Name, out _))
                    .OrderByDescending(entry => Version.Parse(entry.Name))
                    .Select(entry => Path.Combine(entry.Path, "MpCmdRun.exe"))
                    .FirstOrDefault(File.Exists)
                : null;
            if (latest is not null) return latest;
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }

        var fallback = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Windows Defender", "MpCmdRun.exe");
        return File.Exists(fallback) ? fallback : null;
    }

    private sealed record DefenderStatusPayload(bool AntivirusEnabled, bool RealTimeProtectionEnabled,
        string? SignaturesLastUpdated, string? EngineVersion);
}
