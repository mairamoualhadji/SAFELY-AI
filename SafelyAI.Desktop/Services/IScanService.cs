using System.IO;
using SafelyAI.Desktop.Models;
using SafelyAI.Antivirus.FileScanner;
using SafelyAI.Antivirus.SignatureEngine;
namespace SafelyAI.Desktop.Services;
public interface IScanService
{
    Task<FileScanResult> RunAsync(ScanType type, string? path = null, IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default);
    void RegisterSignature(string sha256, string name);
    DateTime? MalwareBazaarUpdatedAtUtc { get; }
    Task<SignatureFeedUpdateResult> UpdateSignaturesAsync(string authKey, CancellationToken cancellationToken = default);
}

public sealed record ScanProgress(int Percent, string Message);

public sealed class AntivirusScanService : IScanService
{
    private readonly SignatureDatabase _signatures = new();
    private readonly FileScannerService _scanner;
    public AntivirusScanService() => _scanner = new(_signatures);
    public DateTime? MalwareBazaarUpdatedAtUtc => _signatures.MalwareBazaarUpdatedAtUtc;
    public void RegisterSignature(string sha256, string name) => _signatures.AddSha256(sha256, name);
    public async Task<SignatureFeedUpdateResult> UpdateSignaturesAsync(string authKey, CancellationToken cancellationToken = default)
    {
        using var feed = new MalwareBazaarSignatureFeed(_signatures);
        return await feed.UpdateAsync(authKey, cancellationToken);
    }
    public Task<FileScanResult> RunAsync(ScanType type, string? path = null, IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        IEnumerable<string> roots = type switch
        {
            ScanType.Quick => ScanScopes.Quick(),
            ScanType.Full => ScanScopes.Full(),
            ScanType.Usb => new RemovableDriveScanner(_scanner).GetReadyDrives().Contains(path, StringComparer.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(path) ? [path] : throw new InvalidOperationException("La clé USB sélectionnée n’est plus connectée."),
            ScanType.Custom when !string.IsNullOrWhiteSpace(path) && (File.Exists(path) || Directory.Exists(path)) => [path],
            _ => throw new DirectoryNotFoundException("Sélectionnez un fichier ou un dossier valide pour l’analyse personnalisée.")
        };
        var reporter = progress is null ? null : new Progress<FileScanProgress>(p => progress.Report(new(p.Percent, p.Message)));
        // Directory enumeration and file hashing stay off the WPF dispatcher.
        return Task.Run(() => _scanner.ScanAsync(roots, reporter, cancellationToken), cancellationToken);
    }
}
