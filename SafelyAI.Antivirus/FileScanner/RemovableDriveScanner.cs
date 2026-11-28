namespace SafelyAI.Antivirus.FileScanner;

public sealed class RemovableDriveScanner(FileScannerService scanner)
{
    public IReadOnlyList<string> GetReadyDrives()
    {
        var drives = new List<string>();
        foreach (var drive in DriveInfo.GetDrives())
        {
            try { if (drive.DriveType == DriveType.Removable && drive.IsReady) drives.Add(drive.RootDirectory.FullName); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        return drives;
    }

    public Task<FileScanResult> ScanAsync(string driveRoot, IProgress<FileScanProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        var drive = DriveInfo.GetDrives().FirstOrDefault(d => d.DriveType == DriveType.Removable && d.IsReady && StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(d.RootDirectory.FullName), Path.GetFullPath(driveRoot)));
        if (drive is null) throw new InvalidOperationException("Sélectionnez une clé USB amovible actuellement connectée.");
        return scanner.ScanAsync([drive.RootDirectory.FullName], progress, cancellationToken);
    }
}
