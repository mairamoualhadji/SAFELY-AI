namespace SafelyAI.Antivirus.FileScanner;

public enum FileThreatSeverity { Low, Medium, High }
public sealed record FileThreat(string Name, string Path, string Sha256, FileThreatSeverity Severity, string Details, DateTime DetectedAt);
public sealed record FileScanProgress(int Percent, string Message);
public sealed record FileScanResult(int FilesScanned, int ThreatsFound, int SkippedFiles, long BytesScanned, DateTime FinishedAt, IReadOnlyList<FileThreat> Threats);
