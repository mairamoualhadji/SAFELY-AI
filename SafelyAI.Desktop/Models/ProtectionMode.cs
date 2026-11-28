namespace SafelyAI.Desktop.Models;
public enum ScanType { Quick, Full, Custom, Usb }
public enum ProtectionMode { Economy, Balanced, Maximum }
public record ScanResult(ScanType Type, int FilesScanned, int ThreatsFound, DateTime FinishedAt);
