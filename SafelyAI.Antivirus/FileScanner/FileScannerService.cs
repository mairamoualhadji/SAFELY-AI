using System.Security.Cryptography;
using SafelyAI.Antivirus.HeuristicEngine;
using SafelyAI.Antivirus.SignatureEngine;

namespace SafelyAI.Antivirus.FileScanner;

/// <summary>Read-only local scanner. It never executes, deletes, or modifies scanned files.</summary>
public sealed class FileScannerService(SignatureDatabase? signatures = null, HeuristicAnalyzer? heuristics = null)
{
    private readonly SignatureDatabase _signatures = signatures ?? new();
    private readonly HeuristicAnalyzer _heuristics = heuristics ?? new();
    private const long MaxFileSize = 256L * 1024 * 1024;

    public async Task<FileScanResult> ScanAsync(IEnumerable<string> roots, IProgress<FileScanProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        var scanRoots = roots.ToArray();
        var threats = new List<FileThreat>();
        var scanned = 0; var skipped = 0; var processed = 0; long bytes = 0;
        foreach (var file in EnumerateFiles(scanRoots, cancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            processed++;
            try
            {
                var info = new FileInfo(file);
                if (info.Length > MaxFileSize) { skipped++; continue; }
                string hash;
                await using (var stream = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan))
                {
                    hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken));
                    bytes += stream.Length;
                }
                scanned++;
                if (_signatures.TryMatch(hash, out var signatureName))
                    threats.Add(new(signatureName, file, hash, FileThreatSeverity.High, "Correspondance exacte avec une signature SHA-256 locale.", DateTime.Now));
                else
                {
                    IReadOnlyList<HeuristicFinding> findings;
                    try { findings = _heuristics.Analyze(file, info.Length); } catch { findings = []; }
                    if (findings.Count > 0)
                        threats.Add(new(string.Join(", ", findings.Select(x => x.Name)), file, hash, FileThreatSeverity.Medium, string.Join(" ", findings.Select(x => x.Details)), DateTime.Now));
                }
            }
            catch (OperationCanceledException) { throw; }
            catch (IOException) { skipped++; }
            catch (UnauthorizedAccessException) { skipped++; }
            catch (System.Security.SecurityException) { skipped++; }
            if (processed % 16 == 0)
            {
                // File count is unknown until enumeration ends; this estimate approaches 95% and never claims completion early.
                var estimate = (int)Math.Min(95, processed * 100L / (processed + 2_000L));
                progress?.Report(new(estimate, $"Analyse locale en cours · {processed:N0} fichier(s) parcouru(s)"));
            }
        }
        progress?.Report(new(100, processed == 0 ? "Aucun fichier accessible dans les emplacements sélectionnés." : $"Analyse terminée · {processed:N0} fichier(s) parcouru(s)"));
        return new(scanned, threats.Count, skipped, bytes, DateTime.Now, threats);
    }

    private static IEnumerable<string> EnumerateFiles(IEnumerable<string> roots, CancellationToken cancellationToken)
    {
        var pending = new Stack<string>(roots.Where(Directory.Exists));
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var root in roots.Where(File.Exists)) if (seen.Add(Path.GetFullPath(root))) yield return Path.GetFullPath(root);
        while (pending.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var dir = pending.Pop();
            IEnumerable<string> entries;
            try { entries = Directory.EnumerateFileSystemEntries(dir); } catch { continue; }
            foreach (var entry in entries)
            {
                cancellationToken.ThrowIfCancellationRequested();
                FileAttributes attrs;
                try { attrs = File.GetAttributes(entry); } catch { continue; }
                if ((attrs & FileAttributes.ReparsePoint) != 0) continue;
                if ((attrs & FileAttributes.Directory) != 0) pending.Push(entry);
                else if (seen.Add(Path.GetFullPath(entry))) yield return Path.GetFullPath(entry);
            }
        }
    }
}
