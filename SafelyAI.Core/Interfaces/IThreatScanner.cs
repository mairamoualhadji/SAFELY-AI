
using SafelyAI.Core.Models;

namespace SafelyAI.Core.Interfaces;

public interface IThreatScanner
{
    Task<SecurityAnalysisResult> ScanFileAsync(string filePath);

    Task<SecurityAnalysisResult> ScanUrlAsync(string url);

    Task<bool> IsThreatDetectedAsync(string filePath);
}
