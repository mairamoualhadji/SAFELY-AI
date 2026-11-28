using System.Security.Cryptography;

namespace SafelyAI.Response.Containment;

public sealed record IsolationResult(bool Success, string Message, string? IsolatedPath = null, string? Sha256 = null);

/// <summary>Moves a file into a private quarantine directory without overwriting an existing item.</summary>
public sealed class FileIsolationManager
{
    public IsolationResult Isolate(string filePath, string quarantineDirectory, bool confirmed)
    {
        if (!confirmed)
            return new(false, "Isolement annulé : confirmation explicite requise.");
        if (string.IsNullOrWhiteSpace(filePath) || string.IsNullOrWhiteSpace(quarantineDirectory))
            return new(false, "Le fichier et le dossier de quarantaine sont obligatoires.");

        try
        {
            string source = Path.GetFullPath(filePath);
            string quarantine = Path.GetFullPath(quarantineDirectory);
            if (!File.Exists(source))
                return new(false, "Le fichier à isoler est introuvable.");
            if ((new FileInfo(source).Attributes & FileAttributes.ReparsePoint) != 0)
                return new(false, "Les liens symboliques ne sont pas isolés automatiquement.");

            Directory.CreateDirectory(quarantine);
            string target = Path.Combine(quarantine, $"{DateTime.UtcNow:yyyyMMddHHmmssfff}_{Guid.NewGuid():N}_{Path.GetFileName(source)}");
            string hash;
            using (var stream = File.OpenRead(source))
                hash = Convert.ToHexString(SHA256.HashData(stream));
            File.Move(source, target);
            return new(true, "Fichier isolé dans la quarantaine.", target, hash);
        }
        catch (UnauthorizedAccessException)
        {
            return new(false, "Accès refusé : droits administrateur nécessaires.");
        }
        catch (IOException ex)
        {
            return new(false, $"Isolement impossible : {ex.Message}");
        }
    }
}
