
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace SafelyAI.WebProtection.DownloadAnalysis
{
    public class DownloadAnalyzer
    {
        private readonly string[] dangerousExtensions =
        {
            ".exe", ".dll", ".bat", ".cmd",
            ".ps1", ".vbs", ".js", ".scr",
            ".msi", ".com", ".hta", ".reg"
        };

        private readonly string[] suspiciousExtensions =
        {
            ".iso", ".img", ".jar", ".zip",
            ".rar", ".7z"
        };

        public DownloadAnalysisResult Analyze(string filePath)
        {
            var result = new DownloadAnalysisResult
            {
                FilePath = filePath,
                Findings = new List<string>()
            };

            if (string.IsNullOrWhiteSpace(filePath) ||
                !File.Exists(filePath))
            {
                result.Findings.Add("Fichier introuvable.");
                result.RiskScore = 100;
                result.RiskLevel = "Élevé";
                return result;
            }

            try
            {
                var fileInfo = new FileInfo(filePath);

                result.FileName = fileInfo.Name;
                result.FileSize = fileInfo.Length;
                result.Extension = fileInfo.Extension.ToLowerInvariant();

                // Vérification de l'extension
                if (dangerousExtensions.Contains(result.Extension))
                {
                    result.Findings.Add(
                        "Extension potentiellement dangereuse : " + result.Extension
                    );
                }

                if (suspiciousExtensions.Contains(result.Extension))
                {
                    result.Findings.Add(
                        "Archive ou image disque nécessitant une analyse complémentaire."
                    );
                }

                // Détection des doubles extensions trompeuses
                string[] parts = result.FileName.Split('.');

                if (parts.Length >= 3 &&
                    dangerousExtensions.Contains("." + parts[^1].ToLowerInvariant()))
                {
                    result.Findings.Add(
                        "Double extension détectée : le nom du fichier peut être trompeur."
                    );
                }

                // Calcul de l'empreinte SHA-256
                using (FileStream stream = File.OpenRead(filePath))
                {
                    byte[] hash = SHA256.HashData(stream);
                    result.SHA256 = Convert.ToHexString(hash);
                }

                result.RiskScore = Math.Min(
                    result.Findings.Count * 30, 100
                );

                result.RiskLevel = result.RiskScore >= 60
                    ? "Élevé"
                    : result.RiskScore >= 30
                        ? "Modéré"
                        : "Faible";

                if (result.Findings.Count == 0)
                {
                    result.Findings.Add(
                        "Aucun indicateur suspect détecté par cette analyse."
                    );
                }
            }
            catch (UnauthorizedAccessException)
            {
                result.Findings.Add("Accès au fichier refusé.");
                result.RiskScore = 100;
                result.RiskLevel = "Élevé";
            }
            catch (IOException ex)
            {
                result.Findings.Add("Erreur de lecture : " + ex.Message);
                result.RiskScore = 100;
                result.RiskLevel = "Élevé";
            }

            return result;
        }
    }

    public class DownloadAnalysisResult
    {
        public string FilePath { get; set; } = "";
        public string FileName { get; set; } = "";
        public string Extension { get; set; } = "";
        public long FileSize { get; set; }
        public string SHA256 { get; set; } = "";
        public int RiskScore { get; set; }
        public string RiskLevel { get; set; } = "";
        public List<string> Findings { get; set; } = new();
    }
}
