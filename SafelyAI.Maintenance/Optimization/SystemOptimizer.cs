
using System;
using System.Collections.Generic;
using System.IO;

namespace SafelyAI.Maintenance.Optimization
{
    public class SystemOptimizer
    {
        public OptimizationResult AnalyzeTemporaryFiles()
        {
            var result = new OptimizationResult();

            if (!OperatingSystem.IsWindows())
            {
                result.Message = "Cette fonctionnalité nécessite Windows.";
                return result;
            }

            string tempPath = Path.GetFullPath(Path.GetTempPath());

            try
            {
                foreach (string file in Directory.EnumerateFiles(
                    tempPath, "*", SearchOption.TopDirectoryOnly))
                {
                    try
                    {
                        var info = new FileInfo(file);

                        if (info.Exists)
                        {
                            result.FilesFound++;
                            result.TotalSize += info.Length;
                            result.Files.Add(info.FullName);
                        }
                    }
                    catch (UnauthorizedAccessException)
                    {
                        result.SkippedFiles++;
                    }
                    catch (IOException)
                    {
                        result.SkippedFiles++;
                    }
                }

                result.Success = true;
                result.Message = "Analyse terminée. Aucun fichier supprimé.";
            }
            catch (UnauthorizedAccessException)
            {
                result.Message = "Accès refusé au dossier temporaire.";
            }
            catch (IOException ex)
            {
                result.Message = "Erreur pendant l'analyse : " + ex.Message;
            }

            return result;
        }

        public OptimizationResult CleanTemporaryFiles(
            List<string> selectedFiles,
            bool confirmed)
        {
            var result = new OptimizationResult();

            if (!OperatingSystem.IsWindows())
            {
                result.Message = "Cette fonctionnalité nécessite Windows.";
                return result;
            }

            if (!confirmed)
            {
                result.Message = "Nettoyage annulé : confirmation requise.";
                return result;
            }

            if (selectedFiles == null || selectedFiles.Count == 0)
            {
                result.Message = "Aucun fichier sélectionné.";
                return result;
            }

            string tempPath = Path.GetFullPath(Path.GetTempPath());

            foreach (string file in selectedFiles)
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(file))
                    {
                        result.SkippedFiles++;
                        continue;
                    }

                    string fullPath = Path.GetFullPath(file);

                    // Vérifier que le chemin est réellement dans Temp.
                    if (!IsInsideDirectory(tempPath, fullPath))
                    {
                        result.SkippedFiles++;
                        continue;
                    }

                    if (!File.Exists(fullPath))
                    {
                        result.SkippedFiles++;
                        continue;
                    }

                    var info = new FileInfo(fullPath);

                    // Refuser les liens symboliques et autres liens spéciaux.
                    if ((info.Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        result.SkippedFiles++;
                        continue;
                    }

                    if (info.IsReadOnly)
                    {
                        result.SkippedFiles++;
                        continue;
                    }

                    long size = info.Length;

                    File.Delete(fullPath);

                    result.FilesDeleted++;
                    result.TotalSize += size;
                }
                catch (UnauthorizedAccessException)
                {
                    result.SkippedFiles++;
                }
                catch (IOException)
                {
                    result.SkippedFiles++;
                }
                catch (ArgumentException)
                {
                    result.SkippedFiles++;
                }
                catch (NotSupportedException)
                {
                    result.SkippedFiles++;
                }
            }

            result.Success = true;
            result.Message = "Nettoyage terminé.";

            return result;
        }

        private bool IsInsideDirectory(string directory, string file)
        {
            string relativePath = Path.GetRelativePath(directory, file);

            if (Path.IsPathRooted(relativePath))
            {
                return false;
            }

            if (relativePath == "..")
            {
                return false;
            }

            if (relativePath.StartsWith(
                ".." + Path.DirectorySeparatorChar,
                StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return relativePath != ".";
        }
    }

    public class OptimizationResult
    {
        public bool Success { get; set; }

        public string Message { get; set; } = "";

        public int FilesFound { get; set; }

        public int FilesDeleted { get; set; }

        public int SkippedFiles { get; set; }

        public long TotalSize { get; set; }

        public List<string> Files { get; set; } = new List<string>();
    }
}
