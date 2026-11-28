
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;

namespace SafelyAI.Response.Recovery
{
    public class RecoveryManager
    {
        private readonly List<RecoveryRecord> records = new();
        private readonly object recordsLock = new();
        private readonly string? historyPath;

        public RecoveryManager(string? historyPath = null)
        {
            this.historyPath = string.IsNullOrWhiteSpace(historyPath) ? null : Path.GetFullPath(historyPath);
            if (this.historyPath == null || !File.Exists(this.historyPath)) return;
            try
            {
                var loaded = JsonSerializer.Deserialize<List<RecoveryRecord>>(File.ReadAllText(this.historyPath));
                if (loaded != null) records.AddRange(loaded);
            }
            catch { /* Un historique corrompu ne doit pas empêcher la restauration. */ }
        }

        public RecoveryResult RestoreFile(
            string backupPath,
            string destinationPath,
            bool confirmed)
        {
            var result = new RecoveryResult();

            if (!confirmed)
            {
                result.Message = "Restauration annulée : confirmation requise.";
                return result;
            }

            if (string.IsNullOrWhiteSpace(backupPath) ||
                string.IsNullOrWhiteSpace(destinationPath))
            {
                result.Message = "Les chemins des fichiers sont obligatoires.";
                return result;
            }

            try
            {
                string source = Path.GetFullPath(backupPath);
                string destination = Path.GetFullPath(destinationPath);

                if (!File.Exists(source))
                {
                    result.Message = "Le fichier de sauvegarde est introuvable.";
                    return result;
                }

                if (string.Equals(
                    source,
                    destination,
                    StringComparison.OrdinalIgnoreCase))
                {
                    result.Message = "La source et la destination sont identiques.";
                    return result;
                }

                if (File.Exists(destination))
                {
                    result.Message = "Un fichier existe déjà à cette destination.";
                    return result;
                }

                string? directory = Path.GetDirectoryName(destination);

                if (string.IsNullOrWhiteSpace(directory) ||
                    !Directory.Exists(directory))
                {
                    result.Message = "Le dossier de destination n'existe pas.";
                    return result;
                }

                File.Copy(source, destination, false);

                var record = new RecoveryRecord
                {
                    Id = Guid.NewGuid(),
                    BackupPath = source,
                    DestinationPath = destination,
                    RestoredAt = DateTime.Now,
                    Status = "Restauré"
                };

                lock (recordsLock)
                {
                    records.Add(record);
                    PersistHistory();
                }

                result.Success = true;
                result.Record = record;
                result.Message = "Fichier restauré avec succès.";
            }
            catch (UnauthorizedAccessException)
            {
                result.Message = "Accès refusé pendant la restauration.";
            }
            catch (IOException ex)
            {
                result.Message = "Erreur de restauration : " + ex.Message;
            }
            catch (ArgumentException)
            {
                result.Message = "Chemin de fichier invalide.";
            }
            catch (NotSupportedException)
            {
                result.Message = "Format de chemin non pris en charge.";
            }

            return result;
        }

        public List<RecoveryRecord> GetRecoveryHistory()
        {
            lock (recordsLock) return new List<RecoveryRecord>(records);
        }

        private void PersistHistory()
        {
            if (historyPath == null) return;
            string? directory = Path.GetDirectoryName(historyPath);
            if (!string.IsNullOrWhiteSpace(directory)) Directory.CreateDirectory(directory);
            string temporary = historyPath + ".tmp";
            File.WriteAllText(temporary, JsonSerializer.Serialize(records, new JsonSerializerOptions { WriteIndented = true }));
            File.Move(temporary, historyPath, true);
        }
    }

    public class RecoveryRecord
    {
        public Guid Id { get; set; }

        public string BackupPath { get; set; } = "";

        public string DestinationPath { get; set; } = "";

        public DateTime RestoredAt { get; set; }

        public string Status { get; set; } = "";
    }

    public class RecoveryResult
    {
        public bool Success { get; set; }

        public string Message { get; set; } = "";

        public RecoveryRecord? Record { get; set; }
    }
}
