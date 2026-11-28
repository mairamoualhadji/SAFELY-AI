
using System;
using System.IO;
using System.Collections.Generic;

using SafelyAI.WebProtection.PhishingDetection;
using SafelyAI.WebProtection.DomainReputation;
using SafelyAI.WebProtection.Certificates;
using SafelyAI.WebProtection.DownloadAnalysis;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SafelyAI.Maintenance.Diagnostics;
using SafelyAI.Maintenance.Repair;
using SafelyAI.Maintenance.Optimization;

// ==========================================
// TEST PHISHING DETECTION
// ==========================================

var detector = new PhishingDetector();

string[] urls =
{
    "https://www.google.com",
    "https://google-login.example.com",
    "https://paypal-security.example.com",
    "http://192.168.1.10/login"
};

foreach (string url in urls)
{
    var result = detector.Analyze(url);

    Console.WriteLine("\nURL : " + result.Url);
    Console.WriteLine("Score : " + result.RiskScore + "/100");
    Console.WriteLine("Niveau : " + result.RiskLevel);

    foreach (string finding in result.Findings)
    {
        Console.WriteLine("- " + finding);
    }
}

// ==========================================
// TEST DOMAIN REPUTATION
// ==========================================

Console.WriteLine("\n=== TEST DOMAIN REPUTATION ===");

var reputationChecker = new DomainReputationChecker();

string[] reputationUrls =
{
    "https://www.google.com",
    "https://secure-login.xyz",
    "https://192.168.1.10",
    "https://paypal-account.top"
};

foreach (string url in reputationUrls)
{
    var result = reputationChecker.Analyze(url);

    Console.WriteLine($"\nURL : {result.Url}");
    Console.WriteLine($"Score : {result.RiskScore}/100");
    Console.WriteLine($"Niveau : {result.RiskLevel}");

    foreach (string finding in result.Findings)
    {
        Console.WriteLine("- " + finding);
    }
}

// ==========================================
// TEST CERTIFICATS HTTPS
// ==========================================

Console.WriteLine("\n=== TEST CERTIFICATS HTTPS ===");

var certificateAnalyzer = new CertificateAnalyzer();

string[] certificateUrls =
{
    "https://www.google.com",
    "https://expired.badssl.com"
};

foreach (string url in certificateUrls)
{
    var result = await certificateAnalyzer.AnalyzeAsync(url);

    Console.WriteLine($"\nURL : {result.Url}");
    Console.WriteLine($"Connexion réussie : {result.ConnectionSuccessful}");

    if (result.ConnectionSuccessful)
    {
        Console.WriteLine($"Sujet : {result.Subject}");
        Console.WriteLine($"Émetteur : {result.Issuer}");
        Console.WriteLine($"Expiration : {result.ExpirationDate}");
    }

    Console.WriteLine($"Score : {result.RiskScore}/100");
    Console.WriteLine($"Niveau : {result.RiskLevel}");

    foreach (string finding in result.Findings)
    {
        Console.WriteLine("- " + finding);
    }
}

// ==========================================
// TEST DOWNLOAD ANALYZER
// ==========================================

Console.WriteLine("\n=== TEST DOWNLOAD ANALYZER ===");

var downloadAnalyzer = new DownloadAnalyzer();

string testFolder = Path.Combine(
    Path.GetTempPath(),
    "SafelyAI-DownloadTests"
);

Directory.CreateDirectory(testFolder);

string[] testFiles =
{
    Path.Combine(testFolder, "document.txt"),
    Path.Combine(testFolder, "setup.exe"),
    Path.Combine(testFolder, "facture.pdf.exe")
};

File.WriteAllText(testFiles[0], "Document de test");
File.WriteAllText(testFiles[1], "Fichier de test inoffensif");
File.WriteAllText(testFiles[2], "Fichier de test inoffensif");

foreach (string file in testFiles)
{
    var result = downloadAnalyzer.Analyze(file);

    Console.WriteLine($"\nFichier : {result.FileName}");
    Console.WriteLine($"Extension : {result.Extension}");
    Console.WriteLine($"Taille : {result.FileSize} octets");
    Console.WriteLine($"SHA-256 : {result.SHA256}");
    Console.WriteLine($"Score : {result.RiskScore}/100");
    Console.WriteLine($"Niveau : {result.RiskLevel}");

    foreach (string finding in result.Findings)
    {
        Console.WriteLine("- " + finding);
    }
}

// ==========================================
// TEST SYSTEM DIAGNOSTICS
// ==========================================

Console.WriteLine("\n=== TEST SYSTEM DIAGNOSTICS ===");

var diagnostics = new SystemDiagnostics();
var system = diagnostics.Analyze();

Console.WriteLine($"Succès : {system.Success}");
Console.WriteLine($"Statut : {system.Status}");
Console.WriteLine($"Ordinateur : {system.ComputerName}");
Console.WriteLine($"Utilisateur : {system.UserName}");
Console.WriteLine($"Système : {system.OperatingSystem}");
Console.WriteLine($"Processeurs logiques : {system.ProcessorCount}");
Console.WriteLine($"Système 64 bits : {system.Is64BitOperatingSystem}");
Console.WriteLine($"RAM totale : {system.TotalMemoryGB} Go");
Console.WriteLine($"RAM disponible : {system.AvailableMemoryGB} Go");
Console.WriteLine($"Disque total : {system.TotalDiskSpaceGB} Go");
Console.WriteLine($"Espace libre : {system.FreeDiskSpaceGB} Go");

// ==========================================
// TEST SYSTEM REPAIR
// ==========================================

Console.WriteLine("\n=== TEST SYSTEM REPAIR ===");

var repair = new SystemRepair();

bool isAdmin = repair.IsAdministrator();

Console.WriteLine($"Windows détecté : {OperatingSystem.IsWindows()}");
Console.WriteLine($"Droits administrateur : {isAdmin}");

if (isAdmin)
{
    Console.WriteLine("Le système est prêt pour les opérations de réparation.");
}
else
{
    Console.WriteLine("Les réparations nécessiteront une exécution en administrateur.");
}

// ==========================================
// TEST SYSTEM OPTIMIZER
// ==========================================

Console.WriteLine("\n=== TEST SYSTEM OPTIMIZER ===");

var optimizer = new SystemOptimizer();

var optimization = optimizer.AnalyzeTemporaryFiles();

Console.WriteLine($"Succès : {optimization.Success}");
Console.WriteLine($"Message : {optimization.Message}");
Console.WriteLine($"Fichiers détectés : {optimization.FilesFound}");
Console.WriteLine($"Fichiers ignorés : {optimization.SkippedFiles}");
Console.WriteLine($"Espace récupérable : {optimization.TotalSize / 1024.0 / 1024.0:F2} Mo");

Console.WriteLine("Aucun fichier supprimé.");

// ==========================================
// TEST NETTOYAGE SECURISE
// ==========================================

Console.WriteLine("\n=== TEST NETTOYAGE SECURISE ===");

var cleanupOptimizer = new SystemOptimizer();

// Test 1 : nettoyage sans confirmation
var test1 = cleanupOptimizer.CleanTemporaryFiles(
    new List<string>(),
    false
);

Console.WriteLine("\nTest sans confirmation :");
Console.WriteLine($"Succès : {test1.Success}");
Console.WriteLine($"Message : {test1.Message}");

// Test 2 : fichier situé hors du dossier temporaire
var test2 = cleanupOptimizer.CleanTemporaryFiles(
    new List<string> { @"C:\Windows\test.txt" },
    true
);

Console.WriteLine("\nTest fichier externe :");
Console.WriteLine($"Fichiers supprimés : {test2.FilesDeleted}");
Console.WriteLine($"Fichiers ignorés : {test2.SkippedFiles}");
Console.WriteLine($"Message : {test2.Message}");

Console.WriteLine("\n=== FIN DES TESTS SAFELY AI ===");

Console.WriteLine("\n=== TEST SUPPRESSION CONTROLEE ===");

var testOptimizer = new SystemOptimizer();

// Création d'un fichier temporaire inoffensif
string testFile = Path.Combine(
    Path.GetTempPath(),
    "SafelyAI_Test_Cleanup.txt"
);

File.WriteAllText(testFile, "Fichier temporaire de test SAFELY AI");

// Vérifier que le fichier existe
Console.WriteLine($"Fichier créé : {File.Exists(testFile)}");

// Demander la suppression avec confirmation
var cleanupResult = testOptimizer.CleanTemporaryFiles(
    new List<string> { testFile },
    true
);

Console.WriteLine($"Nettoyage réussi : {cleanupResult.Success}");
Console.WriteLine($"Fichiers supprimés : {cleanupResult.FilesDeleted}");
Console.WriteLine($"Fichiers ignorés : {cleanupResult.SkippedFiles}");
Console.WriteLine($"Message : {cleanupResult.Message}");

// Vérification finale
Console.WriteLine($"Fichier encore présent : {File.Exists(testFile)}");

Console.WriteLine("\n=== TEST RISK ANALYZER ===");

var riskAnalyzer = new SafelyAI.Response.RiskEngine.RiskAnalyzer();

int[] scores = { 10, 45, 70, 90, 120 };

foreach (int score in scores)
{
    var risk = riskAnalyzer.Analyze(score);

    Console.WriteLine($"\nScore : {score}");
    Console.WriteLine($"Analyse réussie : {risk.Success}");
    Console.WriteLine($"Niveau : {risk.Level}");
    Console.WriteLine($"Recommandation : {risk.Recommendation}");
    Console.WriteLine($"Message : {risk.Message}");
}

Console.WriteLine("\n=== TEST INCIDENT MANAGER ===");

var incidentManager =
    new SafelyAI.Response.IncidentManager.IncidentManager();

// Création d'un incident
var incident = incidentManager.CreateIncident(
    "Activité suspecte",
    "Un comportement inhabituel a été détecté.",
    "Comportement suspect",
    "Élevé"
);

Console.WriteLine($"Incident créé : {incident.Id}");
Console.WriteLine($"Titre : {incident.Title}");
Console.WriteLine($"Gravité : {incident.Severity}");
Console.WriteLine($"Statut : {incident.Status}");

// Vérification de la liste
Console.WriteLine(
    $"Nombre d'incidents : {incidentManager.GetAllIncidents().Count}"
);

// Mise à jour du statut
bool updated = incidentManager.UpdateIncidentStatus(
    incident.Id,
    "En cours"
);

Console.WriteLine($"Mise à jour réussie : {updated}");
Console.WriteLine($"Nouveau statut : {incident.Status}");

// Recherche par identifiant
var found = incidentManager.GetIncidentById(incident.Id);

Console.WriteLine($"Incident retrouvé : {found != null}");

Console.WriteLine("\n=== TEST RECOVERY MANAGER ===");

var recoveryManager =
    new SafelyAI.Response.Recovery.RecoveryManager();

// Créer un fichier de sauvegarde temporaire
string backupPath = Path.Combine(
    Path.GetTempPath(),
    "SafelyAI_Backup_Test.txt"
);

string destinationPath = Path.Combine(
    Path.GetTempPath(),
    "SafelyAI_Restored_Test.txt"
);

// Préparer le fichier de test
File.WriteAllText(backupPath, "Sauvegarde SAFELY AI");

// Nettoyer une éventuelle destination précédente
if (File.Exists(destinationPath))
{
    File.Delete(destinationPath);
}

// Test sans confirmation
var cancelled = recoveryManager.RestoreFile(
    backupPath,
    destinationPath,
    false
);

Console.WriteLine("\n=== TEST DATABASE MANAGER ===");

string databasePath = Path.Combine(
    Path.GetTempPath(),
    "safely_ai_test.db"
);

var databaseManager =
    new SafelyAI.Infrastructure.Database.DatabaseManager(databasePath);

Console.WriteLine("\nTest de connexion :");
Console.WriteLine($"Connexion réussie : {databaseManager.TestConnection()}");

databaseManager.Initialize();

Console.WriteLine("\nInitialisation de la base :");
Console.WriteLine($"Fichier créé : {File.Exists(databasePath)}");

databaseManager.Close();

if (File.Exists(databasePath))
{
    File.Delete(databasePath);
    Console.WriteLine("Fichier de test supprimé.");
}

Console.WriteLine("\n=== TEST SECURITY LOGGER ===");

string logPath = Path.Combine(
    Path.GetTempPath(),
    "safely_ai_test.log"
);

var logger =
    new SafelyAI.Infrastructure.Logging.SecurityLogger(logPath);

logger.LogInfo("SAFELY AI a démarré.");
logger.LogWarning("Activité inhabituelle détectée.");
logger.LogError("Erreur de test.");

Console.WriteLine("\nVérification du fichier :");
Console.WriteLine($"Fichier créé : {File.Exists(logPath)}");

string logContent = File.ReadAllText(logPath);

Console.WriteLine("\nContenu du journal :");
Console.WriteLine(logContent);

Console.WriteLine(
    $"Nombre d'événements : {File.ReadAllLines(logPath).Length}"
);

File.Delete(logPath);

Console.WriteLine("Fichier de test supprimé.");

Console.WriteLine("\n=== TEST CONFIGURATION MANAGER ===");

string configPath = Path.Combine(
    Path.GetTempPath(),
    "safely_ai_config_test.json"
);

var configManager =
    new SafelyAI.Infrastructure.Configuration.ConfigurationManager(configPath);

// Configuration de test
var testConfig = new
{
    MonitoringEnabled = true,
    ScanFrequency = 30,
    AutomaticUpdates = true
};

// Sauvegarde
configManager.Save(testConfig);

Console.WriteLine("\nTest de sauvegarde :");
Console.WriteLine($"Fichier créé : {configManager.Exists()}");

// Récupération
var loadedConfig = configManager.Load<System.Text.Json.JsonElement>();

Console.WriteLine("\nTest de récupération :");
Console.WriteLine($"Surveillance activée : {loadedConfig.GetProperty("MonitoringEnabled").GetBoolean()}");
Console.WriteLine($"Fréquence : {loadedConfig.GetProperty("ScanFrequency").GetInt32()}");
Console.WriteLine($"Mises à jour automatiques : {loadedConfig.GetProperty("AutomaticUpdates").GetBoolean()}");

// Suppression
bool deleted = configManager.Delete();

Console.WriteLine("\nTest de suppression :");
Console.WriteLine($"Suppression réussie : {deleted}");
Console.WriteLine($"Fichier encore présent : {configManager.Exists()}");

Console.WriteLine("\n=== TEST UPDATE MANAGER ===");

var updateManager =
    new SafelyAI.Infrastructure.Updates.UpdateManager();

Console.WriteLine("\nTest de comparaison des versions :");

bool updateAvailable = updateManager.IsUpdateAvailable(
    "1.0.0",
    "1.1.0"
);

Console.WriteLine($"Mise à jour disponible : {updateAvailable}");

bool noUpdate = updateManager.IsUpdateAvailable(
    "1.1.0",
    "1.0.0"
);

Console.WriteLine($"Aucune mise à jour nécessaire : {!noUpdate}");

bool invalidVersion = updateManager.IsUpdateAvailable(
    "version-invalide",
    "2.0.0"
);

Console.WriteLine($"Version invalide rejetée : {!invalidVersion}");

updateManager.Dispose();

Console.WriteLine("\n=== TEST SECURITY ENGINE ===");

var engine = new SafelyAI.Core.SecurityEngine.SecurityEngineManager();

engine.EventPublisher.ThreatDetected += (sender, e) =>
{
    Console.WriteLine($"Menace signalée : {e.Threat.Name}");
};

engine.EventPublisher.SecurityEventRaised += (sender, e) =>
{
    Console.WriteLine($"Événement signalé : {e.SecurityEvent.EventType}");
};

engine.EventPublisher.IncidentCreated += (sender, e) =>
{
    Console.WriteLine($"Incident signalé : {e.Incident.Title}");
};

// Test de l'analyse d'une menace
var testThreat = new SafelyAI.Core.Models.SecurityThreat
{
    Name = "Fichier suspect",
    ThreatType = "Fichier malveillant",
    Severity = "Critique"
};

var threatResult = engine.AnalyzeThreat(testThreat);

Console.WriteLine($"Analyse réussie : {threatResult.Success}");
Console.WriteLine($"Score : {threatResult.RiskScore}/100");
Console.WriteLine($"Niveau : {threatResult.RiskLevel}");

// Test d'un événement de sécurité
var testEvent = new SafelyAI.Core.Models.SecurityEvent
{
    EventType = "Connexion suspecte",
    Description = "Tentative de connexion inhabituelle.",
    Severity = "Élevé"
};

var eventResult = engine.AnalyzeEvent(testEvent);

Console.WriteLine($"Événement analysé : {eventResult.Success}");
Console.WriteLine($"Score : {eventResult.RiskScore}/100");

// Test de création d'un incident
var testIncident = new SafelyAI.Core.Models.SecurityIncident
{
    Title = "Activité suspecte",
    Description = "Comportement inhabituel détecté.",
    Type = "Sécurité",
    Severity = "Élevé"
};

engine.RegisterIncident(testIncident);

Console.WriteLine("=== FIN TEST SECURITY ENGINE ===");

Console.WriteLine("\n=== TEST LOG EVENT ===");

string eventLogPath = Path.Combine(
    Path.GetTempPath(),
    "SAFELY_AI_LogEvent_Test",
    "security.log"
);

var eventLogger = new SafelyAI.Infrastructure.Logging.SecurityLogger(eventLogPath);

var securityEvent = new SafelyAI.Core.Models.SecurityEvent
{
    EventType = "Connexion suspecte",
    Description = "Une connexion inhabituelle a été détectée.",
    Severity = "Élevé",
    Source = "Test"
};

eventLogger.LogEvent(securityEvent);

Console.WriteLine($"Fichier créé : {File.Exists(eventLogPath)}");

string eventLogContent = File.ReadAllText(eventLogPath);

Console.WriteLine($"Événement enregistré : {eventLogContent.Contains("Connexion suspecte")}");
Console.WriteLine($"Description enregistrée : {eventLogContent.Contains("connexion inhabituelle")}");

Console.WriteLine("=== FIN TEST LOG EVENT ===");

Console.WriteLine("\n=== TEST INCIDENT MANAGER INTERFACE ===");

SafelyAI.Core.Interfaces.IIncidentManager incidentService =
    new SafelyAI.Response.IncidentManager.IncidentManager();

var interfaceIncident = incidentService.CreateIncident(
    "Test interface Core",
    "Vérification de la connexion entre Core et Response.",
    "Sécurité",
    "Élevé"
);

Console.WriteLine($"Incident créé : {interfaceIncident != null}");
Console.WriteLine($"Titre : {interfaceIncident?.Title}");

var foundIncident =
    incidentService.GetIncidentById(interfaceIncident!.Id);

Console.WriteLine($"Incident retrouvé : {foundIncident != null}");

bool statusUpdated = incidentService.UpdateIncidentStatus(
    interfaceIncident.Id,
    "En cours"
);

Console.WriteLine($"Statut modifié : {statusUpdated}");
Console.WriteLine($"Nouveau statut : {interfaceIncident.Status}");

Console.WriteLine("=== FIN TEST INCIDENT MANAGER INTERFACE ===");

Console.WriteLine("\n=== TEST INTEGRATION SECURITY ENGINE ===");


Console.WriteLine("\n=== TEST INTEGRATION SECURITY ENGINE ===");

var integrationIncidentManager =
    new SafelyAI.Response.IncidentManager.IncidentManager();

var securityEngine =
    new SafelyAI.Core.SecurityEngine.SecurityEngineManager(
        integrationIncidentManager
    );

var integrationThreat = new SafelyAI.Core.Models.SecurityThreat
{
    Name = "Fichier suspect",
    Description = "Un comportement potentiellement malveillant a été détecté.",
    ThreatType = "Fichier",
    Severity = "Élevé",
    Source = "Test"
};

var generatedIncident =
    securityEngine.CreateIncidentFromThreat(integrationThreat);

Console.WriteLine($"Incident créé : {generatedIncident != null}");
Console.WriteLine($"Titre : {generatedIncident?.Title}");
Console.WriteLine($"Sévérité : {generatedIncident?.Severity}");

var integrationIncidents =
    integrationIncidentManager.GetAllIncidents();

Console.WriteLine(
    $"Nombre d'incidents enregistrés : {integrationIncidents.Count}"
);

Console.WriteLine("=== FIN TEST INTEGRATION ===");

// ==========================================
// TESTS COMPLETS RECOVERY MANAGER
// ==========================================

Console.WriteLine("\n=== TESTS COMPLETS RECOVERY MANAGER ===");

var recoveryTestManager =
    new SafelyAI.Response.Recovery.RecoveryManager();

string recoveryTestFolder = Path.Combine(
    Path.GetTempPath(),
    "SAFELY_AI_Recovery_Tests_" + Guid.NewGuid().ToString("N")
);

Directory.CreateDirectory(recoveryTestFolder);

string recoveryBackup = Path.Combine(
    recoveryTestFolder,
    "backup.txt"
);

string recoveryDestination = Path.Combine(
    recoveryTestFolder,
    "restored.txt"
);

string existingDestination = Path.Combine(
    recoveryTestFolder,
    "existing.txt"
);

string missingBackup = Path.Combine(
    recoveryTestFolder,
    "missing.txt"
);

File.WriteAllText(recoveryBackup, "Contenu de sauvegarde SAFELY AI");

// TEST 1 : restauration sans confirmation
var recoveryCancelled = recoveryTestManager.RestoreFile(
    recoveryBackup,
    recoveryDestination,
    false
);

Console.WriteLine("\nTest sans confirmation :");
Console.WriteLine($"Restauration refusée : {!recoveryCancelled.Success}");
Console.WriteLine($"Destination créée : {File.Exists(recoveryDestination)}");

// TEST 2 : restauration autorisée
var recoverySuccess = recoveryTestManager.RestoreFile(
    recoveryBackup,
    recoveryDestination,
    true
);

Console.WriteLine("\nTest restauration autorisée :");
Console.WriteLine($"Restauration réussie : {recoverySuccess.Success}");
Console.WriteLine($"Contenu correct : {File.Exists(recoveryDestination) &&
    File.ReadAllText(recoveryDestination) == "Contenu de sauvegarde SAFELY AI"}");

// TEST 3 : empêcher l'écrasement
File.WriteAllText(existingDestination, "Fichier déjà présent");

var recoveryExisting = recoveryTestManager.RestoreFile(
    recoveryBackup,
    existingDestination,
    true
);

Console.WriteLine("\nTest destination déjà existante :");
Console.WriteLine($"Écrasement refusé : {!recoveryExisting.Success}");
Console.WriteLine($"Contenu préservé : {File.ReadAllText(existingDestination) == "Fichier déjà présent"}");

// TEST 4 : sauvegarde inexistante
var recoveryMissing = recoveryTestManager.RestoreFile(
    missingBackup,
    Path.Combine(recoveryTestFolder, "missing_restored.txt"),
    true
);

Console.WriteLine("\nTest sauvegarde inexistante :");
Console.WriteLine($"Restauration refusée : {!recoveryMissing.Success}");

// TEST 5 : historique
var recoveryHistory = recoveryTestManager.GetRecoveryHistory();

Console.WriteLine("\nTest historique :");
Console.WriteLine($"Nombre de restaurations : {recoveryHistory.Count}");
Console.WriteLine($"Historique correct : {recoveryHistory.Count == 1}");
Console.WriteLine($"Identifiant présent : {recoveryHistory.Count == 1 && recoveryHistory[0].Id != Guid.Empty}");

Directory.Delete(recoveryTestFolder, true);

Console.WriteLine("\nDossier de test supprimé.");
Console.WriteLine("=== FIN TESTS COMPLETS RECOVERY MANAGER ===");

