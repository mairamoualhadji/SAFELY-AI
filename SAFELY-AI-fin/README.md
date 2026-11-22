# SAFELY-AI
SAFELY AI est une solution intelligente de cybersécurité pour Windows combinant antivirus, intelligence artificielle, surveillance en temps réel et protection avancée contre les menaces.


## Organisation du code
| Projet | Rôle | Responsable |
|---|---|---|
| SafelyAI.Desktop | Interface WPF, tableau de bord | Membre 1 |
| SafelyAI.AI | Ollama, analyse comportementale, anomalies, classification | Membre 2 |
| SafelyAI.Antivirus | Moteur de scan, signatures, quarantaine, ransomwares | Membre 3 (à ajouter) |
| SafelyAI.Network / Identity / SystemMonitor | Réseau, comptes, système, matériel | Membre 4 |
| SafelyAI.Core / Infrastructure / Maintenance / Response / WebProtection / WindowsService | Socle, journalisation, maintenance, réponse aux incidents, protection Web, service Windows | Membre 5 |
| SafelyAI.Common | Outil partagé (Shell.cs) pour lancer PowerShell | Membre 4 |

Compiler tout : `dotnet build SafelyAI.sln` (Windows, .NET 10). Interface : `dotnet run --project SafelyAI.Desktop`.
Network, Identity et SystemMonitor lisent Windows : lancer en administrateur pour Secure Boot, TPM, BitLocker, journaux de sécurité, mots de passe et pare-feu.
