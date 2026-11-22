# SAFELY AI : solution complète
Ouvrir le dossier dans VS Code, puis dans le terminal : `dotnet build SafelyAI.slnx`
Lancer l'interface : `dotnet run --project SafelyAI.Desktop` (Windows, .NET 10).

Projets : Desktop (interface, Membre 1), AI (Membre 2), Network / Identity / SystemMonitor (Membre 4),
Common (outil partagé Shell.cs). SafelyAI.Antivirus (Membre 3) n'est pas inclus : c'est le travail de Dorcas.
Les modules Network, Identity et SystemMonitor lisent Windows : lancer en administrateur pour Secure Boot, TPM,
BitLocker, journaux de sécurité, politique de mots de passe et règles de pare-feu.
