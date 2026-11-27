# SafelyAI.Desktop

Application WPF en français pour le tableau de bord et les pages de protection SAFELY AI.

## Démarrer

Depuis la racine du dépôt :

```powershell
dotnet run --project SafelyAI.Desktop\SafelyAI.Desktop.csproj
```

## État des fonctionnalités

- Navigation entre le tableau de bord, l’antivirus, la quarantaine, le réseau, le système, les comptes, la protection Web, la maintenance, les rapports et les paramètres.
- Thème clair/sombre et mode de protection enregistrés dans `%LOCALAPPDATA%\SafelyAI\preferences.json`.
- Scans locaux annulables (rapide, complet, personnalisé, USB) et historique persistant. Le moteur reste un prototype heuristique, détaillé dans `SafelyAI.Antivirus/README.md`.
- Lectures locales du système, du réseau, des comptes et des composants Windows ; certaines informations nécessitent des droits ou commandes Windows disponibles.
- Analyse heuristique locale des URL et téléchargements. Elle ne remplace pas une base de réputation ni un moteur antivirus.
- Nettoyage temporaire avec aperçu des fichiers, sélection explicite et confirmation avant suppression.
- Notifications de session et export des rapports en texte.

Le scanner local est raccordé à la vue Antivirus. La surveillance des téléchargements et d’un dossier s’active explicitement depuis cette page; les autres protections permanentes ne sont pas activées par ce prototype.
