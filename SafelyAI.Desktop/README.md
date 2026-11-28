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
- Le tableau de bord lance les scans Microsoft Defender rapide, complet ou personnalisé. Dans la page Antivirus, les scans locaux annulables (rapide, complet, personnalisé, USB), les scans Defender sur USB et la mise à jour Defender sont disponibles. Le scanner local reste complémentaire; ses limites sont détaillées dans `SafelyAI.Antivirus/README.md`.
- Lectures locales du système, du réseau, des comptes et des composants Windows ; certaines informations nécessitent des droits ou commandes Windows disponibles.
- Analyse heuristique locale des URL et téléchargements. Elle ne remplace pas une base de réputation ni un moteur antivirus.
- Nettoyage temporaire avec aperçu des fichiers, sélection explicite et confirmation avant suppression.
- Notifications de session et export des rapports en texte. Les 500 derniers résultats de scans Defender et les 2 000 derniers événements d’activité sont conservés sous `%LOCALAPPDATA%\SafelyAI\History`.
- La page Rapports peut lire, sans modifier l’état de sécurité, les 200 détections Defender les plus récentes disponibles sur Windows; cette lecture est facultative et peut être indisponible selon la configuration du poste.

Le scanner local et le flux MalwareBazaar sont raccordés à la vue Antivirus. La surveillance d’un dossier choisi s’active depuis cette page. Dans Paramètres, l’agent de fond facultatif peut démarrer avec la session utilisateur, contrôler jusqu’à 20 000 fichiers déjà présents au premier niveau de Téléchargements, puis les nouveaux fichiers stabilisés; il applique le mode de performance enregistré et tente un scan personnalisé Defender sans élévation sur les nouveaux téléchargements. Si cette demande est refusée, son propre scan continue et l’échec est consigné. C’est un processus utilisateur, sans protection noyau ni interception garantie avant exécution.
