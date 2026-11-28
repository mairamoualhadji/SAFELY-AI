# SAFELY-AI

SAFELY AI est une application de sécurité Windows qui regroupe des outils de diagnostic, un scanner local complémentaire et des commandes d’analyse à la demande avec Microsoft Defender.

## Démarrer l’application

- Windows 10 ou 11 (x64) avec .NET 10 Desktop Runtime.
- Ouvrir `SafelyAI.sln` avec Visual Studio 2026, ou compiler depuis PowerShell avec `dotnet build SafelyAI.sln`.
- Lancer `SafelyAI.Desktop`.
- Dans **Antivirus**, les boutons Defender lancent une analyse rapide, complète, d’un dossier ou d’une clé USB avec le moteur Windows. Windows peut demander une élévation UAC. Le résultat de remédiation et l’historique se consultent dans **Sécurité Windows > Protection contre les virus et menaces > Historique de protection**.
- Dans **Paramètres**, la protection en arrière-plan peut être activée pour la session Windows courante. L’agent caché contrôle jusqu’à 20 000 fichiers déjà présents au premier niveau de Téléchargements, puis les nouveaux fichiers stabilisés. Il tente un scan personnalisé Defender sans élévation pour les nouveaux téléchargements, puis exécute son scan local; si Windows refuse la demande Defender, l’échec est journalisé. Il démarre à l’ouverture de session, applique le mode de performance enregistré et écrit son journal dans `%LOCALAPPDATA%\\SafelyAI\\Logs\\background-protection.log`. Il fonctionne en espace utilisateur et ne remplace pas la protection en temps réel de Windows.
- Le tableau de bord interroge l’état Defender localement. Si Windows ne fournit pas cet état, il l’indique comme indisponible et propose d’ouvrir Sécurité Windows.
- Dans **Rapports**, l’historique des détections de Microsoft Defender peut être actualisé en lecture seule; jusqu’à 200 éléments sont affichés et inclus dans l’export de la session si la lecture a réussi.
- Pour expliquer un indicateur, l’assistant facultatif utilise Ollama uniquement sur `localhost`; il reçoit le nom de l’indicateur et des métadonnées, jamais le contenu du fichier. Sans Ollama, une explication de secours est fournie.

## Ce que fait le scanner SAFELY AI

- Analyse locale complémentaire en lecture seule, empreintes SHA-256 et heuristiques simples.
- Quarantaine locale réversible, analyse manuelle USB, surveillance activable des téléchargements et d’un dossier choisi, plus agent utilisateur de fond opt-in sur Téléchargements.
- Historique local des analyses, des menaces détectées (y compris celles consignées par l’agent de fond) et des changements de fichiers. Les menaces sont rechargées au démarrage et actualisables dans Rapports.

La base intégrée contient uniquement la signature de test EICAR et les empreintes ajoutées localement; le flux MalwareBazaar facultatif ajoute des indicateurs SHA-256 récents, pas un moteur de détection de contenu. Les heuristiques sont des indicateurs à vérifier. Le scanner SAFELY AI seul ne fournit pas une protection antivirus autonome, une interception noyau ou une prévention fiable des ransomwares. Pour la protection quotidienne, garder Microsoft Defender ou un autre antivirus reconnu actif; SAFELY AI ne modifie ni ne désactive sa configuration.

## Étapes vers une protection autonome

1. Stabiliser l’application et son intégration avec Microsoft Defender; les analyses Defender restent déclenchées à la demande.
2. Remplacer les indicateurs communautaires non signés par un flux de règles signé, versionné, anti-rollback et maintenu pour un produit antivirus.
3. Étendre la surveillance actuelle, qui ne couvre que Téléchargements en mode utilisateur, et valider la réponse sur une matrice Windows sans désactiver Defender.
4. Pour devenir un antivirus autonome, développer ou intégrer un moteur maintenu et un composant noyau signé pour l’interception des fichiers. Cela exige une chaîne de signature et de distribution Windows ainsi qu’une validation dédiée; les fonctions actuelles ne la remplacent pas.

## Données locales

Les signatures utilisateur, journaux, éléments de quarantaine et sauvegardes sont conservés sous `%LOCALAPPDATA%\\SafelyAI`. Les chemins et les options de confidentialité sont détaillés dans `SafelyAI.Antivirus/README.md`.
