# SafelyAI.Antivirus

Moteur local de démonstration raccordé à l’application WPF.

- Scan rapide des dossiers Bureau, Téléchargements, Documents et du dossier temporaire.
- Scan complet des volumes fixes; scan personnalisé d’un dossier choisi.
- Lecture seule, calcul SHA-256, annulation et saut des fichiers trop volumineux, verrouillés ou inaccessibles.
- Base locale persistante de signatures SHA-256 dans `%LOCALAPPDATA%\\SafelyAI\\Signatures\\signatures.json`; EICAR est intégré comme test inoffensif. L’utilisateur peut ajouter une empreinte confirmée depuis la liste des indicateurs. Une base maintenue et des mises à jour signées restent à fournir.
- Heuristiques conservatrices sur des métadonnées de nom/attributs; leurs résultats sont des indicateurs, pas une classification fiable de malware.
- Quarantaine locale réversible, avec empreinte vérifiée avant restauration. Suppression définitive et restauration nécessitent une confirmation UI.
- Scan manuel des clés USB amovibles, surveillance activable du dossier Téléchargements et scan des nouveaux fichiers une fois leur taille stabilisée.
- `FileBehaviorMonitor` observe uniquement un dossier explicitement choisi et conserve un journal des modifications; `RansomwareDetector` signale les rafales de suppressions/renommages. La réponse est une alerte, pas un blocage de processus.
- Historique des scans et des changements de fichiers conservé localement. Sauvegardes de fichiers créées explicitement par l’utilisateur, empreinte vérifiée à la restauration et copie restaurée sous un nouveau nom si l’original existe.

Ce prototype n’assure pas de protection noyau/temps réel complète, de détection fiable de tout ransomware, d’analyse de contenu avancée ou de couverture comparable à un antivirus commercial. Les sauvegardes sont à la demande et non des instantanés automatiques antérieurs à chaque changement.
