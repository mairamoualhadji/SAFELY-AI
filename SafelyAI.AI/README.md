# SafelyAI.AI

Le module IA fonctionne d'abord avec des règles locales et peut utiliser un modèle Ollama local pour enrichir les explications.

## Fonctionnalités

- Client HTTP Ollama local (`http://localhost:11434`) avec génération, conversation, version et gestion des modèles.
- Analyse comportementale des processus : chemin, CPU, mémoire et connexions réseau.
- Apprentissage statistique des habitudes par processus avec moyenne et écart-type, sauvegardé en JSON.
- Détection des anomalies système : CPU global, RAM et espace libre des disques.
- Analyse locale des fichiers : extension, double extension, emplacement modifiable, démarrage automatique, attribut caché et SHA-256.
- Classification `Info`, `Low`, `Medium`, `High`, `Critical` et conversion vers les niveaux du projet Core.
- Explications en français, recommandations de sécurité et repli hors ligne.
- Assistant conversationnel local avec historique borné et réponse de secours hors ligne.
- Génération et sauvegarde de rapports JSON.

## Préparation Ollama

Installer Ollama sur Windows, démarrer son serveur local, puis installer explicitement le modèle choisi :

```powershell
ollama serve
ollama pull qwen2.5:7b
```

Le téléchargement n'est pas lancé automatiquement par le constructeur de `AIEngine`. Il peut être demandé explicitement avec `EnsureConfiguredModelAsync()`.

## Utilisation principale

```csharp
var engine = new AIEngine();

var processes = await engine.ProcessCollector.CollectAsync();
foreach (var process in processes)
{
    var analysis = await engine.BehaviorAnalysis.AnalyzeAsync(process);
    var threat = SecurityThreatFactory.FromBehavior(analysis);
}

var file = await engine.FileAnalysis.AnalyzeAsync(filePath);
var answer = await engine.Assistant.AskAsync("Que signifie cette menace ?");

engine.SaveLearningModel();
```

Le module ne supprime, ne bloque et ne met aucun élément en quarantaine automatiquement. Il produit des analyses, des recommandations et des menaces structurées afin que le moteur central ou l'interface demande ensuite une confirmation à l'utilisateur.
