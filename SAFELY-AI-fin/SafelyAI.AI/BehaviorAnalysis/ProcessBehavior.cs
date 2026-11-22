namespace SafelyAI.AI.BehaviorAnalysis;

// Photo d'un processus à un instant donné.
public record ProcessBehavior(string Name, int Pid, string? Path, double CpuPercent, double MemoryMb, int NetworkConnections);

// Résultat de l'analyse : score de 0 à 100 et raisons.
public record BehaviorReport(ProcessBehavior Process, int Score, List<string> Reasons);
