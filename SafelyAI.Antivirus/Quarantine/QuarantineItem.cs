namespace SafelyAI.Antivirus.Quarantine;
public sealed record QuarantineItem(string Id, string Name, string OriginalPath, string StoredPath, string Sha256, DateTime IsolatedAt);
