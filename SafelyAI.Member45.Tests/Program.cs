using SafelyAI.Core.Models;
using SafelyAI.Maintenance.Diagnostics;
using SafelyAI.Network.IntrusionDetection;
using SafelyAI.Network.PortMonitoring;
using SafelyAI.Network.TrafficMonitoring;
using SafelyAI.Response.Containment;
using SafelyAI.Response.IncidentManager;
using SafelyAI.Response.RiskEngine;
using SafelyAI.SystemMonitor.RegistryMonitor;
using SafelyAI.WebProtection.UrlAnalysis;

var failures = new List<string>();
void Check(string name, bool condition)
{
    if (condition) Console.WriteLine($"[OK] {name}");
    else { Console.WriteLine($"[FAIL] {name}"); failures.Add(name); }
}

var url = new UrlAnalyzer().Analyze("http://example.test/login");
Check("URL HTTP suspecte", url.IsValid && url.Risks.Count >= 2 && url.RiskScore > 0);

var ipAnalyzer = new IpAddressAnalyzer();
var privateIp = ipAnalyzer.Analyze("192.168.1.10");
var publicIp = ipAnalyzer.Analyze("8.8.8.8");
Check("Classification IP privée", privateIp.IsValid && privateIp.IsPrivate && privateIp.Classification == "Réseau privé");
Check("Classification IP publique", publicIp.IsValid && !publicIp.IsPrivate && publicIp.Classification == "Adresse publique");

var connections = new[]
{
    new NetConnection("0.0.0.0", 443, "8.8.8.8", 4444, "Established", 10, "powershell"),
    new NetConnection("0.0.0.0", 22, "8.8.8.8", 4445, "Established", 10, "powershell")
};
Check("Détection connexion suspecte", new SuspiciousConnectionDetector().Analyze(connections).Count >= 2);
Check("Détection port local", new PortMonitor().DetectPortScans(Enumerable.Range(1, 10).Select(port =>
    new NetConnection("127.0.0.1", port, "8.8.8.8", 5000, "Established", 1, "test"))).Count == 1);

var first = new NetworkTrafficSnapshot(DateTimeOffset.UtcNow, 100, 200);
var second = new NetworkTrafficSnapshot(DateTimeOffset.UtcNow, 150, 350);
var delta = TrafficMonitor.CalculateDelta(first, second);
Check("Calcul débit réseau", delta.SentBytes == 50 && delta.ReceivedBytes == 150);

var registry = new RegistryMonitor();
var before = new List<RegistryValueSnapshot> { new("CurrentUser", "Run", "A", "one") };
var after = new List<RegistryValueSnapshot> { new("CurrentUser", "Run", "A", "two"), new("CurrentUser", "Run", "B", "new") };
Check("Détection changement registre", registry.DetectChanges(before, after).Count == 2);

var risk = new RiskAnalyzer().Analyze(new SecurityThreat { Name = "test", Severity = "Critique" });
Check("Classification risque critique", risk.Success && risk.Level == "Critique" && risk.Score == 90);

var incidents = new IncidentManager();
var incident = incidents.CreateIncident("Test", "Description", "Test", "Élevé");
Check("Création incident", incidents.GetIncidentById(incident.Id) != null);
Check("Mise à jour incident", incidents.UpdateIncidentStatus(incident.Id, "En cours") && incident.Status == "En cours");

Check("Blocage processus exige confirmation", !new ProcessBlocker().Block(999999, false).Success);
Check("Blocage réseau valide l'adresse", !new NetworkBlocker().BlockIp("not-an-ip", true).Success);
Check("Isolement exige confirmation", !new FileIsolationManager().Isolate("missing.file", Path.GetTempPath(), false).Success);
Check("Mise à jour Windows exposée", new WindowsUpdateChecker() != null);

Console.WriteLine($"\nRésultat : {failures.Count} échec(s) sur les tests membre 4/5.");
return failures.Count == 0 ? 0 : 1;
