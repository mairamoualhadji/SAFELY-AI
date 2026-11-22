
using SafelyAI.WebProtection.PhishingDetection;
using SafelyAI.WebProtection.DomainReputation;
var detector = new PhishingDetector();

string[] urls =
{
    "https://www.google.com",
    "https://google-login.example.com",
    "https://paypal-security.example.com",
    "http://192.168.1.10/login"
};

foreach (string url in urls)
{
    var result = detector.Analyze(url);

    Console.WriteLine("\nURL : " + result.Url);
    Console.WriteLine("Score : " + result.RiskScore + "/100");
    Console.WriteLine("Niveau : " + result.RiskLevel);

    foreach (string finding in result.Findings)
    {
        Console.WriteLine("- " + finding);
    }
}
Console.WriteLine("\n=== TEST DOMAIN REPUTATION ===");

var reputationChecker = new DomainReputationChecker();

string[] reputationUrls =
{
    "https://www.google.com",
    "https://secure-login.xyz",
    "https://192.168.1.10",
    "https://paypal-account.top"
};

foreach (string url in reputationUrls)
{
    var result = reputationChecker.Analyze(url);

    Console.WriteLine($"\nURL : {result.Url}");
    Console.WriteLine($"Score : {result.RiskScore}/100");
    Console.WriteLine($"Niveau : {result.RiskLevel}");

    foreach (string finding in result.Findings)
    {
        Console.WriteLine("- " + finding);
    }
}
