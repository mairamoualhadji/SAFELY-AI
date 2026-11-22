
using SafelyAI.WebProtection.PhishingDetection;
using SafelyAI.WebProtection.DomainReputation;
using SafelyAI.WebProtection.Certificates;
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
Console.WriteLine("\n=== TEST CERTIFICATS HTTPS ===");

var certificateAnalyzer = new CertificateAnalyzer();

string[] certificateUrls =
{
    "https://www.google.com",
    "https://expired.badssl.com"
};

foreach (string url in certificateUrls)
{
    var result = await certificateAnalyzer.AnalyzeAsync(url);

    Console.WriteLine($"\nURL : {result.Url}");
    Console.WriteLine($"Connexion réussie : {result.ConnectionSuccessful}");

    if (result.ConnectionSuccessful)
    {
        Console.WriteLine($"Sujet : {result.Subject}");
        Console.WriteLine($"Émetteur : {result.Issuer}");
        Console.WriteLine($"Expiration : {result.ExpirationDate}");
    }

    Console.WriteLine($"Score : {result.RiskScore}/100");
    Console.WriteLine($"Niveau : {result.RiskLevel}");

    foreach (string finding in result.Findings)
    {
        Console.WriteLine("- " + finding);
    }
}