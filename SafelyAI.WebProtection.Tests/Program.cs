
using SafelyAI.WebProtection.PhishingDetection;

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
