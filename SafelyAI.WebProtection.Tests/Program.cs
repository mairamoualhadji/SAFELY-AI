
using SafelyAI.WebProtection.UrlAnalysis;

var analyzer = new UrlAnalyzer();

string[] urls =
{
    "https://www.google.com",
    "http://example.com/login",
    "https://example.com/account/verify"
};

foreach (string url in urls)
{
    var result = analyzer.Analyze(url);

    Console.WriteLine("\nURL : " + result.Url);
    Console.WriteLine("Valide : " + result.IsValid);
    Console.WriteLine("Score : " + result.RiskScore + "/100");
    Console.WriteLine("Risque : " + result.RiskLevel);

    foreach (string risk in result.Risks)
    {
        Console.WriteLine("- " + risk);
    }
}
