
using SafelyAI.WebProtection.PhishingDetection;
using SafelyAI.WebProtection.DomainReputation;
using SafelyAI.WebProtection.Certificates;
using SafelyAI.WebProtection.DownloadAnalysis;
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
Console.WriteLine("\n=== TEST DOWNLOAD ANALYZER ===");

var downloadAnalyzer = new DownloadAnalyzer();

string testFolder = Path.Combine(
    Path.GetTempPath(),
    "SafelyAI-DownloadTests"
);

Directory.CreateDirectory(testFolder);

// Création de trois fichiers de test inoffensifs
string[] testFiles =
{
    Path.Combine(testFolder, "document.txt"),
    Path.Combine(testFolder, "setup.exe"),
    Path.Combine(testFolder, "facture.pdf.exe")
};

File.WriteAllText(testFiles[0], "Document de test");
File.WriteAllText(testFiles[1], "Fichier de test inoffensif");
File.WriteAllText(testFiles[2], "Fichier de test inoffensif");

foreach (string file in testFiles)
{
    var result = downloadAnalyzer.Analyze(file);

    Console.WriteLine($"\nFichier : {result.FileName}");
    Console.WriteLine($"Extension : {result.Extension}");
    Console.WriteLine($"Taille : {result.FileSize} octets");
    Console.WriteLine($"SHA-256 : {result.SHA256}");
    Console.WriteLine($"Score : {result.RiskScore}/100");
    Console.WriteLine($"Niveau : {result.RiskLevel}");

    foreach (string finding in result.Findings)
    {
        Console.WriteLine("- " + finding);
    }
}