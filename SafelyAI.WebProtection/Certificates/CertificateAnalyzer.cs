
using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

namespace SafelyAI.WebProtection.Certificates
{
    public class CertificateAnalyzer
    {
        public async Task<CertificateAnalysisResult> AnalyzeAsync(string url)
        {
            var result = new CertificateAnalysisResult
            {
                Url = url,
                Findings = new List<string>()
            };

            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? uri)
                || uri == null
                || uri.Scheme != Uri.UriSchemeHttps)
            {
                result.Findings.Add("Une URL HTTPS valide est nécessaire.");
                result.RiskScore = 100;
                result.RiskLevel = "Élevé";
                return result;
            }

            try
            {
                using var client = new TcpClient();

                await client.ConnectAsync(uri.Host, 443);

              using var sslStream = new SslStream(
    client.GetStream(),
    false
);

                await sslStream.AuthenticateAsClientAsync(uri.Host);

                using X509Certificate2 cert =
                    new X509Certificate2(sslStream.RemoteCertificate!);

                result.Subject = cert.Subject;
                result.Issuer = cert.Issuer;
                result.ExpirationDate = cert.NotAfter;
                result.IsExpired = cert.NotAfter < DateTime.UtcNow;

                if (result.IsExpired)
                {
                    result.Findings.Add("Le certificat HTTPS est expiré.");
                }

                if (sslStream.SslProtocol == System.Security.Authentication.SslProtocols.None)
                {
                    result.Findings.Add("Le protocole TLS n'a pas pu être déterminé.");
                }

                if (result.Findings.Count == 0)
                {
                    result.Findings.Add("Aucun problème d'expiration détecté.");
                }

                result.RiskScore = result.IsExpired ? 100 : 0;
                result.RiskLevel = result.IsExpired ? "Élevé" : "Faible";
                result.ConnectionSuccessful = true;
            }
            catch (Exception ex)
            {
                result.Findings.Add("Impossible de vérifier le certificat : " + ex.Message);
                result.RiskScore = 100;
                result.RiskLevel = "Élevé";
                result.ConnectionSuccessful = false;
            }

            return result;
        }
    }

    public class CertificateAnalysisResult
    {
        public string Url { get; set; } = "";
        public string Subject { get; set; } = "";
        public string Issuer { get; set; } = "";
        public DateTime ExpirationDate { get; set; }
        public bool IsExpired { get; set; }
        public bool ConnectionSuccessful { get; set; }
        public int RiskScore { get; set; }
        public string RiskLevel { get; set; } = "";
        public List<string> Findings { get; set; } = new();
    }
}
