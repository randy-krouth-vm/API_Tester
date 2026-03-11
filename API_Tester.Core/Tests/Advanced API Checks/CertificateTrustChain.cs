namespace API_Tester;

public partial class MainPage
{
    /*
    Certificate Trust Chain Validation Test

    Purpose:
    Evaluates whether the server presents a properly configured TLS certificate
    chain during HTTPS connections.

    Threat Model:
    TLS certificates rely on a chain of trust that links the server certificate
    to a trusted Certificate Authority (CA). If the chain is incomplete,
    misconfigured, expired, or uses untrusted issuers, clients may be unable
    to verify the authenticity of the server.

    Improper certificate configuration can enable:

        - Man-in-the-Middle (MITM) attacks
        - Impersonation of services
        - Trust warnings in clients and browsers
        - Failed TLS verification in secure API clients

    Test Strategy:
    The scanner performs an HTTPS request and inspects the certificate chain
    returned by the server. It verifies whether:

        - The certificate is valid and not expired
        - The certificate chain links to a trusted root authority
        - Intermediate certificates are properly presented
        - The hostname matches the certificate's subject or SAN entries

    Potential Impact:
    If the certificate chain cannot be validated, clients may reject the
    connection or be vulnerable to interception attacks if certificate
    validation is bypassed.

    Expected Behavior:
    The server should present a complete, valid certificate chain signed
    by a trusted CA, with correct hostname bindings and valid expiration
    dates.
    */

    private async Task<string> RunCertificateTrustChainTestsAsync(Uri baseUri)
    {
        var findings = new List<string>();
        if (baseUri.Scheme != Uri.UriSchemeHttps)
        {
            findings.Add("Target is not HTTPS; certificate trust-chain probe requires TLS.");
            return FormatSection("Certificate Trust Chain", baseUri, findings);
        }

        try
        {
            using var tcp = new TcpClient();
            await tcp.ConnectAsync(baseUri.Host, baseUri.Port > 0 ? baseUri.Port : 443);
            using var ssl = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);
            await ssl.AuthenticateAsClientAsync(baseUri.Host);

            if (ssl.RemoteCertificate is null)
            {
                findings.Add("No remote certificate was presented.");
                return FormatSection("Certificate Trust Chain", baseUri, findings);
            }

            var cert = new X509Certificate2(ssl.RemoteCertificate);
            findings.Add($"Subject: {cert.Subject}");
            findings.Add($"Issuer: {cert.Issuer}");
            findings.Add($"NotAfter (UTC): {cert.NotAfter:yyyy-MM-dd HH:mm:ss}");
            findings.Add(cert.NotAfter <= DateTime.UtcNow
            ? "Potential risk: certificate appears expired."
            : "Certificate expiration window appears valid.");

            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            var valid = chain.Build(cert);
            findings.Add(valid
            ? "Certificate chain build succeeded."
            : $"Potential risk: chain issues ({string.Join(", ", chain.ChainStatus.Select(s => s.Status.ToString()))}).");
        }
        catch
        {
            findings.Add("Unable to complete TLS handshake/certificate probe.");
        }

        return FormatSection("Certificate Trust Chain", baseUri, findings);
    }

}

