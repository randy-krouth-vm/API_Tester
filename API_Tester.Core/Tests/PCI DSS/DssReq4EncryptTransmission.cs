namespace API_Tester
{
    public partial class MainPage
    {
        /*
        PCI DSS Requirement 4 – Encrypt Transmission Tests

        Purpose:
        Performs automated tests to verify that sensitive data transmitted
        between the client and the application is encrypted in accordance
        with PCI DSS Requirement 4. These tests evaluate whether secure
        communication protocols are enforced to protect data in transit.

        Threat Model:
        If transmission encryption is weak or missing, attackers may:

            - intercept sensitive data using network sniffing
            - perform man-in-the-middle (MITM) attacks
            - capture authentication credentials or payment information
            - modify or tamper with transmitted data

        Payment environments often transmit sensitive data such as:

            - payment card information
            - authentication credentials
            - session tokens
            - customer personal data
            - transaction details

        Common vulnerabilities include:

            - use of unencrypted HTTP instead of HTTPS
            - weak or outdated TLS versions
            - insecure cipher suites
            - improper certificate validation
            - inconsistent encryption across services

        Test Strategy:
        The method performs automated checks that:

            - verify enforcement of HTTPS for all communication
            - inspect TLS configuration and certificate validity
            - detect insecure redirects or protocol downgrades
            - analyze responses for sensitive data transmitted insecurely
            - evaluate encryption consistency across application endpoints

        Potential Impact:
        If transmission encryption controls are weak, attackers may:

            - capture payment card data or sensitive customer information
            - compromise authentication credentials
            - manipulate transaction data in transit
            - violate regulatory and compliance requirements

        Expected Behavior:
        Applications should:

            - enforce HTTPS using modern TLS protocols
            - disable insecure transport protocols
            - validate server certificates properly
            - encrypt all sensitive data transmitted over networks
            - consistently apply secure communication across all services
        */
        
        private async Task<string> RunDssReq4EncryptTransmissionTestsAsync(Uri baseUri)
        {
            var findings = new List<string>
            {
                baseUri.Scheme == Uri.UriSchemeHttps
                ? "HTTPS target detected."
                : "Potential risk: HTTP target detected (no TLS on this URL)."
            };

            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, baseUri));
            if (response is null)
            {
                findings.Add("No response received.");
                return FormatSection("Transport Security", baseUri, findings);
            }

            findings.Add($"HTTP {(int)response.StatusCode} {response.StatusCode}");
            if (baseUri.Scheme == Uri.UriSchemeHttps)
            {
                findings.Add(response.Headers.Contains("Strict-Transport-Security")
                ? "HSTS header present."
                : "HSTS header missing.");
            }

            return FormatSection("Transport Security", baseUri, findings);
        }
    }
}

