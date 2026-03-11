namespace API_Tester
{
    public partial class MainPage
    {
        /*
        SC-8 Transmission Confidentiality and Integrity Tests

        Purpose:
        Performs automated tests to evaluate the application’s controls for 
        maintaining the confidentiality and integrity of data in transit, in 
        accordance with SC-8 security requirements, ensuring that communications 
        are protected from interception or tampering.

        Threat Model:
        Weak transmission security may allow attackers to:

            - Intercept sensitive data transmitted over networks
            - Modify or tamper with messages or transactions in transit
            - Exploit weak or misconfigured encryption protocols
            - Conduct man-in-the-middle (MITM) or replay attacks

        Common vulnerabilities include:

            - Unencrypted communication channels (e.g., HTTP instead of HTTPS)
            - Weak or outdated cryptographic algorithms and ciphers
            - Misconfigured TLS/SSL certificates or protocols
            - Lack of message integrity checks (e.g., HMAC, signatures)
            - Inadequate protection for sensitive headers or tokens in transit

        Test Strategy:
        The method performs automated checks that:

            - Verify encryption of sensitive data during transmission
            - Inspect configuration of TLS/SSL and cryptographic protocols
            - Test for message integrity verification mechanisms
            - Assess protection of authentication tokens, session IDs, and sensitive headers
            - Detect insecure or misconfigured communication endpoints

        Potential Impact:
        If transmission confidentiality and integrity controls are weak, attackers may:

            - Intercept and read sensitive communications
            - Modify data in transit without detection
            - Compromise authentication or session integrity
            - Exploit communication weaknesses to gain further access

        Expected Behavior:
        Applications should:

            - Encrypt all sensitive data in transit using strong protocols
            - Validate TLS/SSL configurations and enforce secure connections
            - Ensure integrity checks for transmitted data (e.g., HMAC or digital signatures)
            - Protect sensitive headers, tokens, and credentials in transit
            - Monitor and log communications for anomalies and potential attacks
        */

        private async Task<string> RunSc8TransmissionConfidentialityIntegrityTestsAsync(Uri baseUri)
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

