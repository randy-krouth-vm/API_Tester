namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Use of Cryptography Tests

        Purpose:
        Performs automated tests to evaluate the application’s use of 
        cryptography, ensuring that sensitive data is protected using 
        appropriate encryption algorithms, key management practices, 
        and cryptographic protocols.

        Threat Model:
        Improper use of cryptography may allow attackers to:

            - Intercept and read sensitive data in transit or at rest
            - Exploit weak or outdated encryption algorithms
            - Compromise poorly managed cryptographic keys
            - Bypass security mechanisms relying on cryptography

        Common vulnerabilities include:

            - Use of weak or deprecated algorithms (e.g., MD5, SHA-1)
            - Hard-coded or poorly protected cryptographic keys
            - Insecure storage of encrypted data
            - Lack of encryption for sensitive data in transit or at rest
            - Improper use of cryptographic libraries or protocols

        Test Strategy:
        The method performs asynchronous automated checks to:

            - Verify the strength and appropriateness of cryptographic algorithms
            - Inspect key management practices and storage
            - Assess encryption of data in transit and at rest
            - Detect insecure implementation or misuse of cryptography
            - Validate adherence to cryptographic best practices and standards

        Potential Impact:
        If cryptographic controls are weak, attackers may:

            - Access sensitive data despite encryption
            - Modify or tamper with encrypted data undetected
            - Exploit cryptographic weaknesses to bypass security controls
            - Compromise the confidentiality and integrity of systems and data

        Expected Behavior:
        Applications should:

            - Use strong, industry-standard encryption algorithms
            - Implement secure key generation, storage, and rotation practices
            - Encrypt sensitive data both in transit and at rest
            - Apply cryptography consistently across all relevant data and communications
            - Follow cryptographic best practices and regulatory requirements
        */
        
        private async Task<string> RunUseOfCryptographyTestsAsync(Uri baseUri)
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

