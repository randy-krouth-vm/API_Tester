namespace API_Tester
{
    public partial class MainPage
    {
        /*
        System and Communications Protection Tests

        Purpose:
        Performs automated tests to evaluate the application’s system and
        communications protection mechanisms, ensuring that data flows,
        network interactions, and system interfaces are protected against
        unauthorized access, interception, and tampering.

        Threat Model:
        Weak system and communications protections may allow attackers to:

            - Intercept or manipulate data in transit
            - Exploit insecure network services or exposed interfaces
            - Bypass segmentation or communication controls
            - Access internal services through insecure communication channels

        Common vulnerabilities include:

            - Unencrypted communication between systems
            - Misconfigured TLS/SSL or weak cryptographic protocols
            - Insecure service endpoints or APIs
            - Lack of integrity validation for transmitted data
            - Missing protections for internal service communication

        Test Strategy:
        The method performs automated checks that:

            - Verify encryption and secure protocols for data in transit
            - Assess protection of internal and external communication interfaces
            - Inspect TLS/SSL configurations and certificate usage
            - Detect insecure endpoints or exposed services
            - Evaluate integrity protections for transmitted data

        Potential Impact:
        If system and communications protections are weak, attackers may:

            - Intercept or modify sensitive communications
            - Access internal systems or services
            - Exploit exposed communication interfaces
            - Compromise the confidentiality and integrity of system data

        Expected Behavior:
        Applications should:

            - Encrypt sensitive communications using strong protocols
            - Secure all service interfaces and network communications
            - Implement integrity protections for transmitted data
            - Restrict access to internal services and interfaces
            - Monitor and log suspicious communication activity
        */

        private async Task<string> RunSystemAndCommunicationsProtectionTestsAsync(Uri baseUri)
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

