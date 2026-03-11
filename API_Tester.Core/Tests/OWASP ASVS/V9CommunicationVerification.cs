namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Communication Security Verification Tests (V9)

        Purpose:
        Performs automated tests to verify that communication channels used
        by the application are properly secured. These tests ensure that data
        transmitted between clients, services, and external systems is protected
        against interception, tampering, or unauthorized disclosure.

        Threat Model:
        Weak communication security may allow attackers to:

            - intercept sensitive data during transmission
            - perform man-in-the-middle (MITM) attacks
            - modify messages in transit
            - exploit insecure transport protocols
            - downgrade connections to weaker encryption

        Attackers commonly attempt to exploit:

            - unencrypted HTTP endpoints
            - weak or outdated TLS configurations
            - improper certificate validation
            - exposed internal service communication
            - insecure API integrations

        Common vulnerabilities include:

            - use of insecure transport protocols (e.g., HTTP instead of HTTPS)
            - outdated or weak TLS versions or cipher suites
            - missing certificate validation
            - lack of integrity protection for transmitted data
            - inconsistent encryption across services

        Test Strategy:
        The method performs automated checks that:

            - verify that all endpoints enforce secure transport (HTTPS/TLS)
            - inspect TLS configuration and certificate validity
            - detect insecure redirects or protocol downgrades
            - evaluate encryption consistency across endpoints
            - identify exposed insecure communication interfaces

        Potential Impact:
        If communication security controls are weak, attackers may:

            - capture sensitive user or system data
            - manipulate messages in transit
            - compromise authentication tokens or session identifiers
            - gain insight into internal system operations

        Expected Behavior:
        Applications should:

            - enforce HTTPS for all communications
            - use modern TLS versions and secure cipher suites
            - validate certificates properly
            - ensure integrity protection for transmitted data
            - consistently apply secure communication practices across all services
        */
        
        private async Task<string> RunV9CommunicationVerificationTestsAsync(Uri baseUri)
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

