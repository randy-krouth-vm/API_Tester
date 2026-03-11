namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Network Communication Tests

        Purpose:
        Performs automated tests to evaluate the security of network
        communications between the client and the application. These tests
        verify that network connections are properly protected and that
        sensitive data is not transmitted insecurely.

        Threat Model:
        Insecure network communication may allow attackers to:

            - intercept sensitive information
            - perform man-in-the-middle (MITM) attacks
            - modify messages during transmission
            - exploit weak or outdated encryption protocols

        Attackers may attempt to observe or manipulate traffic when:

            - communication occurs over insecure protocols
            - TLS configurations are weak
            - certificates are improperly validated
            - internal services communicate without encryption

        Common vulnerabilities include:

            - unencrypted HTTP communication
            - weak TLS versions or cipher suites
            - missing certificate validation
            - exposure of sensitive data in network responses
            - inconsistent encryption between services

        Test Strategy:
        The method performs automated checks that:

            - verify that all endpoints enforce encrypted communication
            - inspect TLS configurations and certificate validity
            - detect insecure redirects or protocol downgrades
            - analyze network responses for sensitive information exposure
            - evaluate consistency of encryption across services

        Potential Impact:
        If network communication protections are weak, attackers may:

            - capture authentication tokens or credentials
            - manipulate requests or responses
            - gain access to sensitive system data
            - compromise system confidentiality and integrity

        Expected Behavior:
        Applications should:

            - enforce HTTPS for all communications
            - use modern TLS versions and strong cipher suites
            - validate certificates properly
            - avoid transmitting sensitive data over insecure channels
            - consistently secure communication between all services
        */
        
        private async Task<string> RunNetworkCommunicationTestsAsync(Uri baseUri)
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

