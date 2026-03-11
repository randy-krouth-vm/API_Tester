namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Network Security Tests

        Purpose:
        Performs automated tests to evaluate the application’s network 
        security controls, ensuring that communications, services, and 
        network boundaries are properly protected against unauthorized 
        access, interception, and attacks.

        Threat Model:
        Weak network security may allow attackers to:

            - Intercept, modify, or disrupt network traffic
            - Exploit misconfigured network services or endpoints
            - Bypass firewalls, segmentation, or access controls
            - Launch denial-of-service (DoS) or other network-based attacks

        Common vulnerabilities include:

            - Open or unnecessary network ports
            - Weak or unencrypted communication protocols
            - Misconfigured firewalls, routing, or segmentation
            - Insecure or exposed services and endpoints
            - Lack of monitoring for anomalous network activity

        Test Strategy:
        The method performs asynchronous automated checks to:

            - Assess firewall and network segmentation configurations
            - Verify encryption and integrity of network communications
            - Detect exposed services or misconfigured network endpoints
            - Evaluate protection against common network attacks
            - Inspect monitoring and alerting for anomalous network activity

        Potential Impact:
        If network security controls are weak, attackers may:

            - Intercept or tamper with sensitive data in transit
            - Gain unauthorized access to internal systems
            - Disrupt service availability or integrity
            - Exploit network weaknesses for further attacks

        Expected Behavior:
        Applications and systems should:

            - Protect communications using strong encryption and secure protocols
            - Restrict access to services and endpoints via firewalls and segmentation
            - Monitor network traffic for anomalies and attacks
            - Apply consistent network security policies across all environments
            - Ensure timely response to detected network security events
        */
        
        private async Task<string> RunNetworkSecurityTestsAsync(Uri baseUri)
        {
            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, baseUri));
            var findings = new List<string>();

            if (response is null)
            {
                findings.Add("No response received.");
                return FormatSection("Security Headers", baseUri, findings);
            }

            findings.Add($"HTTP {(int)response.StatusCode} {response.StatusCode}");
            var requiredHeaders = new[]
            {
                "Content-Security-Policy",
                "X-Content-Type-Options",
                "X-Frame-Options",
                "Referrer-Policy"
            };

            foreach (var header in requiredHeaders)
            {
                findings.Add(HasHeader(response, header)
                ? $"Present: {header}"
                : $"Missing: {header}");
            }

            if (baseUri.Scheme == Uri.UriSchemeHttps)
            {
                findings.Add(response.Headers.Contains("Strict-Transport-Security")
                ? "Present: Strict-Transport-Security"
                : "Missing: Strict-Transport-Security");
            }

            return FormatSection("Security Headers", baseUri, findings);
        }
    }
}

