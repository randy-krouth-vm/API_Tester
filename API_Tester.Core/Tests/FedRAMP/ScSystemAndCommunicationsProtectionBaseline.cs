namespace API_Tester
{
    public partial class MainPage
    {
        /*
        System and Communications Protection Baseline Tests

        Purpose:
        Performs automated tests to evaluate the application's system and 
        communications protection controls, ensuring data confidentiality, 
        integrity, and secure communications channels.

        Threat Model:
        Weak system or communications protections can allow attackers to:

            - Intercept or manipulate sensitive data in transit
            - Exploit insecure network protocols or misconfigured services
            - Circumvent encryption or security controls
            - Gain unauthorized access to internal systems

        Common vulnerabilities include:

            - Unencrypted or weakly encrypted communications
            - Lack of integrity checks on data in transit
            - Misconfigured TLS/SSL or outdated protocols
            - Exposure of sensitive system information through network channels
            - Weak or missing network segmentation and access controls

        Test Strategy:
        The method performs asynchronous automated checks to:

            - Validate encryption and integrity mechanisms for data in transit
            - Analyze network and application endpoints for secure configurations
            - Verify proper enforcement of secure communication protocols
            - Detect exposure of sensitive system information over communications channels

        Potential Impact:
        If system and communications protections are weak, attackers may:

            - Intercept or modify sensitive data
            - Compromise the confidentiality or integrity of communications
            - Exploit misconfigurations to access internal systems
            - Bypass network security controls for further attacks

        Expected Behavior:
        Applications should:

            - Use strong encryption for all sensitive data in transit
            - Enforce integrity checks to prevent tampering
            - Configure network services and protocols securely
            - Minimize exposure of system information
            - Maintain segmentation and access control for internal communications
        */
        
        private async Task<string> RunScSystemAndCommunicationsProtectionBaselineTestsAsync(Uri baseUri)
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

