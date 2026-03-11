namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Technological Controls Tests

        Purpose:
        Performs automated tests to evaluate the application’s technological 
        security controls, ensuring that technical safeguards are properly 
        implemented to protect systems, data, and communications.

        Threat Model:
        Weak technological controls may allow attackers to:

            - Exploit system vulnerabilities or misconfigurations
            - Bypass security mechanisms through technical weaknesses
            - Access sensitive data or services without authorization
            - Interfere with system operations or integrity

        Common vulnerabilities include:

            - Misconfigured servers, services, or applications
            - Weak encryption or insecure protocol usage
            - Insufficient authentication, authorization, or logging
            - Unpatched software or outdated components
            - Poorly implemented security features and safeguards

        Test Strategy:
        The method performs asynchronous automated checks to:

            - Evaluate the configuration and effectiveness of security controls
            - Verify encryption, authentication, and access control mechanisms
            - Inspect system logs and monitoring for proper coverage
            - Detect misconfigurations or deviations from security best practices
            - Ensure consistent enforcement of technological safeguards across systems

        Potential Impact:
        If technological controls are weak, attackers may:

            - Compromise system integrity, availability, or confidentiality
            - Gain unauthorized access to sensitive data or resources
            - Exploit weaknesses to escalate privileges or persist within systems
            - Evade detection and monitoring mechanisms

        Expected Behavior:
        Applications and systems should:

            - Implement and enforce technical security controls consistently
            - Protect data and systems using strong encryption and access controls
            - Maintain updated and patched software components
            - Log and monitor relevant security events
            - Ensure that technological safeguards align with organizational policies and regulatory requirements
        */
        
        private async Task<string> RunTechnologicalControlsTestsAsync(Uri baseUri)
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

