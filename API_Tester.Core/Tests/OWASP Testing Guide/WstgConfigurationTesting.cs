namespace API_Tester
{
    public partial class MainPage
    {
        /*
        WSTG Configuration Testing Tests

        Purpose:
        Performs automated tests aligned with the OWASP Web Security Testing Guide
        (WSTG) to evaluate whether the application and its supporting infrastructure
        are securely configured. These tests help identify insecure settings,
        exposed services, or misconfigured components.

        Threat Model:
        Misconfigured systems may allow attackers to:

            - access administrative or debugging interfaces
            - retrieve sensitive configuration files
            - exploit exposed services or default settings
            - gain insight into internal system architecture

        Attackers commonly probe for:

            - exposed configuration or backup files
            - directory listings or server metadata
            - default credentials or test accounts
            - verbose error messages revealing configuration details
            - unnecessary services or ports exposed to the network

        Common vulnerabilities include:

            - default or insecure configuration settings
            - exposed administrative interfaces
            - unnecessary services enabled in production
            - improper file permissions or directory exposure
            - insufficient hardening of frameworks or servers

        Test Strategy:
        The method performs automated checks that:

            - probe for exposed configuration files and directories
            - inspect server responses for configuration metadata
            - analyze error responses for system information leakage
            - detect unnecessary or exposed services
            - evaluate consistency of security configuration across endpoints

        Potential Impact:
        If configuration controls are weak, attackers may:

            - discover exploitable system details
            - gain unauthorized administrative access
            - exploit insecure or default configurations
            - compromise system integrity or confidentiality

        Expected Behavior:
        Applications and infrastructure should:

            - follow secure configuration baselines
            - disable unnecessary services and debug features
            - restrict access to administrative interfaces
            - protect configuration files and directories
            - regularly review and harden system configurations
        */
        
        private async Task<string> RunWstgConfigurationTestingTestsAsync(Uri baseUri)
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

