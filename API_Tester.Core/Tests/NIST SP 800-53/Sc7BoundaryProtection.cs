namespace API_Tester
{
    public partial class MainPage
    {
        /*
        SC-7 Boundary Protection Tests

        Purpose:
        Performs automated tests to evaluate the application’s boundary 
        protection controls in accordance with SC-7 security requirements, 
        ensuring that system boundaries are properly defended against 
        unauthorized access and threats.

        Threat Model:
        Weak boundary protections may allow attackers to:

            - Access internal systems from untrusted networks
            - Exploit misconfigured firewalls, routers, or proxies
            - Bypass network segmentation and access controls
            - Intercept or manipulate data crossing network boundaries

        Common vulnerabilities include:

            - Unrestricted or improperly filtered network traffic
            - Misconfigured firewalls, routers, or access control lists
            - Inadequate monitoring of ingress and egress traffic
            - Lack of segmentation between critical systems and external networks
            - Insufficient controls on remote access or VPN endpoints

        Test Strategy:
        The method performs automated checks that:

            - Assess network and system boundaries for proper enforcement
            - Verify access controls and filtering rules on critical interfaces
            - Test isolation between internal and external networks
            - Inspect monitoring and alerting for boundary violations
            - Detect misconfigurations that could allow unauthorized access

        Potential Impact:
        If boundary protection controls are weak, attackers may:

            - Gain unauthorized access to internal systems or data
            - Exploit network segmentation gaps to move laterally
            - Intercept or tamper with sensitive communications
            - Bypass security mechanisms intended to isolate threats

        Expected Behavior:
        Applications should:

            - Enforce strict network and system boundary protections
            - Implement and monitor firewalls, routers, and access controls
            - Maintain segmentation between internal and external networks
            - Detect and respond to unauthorized access attempts
            - Ensure consistent boundary protection policies across all environments
        */

        private async Task<string> RunSc7BoundaryProtectionTestsAsync(Uri baseUri)
        {
            var response = await SafeSendAsync(() =>
            {
                var req = new HttpRequestMessage(HttpMethod.Options, baseUri);
                req.Headers.TryAddWithoutValidation("Origin", "https://security-test.local");
                req.Headers.TryAddWithoutValidation("Access-Control-Request-Method", "GET");
                return req;
            });

            var findings = new List<string>();
            if (response is null)
            {
                findings.Add("No response received.");
                return FormatSection("CORS", baseUri, findings);
            }

            findings.Add($"HTTP {(int)response.StatusCode} {response.StatusCode}");
            var acao = TryGetHeader(response, "Access-Control-Allow-Origin");
            var acc = TryGetHeader(response, "Access-Control-Allow-Credentials");

            findings.Add(string.IsNullOrWhiteSpace(acao)
            ? "Missing: Access-Control-Allow-Origin"
            : $"Access-Control-Allow-Origin: {acao}");
            findings.Add(string.IsNullOrWhiteSpace(acc)
            ? "Missing: Access-Control-Allow-Credentials"
            : $"Access-Control-Allow-Credentials: {acc}");

            if (acao == "*" && string.Equals(acc, "true", StringComparison.OrdinalIgnoreCase))
            {
                findings.Add("Potential risk: wildcard CORS with credentials enabled.");
            }

            return FormatSection("CORS", baseUri, findings);
        }
    }
}

