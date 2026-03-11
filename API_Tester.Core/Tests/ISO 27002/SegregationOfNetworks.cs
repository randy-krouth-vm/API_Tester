namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Segregation of Networks Tests

        Purpose:
        Performs automated tests to evaluate network segregation and 
        segmentation controls, ensuring that systems, applications, and 
        sensitive data are isolated appropriately to prevent unauthorized 
        access and lateral movement.

        Threat Model:
        Weak or absent network segregation may allow attackers to:

            - Move laterally within internal networks
            - Access sensitive systems or data without authorization
            - Exploit misconfigured network boundaries or trust assumptions
            - Bypass security controls intended to contain threats

        Common vulnerabilities include:

            - Flat networks without segmentation between critical systems
            - Insufficient firewall or access control rules between network zones
            - Exposed services in sensitive network segments
            - Misconfigured routing or VLANs
            - Lack of monitoring for cross-segment traffic

        Test Strategy:
        The method performs asynchronous automated checks to:

            - Evaluate network segmentation and access control enforcement
            - Identify potential paths for unauthorized lateral movement
            - Test isolation of sensitive systems or environments
            - Inspect network policies for consistency and completeness
            - Detect misconfigurations or overly permissive connections

        Potential Impact:
        If network segregation is weak, attackers may:

            - Gain access to sensitive systems or data across network segments
            - Escalate privileges or move undetected within the network
            - Exploit internal network trust relationships
            - Circumvent controls designed to limit the impact of a breach

        Expected Behavior:
        Applications and systems should:

            - Enforce strict network segmentation for critical systems and data
            - Apply access control and firewall policies between segments
            - Monitor cross-segment traffic for anomalies
            - Restrict lateral movement opportunities for unauthorized users
            - Maintain consistent enforcement of network segregation policies
        */
        
        private async Task<string> RunSegregationOfNetworksTestsAsync(Uri baseUri)
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

