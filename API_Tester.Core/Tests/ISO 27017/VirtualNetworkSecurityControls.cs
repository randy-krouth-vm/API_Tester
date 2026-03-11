namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Virtual Network Security Controls Tests

        Purpose:
        Performs automated tests to evaluate the security controls of virtual 
        networks, ensuring that cloud or virtualized network environments are 
        properly configured to protect resources, data, and communications.

        Threat Model:
        Weak virtual network security may allow attackers to:

            - Access internal systems or sensitive data via misconfigured VNets
            - Exploit insecure network boundaries or routing rules
            - Bypass segmentation or firewall protections
            - Perform lateral movement within cloud or virtualized environments

        Common vulnerabilities include:

            - Overly permissive security group or firewall rules
            - Misconfigured network peering or routing
            - Lack of network isolation between critical resources
            - Inconsistent application of security policies across VNets
            - Absence of monitoring for cross-VNet traffic anomalies

        Test Strategy:
        The method performs asynchronous automated checks to:

            - Assess virtual network segmentation and isolation
            - Verify firewall and security group configurations
            - Identify exposed services or misconfigured endpoints
            - Test enforcement of access controls between VNets
            - Inspect monitoring and alerting for virtual network traffic

        Potential Impact:
        If virtual network controls are weak, attackers may:

            - Gain unauthorized access to sensitive resources
            - Move laterally within the virtual network environment
            - Exploit misconfigurations to bypass security controls
            - Intercept or tamper with data transmitted between VNets

        Expected Behavior:
        Applications and systems should:

            - Enforce network segmentation and isolation within VNets
            - Apply strict security group and firewall rules
            - Monitor network traffic and detect anomalies
            - Restrict lateral movement and access to critical resources
            - Consistently enforce virtual network security policies across environments
        */
        
        private async Task<string> RunVirtualNetworkSecurityControlsTestsAsync(Uri baseUri)
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

