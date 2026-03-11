namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Secrets and Metadata Exposure Tests

        Purpose:
        Performs automated tests to evaluate whether sensitive secrets or
        metadata endpoints are exposed to unauthorized users through the
        application or its underlying infrastructure.

        Threat Model:
        Exposed secrets or metadata services may allow attackers to:

            - Retrieve API keys, tokens, or credentials
            - Access cloud instance metadata (e.g., AWS, Azure, GCP)
            - Discover internal configuration details
            - Escalate privileges using exposed service credentials

        Common vulnerabilities include:

            - Public access to environment configuration endpoints
            - Exposure of cloud metadata services (e.g., 169.254.169.254)
            - Secrets embedded in API responses or debug outputs
            - Insecure storage or transmission of credentials
            - Misconfigured services exposing internal configuration data

        Test Strategy:
        The method performs automated checks that:

            - Probe common metadata and secrets-related endpoints
            - Inspect responses for credential patterns or sensitive values
            - Detect exposure of cloud metadata services
            - Evaluate access controls protecting configuration and secret data
            - Identify endpoints returning sensitive environment information

        Potential Impact:
        If secrets or metadata endpoints are exposed, attackers may:

            - Obtain credentials or API keys
            - Access cloud infrastructure resources
            - Escalate privileges within the environment
            - Compromise application or infrastructure security

        Expected Behavior:
        Applications and infrastructure should:

            - Restrict access to metadata services
            - Protect secrets using secure secret management systems
            - Avoid exposing credentials in responses or logs
            - Enforce strong access controls for configuration endpoints
            - Monitor and alert on unauthorized access attempts
        */
        private async Task<string> RunSecretsMetadataExposureTestsAsync(Uri baseUri)
        {
            var findings = new List<string>();
            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, baseUri));

            if (response is null)
            {
                findings.Add("No response received.");
                return FormatSection("Information Disclosure", baseUri, findings);
            }

            findings.Add($"HTTP {(int)response.StatusCode} {response.StatusCode}");
            var disclosureHeaders = new[] { "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version" };

            foreach (var header in disclosureHeaders)
            {
                var value = TryGetHeader(response, header);
                findings.Add(string.IsNullOrWhiteSpace(value)
                ? $"Not exposed: {header}"
                : $"Potential disclosure: {header}={value}");
            }

            return FormatSection("Information Disclosure", baseUri, findings);
        }
    }
}

