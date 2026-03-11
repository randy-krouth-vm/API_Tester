namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Secrets Protection Test

        Purpose:
        Checks whether sensitive secrets such as API keys, tokens, credentials,
        or configuration values are exposed through API responses, error
        messages, headers, or publicly accessible endpoints.

        Threat Model:
        Applications often rely on secrets to authenticate with internal
        services, third-party APIs, or infrastructure components. If these
        secrets are accidentally exposed, attackers may gain unauthorized
        access to systems or resources.

        Common examples of secrets include:

            - API keys
            - access tokens or bearer tokens
            - database connection strings
            - private cryptographic keys
            - cloud service credentials
            - environment variables containing secrets

        Attack scenarios include:

            - secrets embedded in API responses or debug output
            - configuration files exposed through endpoints
            - error messages revealing credentials or connection strings
            - accidentally committed or returned environment variables

        Example risky output:

            {
                "database": "Server=db.internal;User=admin;Password=secret123"
            }

        Such responses expose credentials that attackers could reuse.

        Test Strategy:
        The scanner analyzes API responses and error messages for patterns
        commonly associated with secrets such as API keys, tokens, passwords,
        or connection strings.

        Potential Impact:
        If secrets are exposed, attackers may be able to:

            - access internal systems or databases
            - authenticate as the application to third-party services
            - escalate privileges within the infrastructure
            - compromise additional services connected to the system

        Expected Behavior:
        Applications should never expose secrets in responses, logs, or
        public endpoints. Secrets should be stored securely using dedicated
        secret management systems or protected environment variables and
        should not be returned to clients.
        */
        
        private async Task<string> RunSecretsProtectionTestsAsync(Uri baseUri)
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

