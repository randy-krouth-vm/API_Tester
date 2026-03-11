namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Data Protection Test

        Purpose:
        Checks whether the application properly protects sensitive data during
        processing, storage, and transmission.

        Threat Model:
        Applications frequently handle sensitive information such as personal
        data, authentication credentials, financial details, and tokens. If
        data protection controls are weak or missing, attackers may be able
        to intercept, expose, or manipulate sensitive information.

        Sensitive data may include:

            - passwords or password hashes
            - personal identifiable information (PII)
            - financial or payment data
            - authentication tokens or session identifiers
            - internal identifiers or account information

        Common weaknesses include:

            - transmitting sensitive data in plaintext
            - exposing sensitive fields in API responses
            - storing credentials or tokens without protection
            - logging sensitive information
            - returning excessive data in API responses

        Example risky response:

        {
            "userId": 123,
            "email": "user@example.com",
            "passwordHash": "$2a$10$..."
        }

        Even hashed credentials or internal identifiers may provide useful
        information to attackers.

        Test Strategy:
        The scanner analyzes API responses and behavior to identify whether
        sensitive fields are unnecessarily exposed or transmitted insecurely.
        It looks for patterns that may indicate credentials, tokens, personal
        data, or protected information being returned to clients.

        Potential Impact:
        If sensitive data is improperly exposed, attackers may be able to:

            - harvest credentials or authentication tokens
            - access personal or financial data
            - perform identity theft or account takeover
            - gain insight into internal system structure

        Expected Behavior:
        Applications should follow data minimization principles and return
        only the data necessary for the client. Sensitive information should
        be protected using encryption, access controls, and secure storage
        mechanisms, and should never be unnecessarily exposed in API responses.
        */
        
        private async Task<string> RunDataProtectionTestsAsync(Uri baseUri)
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

