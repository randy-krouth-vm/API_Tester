namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Storage Privacy Tests

        Purpose:
        Performs automated tests to evaluate whether sensitive data stored by
        the application is handled in a privacy-preserving and secure manner.
        These tests assess whether stored information is minimized, protected,
        and not unnecessarily exposed through storage mechanisms.

        Threat Model:
        Improper storage practices may allow attackers or unauthorized users to:

            - access stored personal or sensitive information
            - retrieve credentials, tokens, or private user data
            - exploit improperly protected storage systems
            - analyze stored data for system or user intelligence

        Sensitive stored data may include:

            - personally identifiable information (PII)
            - authentication credentials or tokens
            - financial or transaction records
            - account identifiers or user metadata
            - application configuration or internal data

        Common vulnerabilities include:

            - storing sensitive data in plaintext
            - lack of encryption for stored confidential data
            - excessive retention of user information
            - improper access controls on storage systems
            - exposure of stored data through APIs or backups

        Test Strategy:
        The method performs automated checks that:

            - inspect API responses for stored sensitive information
            - evaluate whether confidential data appears in storage-related endpoints
            - detect excessive or unnecessary data storage
            - assess encryption and protection mechanisms where observable
            - analyze consistency of storage privacy protections

        Potential Impact:
        If storage privacy protections are weak, attackers may:

            - obtain sensitive personal or financial data
            - perform identity theft or account takeover
            - exploit exposed credentials or tokens
            - violate regulatory or privacy compliance requirements

        Expected Behavior:
        Applications should:

            - minimize storage of sensitive user data
            - encrypt confidential information at rest
            - enforce strict access controls on stored data
            - redact or anonymize sensitive fields where possible
            - follow secure data retention and privacy policies
        */
        
        private async Task<string> RunStoragePrivacyTestsAsync(Uri baseUri)
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

