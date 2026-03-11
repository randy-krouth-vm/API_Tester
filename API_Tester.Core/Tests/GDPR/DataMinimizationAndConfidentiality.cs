namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Data Minimization and Confidentiality Tests

        Purpose:
        Performs automated tests to evaluate the application’s handling of 
        sensitive data, ensuring that only necessary information is collected, 
        processed, and transmitted, and that confidentiality is maintained.

        Threat Model:
        Applications that fail to enforce data minimization or confidentiality 
        principles may expose sensitive information to attackers, including:

            - Personal Identifiable Information (PII)
            - Authentication credentials or tokens
            - Financial or payment data
            - Internal system identifiers or configuration details

        Common vulnerabilities include:

            - Returning excessive or unnecessary data in API responses
            - Logging sensitive information insecurely
            - Transmitting sensitive data in plaintext or weakly encrypted channels
            - Storing sensitive information without proper protection
            - Exposing internal identifiers or system details to clients

        Test Strategy:
        The method performs asynchronous automated checks to:

            - Inspect API responses for unnecessary exposure of sensitive data
            - Validate secure storage and transmission of confidential information
            - Detect logging or output of sensitive fields
            - Ensure adherence to data minimization principles across endpoints

        Potential Impact:
        If data minimization or confidentiality controls are weak, attackers may:

            - Harvest credentials, tokens, or sensitive user data
            - Gain insight into internal system structure
            - Perform identity theft or account takeover
            - Exploit exposed data to launch further attacks

        Expected Behavior:
        Applications should:

            - Collect, process, and transmit only the data required for functionality
            - Protect sensitive data in transit and at rest using strong encryption
            - Avoid logging sensitive information unnecessarily
            - Limit exposure of internal identifiers or confidential fields
            - Ensure all endpoints enforce data minimization and confidentiality consistently
        */
        
        private async Task<string> RunDataMinimizationAndConfidentialityTestsAsync(Uri baseUri)
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

