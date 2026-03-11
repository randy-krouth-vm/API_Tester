namespace API_Tester
{
    public partial class MainPage
    {
        /*
        PII Disclosure Prevention Controls Tests

        Purpose:
        Performs automated tests to evaluate the application’s controls for 
        preventing the disclosure of personally identifiable information (PII), 
        ensuring that sensitive personal data is protected against unauthorized 
        access, exposure, or transmission.

        Threat Model:
        Weak PII disclosure prevention controls may allow attackers to:

            - Access or exfiltrate sensitive personal information
            - Exploit exposed PII for identity theft or fraud
            - Circumvent privacy protections and regulatory requirements
            - Gain insight into system structure or sensitive user data

        Common vulnerabilities include:

            - Exposing PII in API responses or logs
            - Storing sensitive information without encryption
            - Insecure transmission of PII across networks
            - Returning excessive or unnecessary personal data
            - Lack of access controls for sensitive data endpoints

        Test Strategy:
        The method performs asynchronous automated checks to:

            - Inspect API responses and logs for exposure of PII
            - Verify encryption and access controls on stored and transmitted data
            - Evaluate adherence to data minimization principles
            - Detect scenarios where PII may be unnecessarily disclosed
            - Assess consistency of privacy and disclosure controls across endpoints

        Potential Impact:
        If PII disclosure prevention controls are weak, attackers may:

            - Harvest personal data for malicious purposes
            - Violate privacy regulations and incur legal or reputational penalties
            - Exploit exposed information for account takeover or fraud
            - Gain unauthorized insight into users or system data

        Expected Behavior:
        Applications should:

            - Protect all PII in transit and at rest using strong encryption
            - Limit exposure of personal data according to necessity
            - Apply strict access controls to sensitive data endpoints
            - Avoid logging or returning sensitive information unnecessarily
            - Ensure consistent enforcement of disclosure prevention controls across the system
        */
        
        private async Task<string> RunPiiDisclosurePreventionControlsTestsAsync(Uri baseUri)
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

