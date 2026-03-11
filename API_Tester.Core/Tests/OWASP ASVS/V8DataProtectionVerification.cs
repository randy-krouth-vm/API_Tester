namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Data Protection Verification Tests (V8)

        Purpose:
        Performs automated tests to verify that the application properly
        protects sensitive data during processing, storage, and transmission.
        These tests evaluate whether confidentiality controls are applied
        consistently to sensitive information handled by the system.

        Threat Model:
        Weak data protection controls may allow attackers to:

            - intercept sensitive data during transmission
            - retrieve confidential information from API responses
            - access unprotected personal or financial data
            - exploit insufficient encryption or masking mechanisms

        Sensitive data may include:

            - personally identifiable information (PII)
            - authentication credentials or tokens
            - financial or payment data
            - account identifiers or internal system identifiers
            - confidential business information

        Common vulnerabilities include:

            - transmitting sensitive data over insecure channels
            - exposing sensitive fields in API responses
            - storing confidential data without encryption
            - insufficient masking or redaction of sensitive information
            - inadequate access controls protecting protected data

        Test Strategy:
        The method performs automated checks that:

            - inspect API responses for exposed sensitive fields
            - verify secure transport mechanisms for sensitive data
            - detect improper handling of credentials or tokens
            - evaluate masking or redaction of confidential information
            - assess consistency of protection across endpoints

        Potential Impact:
        If data protection controls are weak, attackers may:

            - access confidential user or business information
            - perform identity theft or account takeover
            - exploit exposed credentials or authentication tokens
            - cause regulatory or compliance violations

        Expected Behavior:
        Applications should:

            - minimize exposure of sensitive data in responses
            - protect sensitive information using strong encryption
            - restrict access to confidential data
            - mask or redact sensitive fields when possible
            - consistently apply data protection policies across the system
        */
        
        private async Task<string> RunV8DataProtectionVerificationTestsAsync(Uri baseUri)
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

