namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Privacy by Design and Default Tests

        Purpose:
        Performs automated tests to evaluate whether the application enforces 
        privacy principles by design and by default, ensuring that user data is 
        handled securely, transparently, and with minimal exposure.

        Threat Model:
        Applications that fail to implement privacy by design and default may:

            - Collect, process, or retain more personal data than necessary
            - Expose sensitive information to unauthorized parties
            - Fail to provide proper user consent or data access controls
            - Increase the risk of regulatory non-compliance

        Common vulnerabilities include:

            - Overcollection of user data without justification
            - Lack of default privacy settings for accounts or services
            - Inadequate user consent mechanisms or visibility into data use
            - Weak protection for sensitive data in storage or transit
            - Sharing data with third parties without proper controls

        Test Strategy:
        The method performs asynchronous automated checks to:

            - Verify that only necessary personal data is collected and stored
            - Confirm default privacy settings are applied correctly
            - Inspect data flows for compliance with privacy principles
            - Evaluate consent and access control mechanisms
            - Detect potential overexposure of user information

        Potential Impact:
        If privacy by design and default controls are weak, attackers or 
        unauthorized parties may:

            - Access personal or sensitive information unnecessarily
            - Exploit overexposed data for identity theft or fraud
            - Compromise user trust and violate privacy regulations
            - Use collected data for unauthorized profiling or targeting

        Expected Behavior:
        Applications should:

            - Minimize collection, processing, and storage of personal data
            - Apply privacy-protective defaults for accounts and services
            - Enforce consent and access controls consistently
            - Protect sensitive information with encryption and access restrictions
            - Monitor and enforce privacy principles across all application components
        */
        
        private async Task<string> RunPrivacyByDesignAndDefaultTestsAsync(Uri baseUri)
        {
            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, baseUri));
            var findings = new List<string>();

            if (response is null)
            {
                findings.Add("No response received.");
                return FormatSection("Security Headers", baseUri, findings);
            }

            findings.Add($"HTTP {(int)response.StatusCode} {response.StatusCode}");
            var requiredHeaders = new[]
            {
                    "Content-Security-Policy",
                    "X-Content-Type-Options",
                    "X-Frame-Options",
                    "Referrer-Policy"
                };

            foreach (var header in requiredHeaders)
            {
                findings.Add(HasHeader(response, header)
                ? $"Present: {header}"
                : $"Missing: {header}");
            }

            if (baseUri.Scheme == Uri.UriSchemeHttps)
            {
                findings.Add(response.Headers.Contains("Strict-Transport-Security")
                ? "Present: Strict-Transport-Security"
                : "Missing: Strict-Transport-Security");
            }

            return FormatSection("Security Headers", baseUri, findings);
        }
    }
}

