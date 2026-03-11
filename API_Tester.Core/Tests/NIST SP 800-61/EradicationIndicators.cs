namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Eradication Indicators Tests

        Purpose:
        Performs automated tests to evaluate the application’s ability to 
        identify and support eradication of threats and malicious activity, 
        ensuring that indicators of compromise (IoCs) are properly detected 
        and addressed to prevent recurrence.

        Threat Model:
        Weak eradication capabilities may allow attackers to:

            - Persist within systems after an initial compromise
            - Reintroduce malware or malicious activity
            - Evade detection due to incomplete remediation
            - Exploit residual vulnerabilities or leftover malicious artifacts

        Common vulnerabilities include:

            - Lack of monitoring for indicators of compromise
            - Incomplete removal of malware or malicious configurations
            - Absence of automated or documented eradication procedures
            - Poor coordination between detection, containment, and eradication efforts
            - Inconsistent verification that threats have been fully neutralized

        Test Strategy:
        The method performs automated checks that:

            - Identify residual indicators of compromise in systems or applications
            - Verify that eradication procedures remove malicious artifacts
            - Assess consistency and effectiveness of remediation processes
            - Detect weaknesses in coordination between detection and eradication
            - Examine logging and alerting related to eradication activities

        Potential Impact:
        If eradication controls are weak, attackers may:

            - Maintain persistence within the environment
            - Re-exploit compromised systems
            - Compromise additional data or systems after initial containment
            - Evade monitoring and detection mechanisms

        Expected Behavior:
        Applications should:

            - Identify and track indicators of compromise effectively
            - Apply thorough eradication procedures to remove threats
            - Validate that malicious artifacts are fully eliminated
            - Integrate eradication with detection, containment, and response workflows
            - Maintain consistent and repeatable eradication processes across all systems
        */

        private async Task<string> RunEradicationIndicatorsTestsAsync(Uri baseUri)
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

