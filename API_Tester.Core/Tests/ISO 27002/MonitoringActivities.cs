namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Monitoring Activities Tests

        Purpose:
        Performs automated tests to evaluate the effectiveness of the 
        application’s monitoring activities, ensuring that security events 
        are detected, logged, and analyzed in a timely and actionable manner.

        Threat Model:
        Weak monitoring controls may allow attackers or malicious insiders to:

            - Operate undetected within the system
            - Escalate privileges or exfiltrate data without triggering alerts
            - Exploit gaps in event detection and response
            - Maintain persistent access due to insufficient oversight

        Common vulnerabilities include:

            - Incomplete or inconsistent monitoring coverage across endpoints
            - Missing or ineffective alerting mechanisms
            - Insufficient logging of critical security events
            - Lack of correlation or analysis of security events
            - Delayed or absent response to detected anomalies

        Test Strategy:
        The method performs asynchronous automated checks to:

            - Verify that all critical activities and events are being logged
            - Assess the completeness, accuracy, and timeliness of monitoring
            - Inspect alerting and notification mechanisms for effectiveness
            - Detect gaps or inconsistencies in monitoring coverage
            - Evaluate event correlation and anomaly detection capabilities

        Potential Impact:
        If monitoring activities are insufficient, attackers may:

            - Conduct malicious actions without detection
            - Evade incident response processes
            - Exploit system weaknesses undetected
            - Compromise system integrity, confidentiality, or availability

        Expected Behavior:
        Applications should:

            - Continuously monitor critical activities and system events
            - Generate accurate and actionable alerts for anomalous behavior
            - Correlate events to identify potential security incidents
            - Protect logs and monitoring data from tampering
            - Ensure timely response to detected security events
        */
        
        private async Task<string> RunMonitoringActivitiesTestsAsync(Uri baseUri)
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

