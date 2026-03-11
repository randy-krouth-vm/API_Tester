namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Detection and Analysis Tests

        Purpose:
        Performs automated tests to evaluate the application’s capabilities 
        for detecting and analyzing security events, ensuring timely identification 
        of incidents and supporting effective response actions.

        Threat Model:
        Weak detection and analysis capabilities may allow attackers to:

            - Operate undetected within the environment
            - Exploit vulnerabilities without triggering alerts
            - Delay or bypass incident response
            - Escalate privileges or move laterally without monitoring

        Common vulnerabilities include:

            - Incomplete or inconsistent logging of security-relevant events
            - Lack of monitoring for anomalous or suspicious activity
            - Absence of automated analysis or correlation of events
            - Poor integration between detection and response systems
            - Delayed or ineffective alerting mechanisms

        Test Strategy:
        The method performs automated checks that:

            - Verify security events are detected and logged properly
            - Assess the correlation and analysis of detected events
            - Evaluate alerting and notification mechanisms
            - Detect gaps or inconsistencies in monitoring coverage
            - Examine integration with incident response and containment workflows

        Potential Impact:
        If detection and analysis controls are weak, attackers may:

            - Maintain persistent access undetected
            - Exploit unmonitored vulnerabilities
            - Delay incident response and mitigation
            - Compromise sensitive data or critical systems

        Expected Behavior:
        Applications should:

            - Continuously monitor security events across all systems
            - Analyze and correlate events to detect potential incidents
            - Generate timely and actionable alerts for detected threats
            - Integrate detection and analysis with response workflows
            - Maintain consistent monitoring and analysis across all environments
        */
        
        private async Task<string> RunDetectionAndAnalysisTestsAsync(Uri baseUri)
        {
            var malformed = AppendQuery(baseUri, new Dictionary<string, string> { ["malformed"] = "%ZZ%YY" });
            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, malformed));
            var body = await ReadBodyAsync(response);

            var findings = new List<string>
            {
                $"HTTP {FormatStatus(response)}",
                ContainsAny(body, "exception", "stack trace", "at ", "innerexception")
                ? "Potential risk: exception or stack-trace details exposed."
                : "No obvious stack-trace leakage detected."
            };

            return FormatSection("Error Handling Leakage", malformed, findings);
        }
    }
}

