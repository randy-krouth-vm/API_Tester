namespace API_Tester
{
    public partial class MainPage
    {
        /*
        FFIEC CAT Logging and Monitoring Controls Tests

        Purpose:
        Performs automated tests to evaluate logging and monitoring controls 
        in accordance with FFIEC Cybersecurity Assessment Tool (CAT) guidelines, 
        ensuring that security-relevant events are properly captured, monitored, 
        and actionable.

        Threat Model:
        Insufficient logging or monitoring can allow attackers to:

            - Conduct malicious activities undetected
            - Modify or delete logs to hide their actions
            - Maintain persistence within the system
            - Evade detection and incident response mechanisms

        Common vulnerabilities include:

            - Missing or incomplete logging of critical events
            - Lack of correlation between events and alerts
            - Unprotected or tamperable logs
            - Inconsistent monitoring across systems or services

        Test Strategy:
        The method performs asynchronous automated checks to:

            - Trigger security-relevant events and inspect logs
            - Validate completeness, accuracy, and timestamping of log entries
            - Ensure logs include user and system context
            - Verify secure storage and integrity of log data
            - Confirm that monitoring and alerting mechanisms are operational

        Potential Impact:
        If logging and monitoring controls are weak, attackers may:

            - Conduct unauthorized activities without detection
            - Erase or alter evidence of malicious activity
            - Evade incident response and forensic investigations
            - Compromise regulatory or compliance requirements

        Expected Behavior:
        Applications should:

            - Log all critical security and operational events
            - Include sufficient context (timestamps, user IDs, event details)
            - Protect logs against unauthorized modification or deletion
            - Ensure consistent logging and monitoring across all systems
            - Support alerting and investigation processes for detected anomalies
        */
        
        private async Task<string> RunFfiecLoggingAndMonitoringControlsTestsAsync(Uri baseUri)
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

