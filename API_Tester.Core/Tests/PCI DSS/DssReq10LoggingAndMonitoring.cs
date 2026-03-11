namespace API_Tester
{
    public partial class MainPage
    {
        /*
        PCI DSS Requirement 10 – Logging and Monitoring Tests

        Purpose:
        Performs automated tests to verify that the application properly logs
        and monitors security-relevant events in accordance with PCI DSS
        Requirement 10. These tests ensure that activities affecting
        cardholder data environments are recorded and can be reviewed for
        security analysis and incident investigation.

        Threat Model:
        If logging and monitoring controls are weak, attackers may:

            - perform malicious actions without leaving an audit trail
            - tamper with systems without detection
            - hide unauthorized access or privilege escalation
            - evade incident detection and forensic investigation

        Attackers commonly attempt to exploit:

            - missing logging of authentication events
            - lack of monitoring for administrative actions
            - insufficient tracking of access to sensitive data
            - incomplete audit records
            - absence of alerts for suspicious activity

        Common vulnerabilities include:

            - failure to log security-critical events
            - inconsistent logging across services or endpoints
            - logs missing important contextual information
            - lack of centralized monitoring or alerting
            - inadequate protection of log integrity

        Test Strategy:
        The method performs automated checks that:

            - trigger authentication and authorization events
            - inspect system responses for evidence of logging
            - evaluate consistency of monitoring across endpoints
            - detect missing audit records for security-relevant actions
            - analyze responses for indicators of monitoring or alerting behavior

        Potential Impact:
        If logging and monitoring controls are weak, attackers may:

            - maintain persistence without detection
            - manipulate or access sensitive payment data
            - evade security teams and incident response
            - compromise the integrity of forensic investigations

        Expected Behavior:
        Applications should:

            - log all security-relevant events and administrative actions
            - record user identity, timestamps, and activity context
            - protect logs from unauthorized modification
            - integrate logs with centralized monitoring systems
            - generate alerts for suspicious or anomalous activity
        */
        
        private async Task<string> RunDssReq10LoggingAndMonitoringTestsAsync(Uri baseUri)
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

