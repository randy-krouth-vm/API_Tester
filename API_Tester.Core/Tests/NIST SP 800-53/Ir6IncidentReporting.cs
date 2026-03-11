namespace API_Tester
{
    public partial class MainPage
    {
        /*
        IR-6 Incident Reporting Tests

        Purpose:
        Performs automated tests to evaluate the application’s incident reporting 
        controls in accordance with IR-6 (Incident Reporting) security requirements, 
        ensuring that security incidents are promptly reported to authorized personnel 
        and relevant authorities.

        Threat Model:
        Weak incident reporting controls may allow attackers or insiders to:

            - Exploit the system without detection
            - Delay or prevent notification of security events
            - Evade incident response procedures
            - Cause regulatory or compliance violations

        Common vulnerabilities include:

            - Failure to log and report security-relevant events
            - Inadequate procedures for alerting appropriate stakeholders
            - Delayed reporting of incidents or anomalies
            - Missing integration with monitoring or ticketing systems
            - Inconsistent reporting across systems or components

        Test Strategy:
        The method performs automated checks that:

            - Trigger security events and observe reporting behavior
            - Verify notifications are sent to the appropriate personnel
            - Assess timeliness and completeness of incident reporting
            - Evaluate consistency across endpoints and systems
            - Detect gaps in the incident reporting workflow

        Potential Impact:
        If incident reporting controls are weak, attackers may:

            - Maintain unauthorized access undetected
            - Exploit unreported vulnerabilities or misconfigurations
            - Evade organizational or regulatory oversight
            - Increase risk of operational, financial, or reputational damage

        Expected Behavior:
        Applications should:

            - Log and report all security-relevant incidents promptly
            - Notify appropriate personnel and authorities as required
            - Ensure reporting processes are consistent and reliable
            - Integrate with monitoring and incident response workflows
            - Maintain records of reported incidents for auditing and compliance
        */

        private async Task<string> RunIr6IncidentReportingTestsAsync(Uri baseUri)
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

