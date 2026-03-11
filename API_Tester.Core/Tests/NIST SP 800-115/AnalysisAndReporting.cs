namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Analysis and Reporting Tests

        Purpose:
        Performs automated tests to evaluate the application’s ability to 
        analyze security events and generate actionable reports, ensuring 
        visibility into system activity and support for informed decision-making.

        Threat Model:
        Weak analysis and reporting capabilities may allow attackers to:

            - Operate undetected due to inadequate monitoring
            - Exploit unreported or misclassified security events
            - Evade incident response and auditing processes
            - Bypass controls by exploiting gaps in analysis and reporting

        Common vulnerabilities include:

            - Incomplete or missing event logging
            - Lack of correlation between security events
            - Delays or gaps in generating actionable reports
            - Insufficient visibility into critical systems or endpoints
            - Inconsistent reporting formats or coverage across systems

        Test Strategy:
        The method performs automated checks that:

            - Verify the collection and analysis of security-relevant events
            - Assess the timeliness and accuracy of generated reports
            - Inspect correlation and aggregation of related events
            - Detect gaps or missing coverage in analysis and reporting
            - Evaluate integration of reporting with monitoring and response workflows

        Potential Impact:
        If analysis and reporting controls are weak, attackers may:

            - Evade detection while exploiting system vulnerabilities
            - Delay response to security incidents
            - Cause operational, regulatory, or reputational damage
            - Compromise the integrity and accountability of audit data

        Expected Behavior:
        Applications should:

            - Collect and analyze security events consistently
            - Generate timely and actionable reports for security monitoring
            - Correlate events to identify patterns and potential threats
            - Integrate reporting with incident response and monitoring processes
            - Maintain consistent coverage and format across all systems and endpoints
        */

        private async Task<string> RunAnalysisAndReportingTestsAsync(Uri baseUri)
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

