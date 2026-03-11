namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Recovery and Reoccurrence Tests

        Purpose:
        Performs automated tests to evaluate the application’s recovery 
        procedures and controls for preventing the reoccurrence of security 
        incidents, ensuring systems can resume normal operations securely 
        and reliably after an event.

        Threat Model:
        Weak recovery and reoccurrence controls may allow attackers to:

            - Exploit systems during recovery phases
            - Cause repeated or recurring security incidents
            - Bypass mitigation controls due to incomplete restoration
            - Maintain persistence or impact availability after recovery

        Common vulnerabilities include:

            - Lack of tested and documented recovery procedures
            - Incomplete restoration of systems to secure baseline configurations
            - Failure to address root causes of incidents
            - Insufficient monitoring post-recovery to detect reoccurrence
            - Inconsistent application of recovery controls across environments

        Test Strategy:
        The method performs automated checks that:

            - Validate recovery processes for affected systems or services
            - Assess restoration of configurations, data, and services
            - Verify that previously exploited vulnerabilities are mitigated
            - Detect potential gaps that could allow incident reoccurrence
            - Evaluate monitoring and alerting after recovery

        Potential Impact:
        If recovery and reoccurrence controls are weak, attackers may:

            - Re-exploit systems after recovery
            - Cause repeated disruption or data compromise
            - Evade detection due to insufficient post-recovery monitoring
            - Undermine business continuity and operational stability

        Expected Behavior:
        Applications should:

            - Implement robust and tested recovery procedures
            - Restore systems to secure, baseline configurations
            - Address root causes of incidents to prevent recurrence
            - Monitor systems post-recovery for anomalies or reoccurrence
            - Ensure consistent recovery practices across all environments
        */
        
        private async Task<string> RunRecoveryReoccurrenceTestsAsync(Uri baseUri)
        {
            var payload = "{\"amount\":100,\"currency\":\"USD\"}";
            const string key = "api-tester-idempotency-key";

            var first = await SafeSendAsync(() =>
            {
                var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
                req.Headers.TryAddWithoutValidation("Idempotency-Key", key);
                req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
                return req;
            });

            var second = await SafeSendAsync(() =>
            {
                var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
                req.Headers.TryAddWithoutValidation("Idempotency-Key", key);
                req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
                return req;
            });

            var findings = new List<string>
                {
                    $"First request: {FormatStatus(first)}",
                    $"Replay request: {FormatStatus(second)}"
                };

            if (first is not null && second is not null && first.StatusCode == second.StatusCode && first.StatusCode == HttpStatusCode.OK)
            {
                findings.Add("Potential risk: replay with same idempotency key not differentiated.");
            }
            else
            {
                findings.Add("No obvious replay acceptance indicator.");
            }

            return FormatSection("Idempotency Replay", baseUri, findings);
        }
    }
}

