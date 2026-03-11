namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Replay Resistance Tests

        Purpose:
        Performs automated tests to evaluate the application’s resistance to 
        replay attacks, ensuring that authentication and session tokens cannot 
        be reused maliciously to gain unauthorized access or perform actions.

        Threat Model:
        Weak replay resistance may allow attackers to:

            - Reuse intercepted authentication tokens or session IDs
            - Impersonate legitimate users
            - Bypass authentication controls
            - Escalate privileges or access sensitive resources

        Common vulnerabilities include:

            - Tokens or credentials that can be reused without validation
            - Absence of nonces, timestamps, or sequence numbers in requests
            - Lack of server-side verification for one-time use tokens
            - Insufficient session management to prevent replay attacks
            - No mechanisms to detect repeated or duplicate requests

        Test Strategy:
        The method performs automated checks that:

            - Attempt to reuse valid tokens or credentials in subsequent requests
            - Verify that replayed requests are rejected by the server
            - Evaluate enforcement of nonces, timestamps, or other anti-replay mechanisms
            - Detect endpoints or workflows susceptible to replay attacks
            - Assess consistency of replay protection across all services

        Potential Impact:
        If replay resistance controls are weak, attackers may:

            - Gain unauthorized access to accounts or sensitive actions
            - Perform fraudulent transactions or operations
            - Bypass multi-factor or session authentication controls
            - Evade detection and auditing mechanisms

        Expected Behavior:
        Applications should:

            - Implement nonces, timestamps, or sequence numbers to prevent replay
            - Reject reused or expired authentication tokens or requests
            - Maintain secure session management to prevent replay
            - Monitor and log suspicious or repeated request activity
            - Ensure replay resistance is consistently applied across all endpoints
        */
        
        private async Task<string> RunReplayResistanceTestsAsync(Uri baseUri)
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

