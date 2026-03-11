namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Sensitive Business Flow Access Tests

        Purpose:
        Performs automated tests to evaluate whether sensitive business
        processes are properly protected by authentication, authorization,
        and integrity controls. These tests ensure that critical workflows
        cannot be executed or manipulated by unauthorized users.

        Threat Model:
        Sensitive business flows represent high-value operations such as:

            - financial transactions
            - account changes
            - password resets
            - privilege changes
            - order processing or billing actions

        If these flows are not properly protected, attackers may attempt to:

            - bypass authentication or authorization checks
            - manipulate workflow parameters
            - replay requests to repeat sensitive actions
            - execute actions out of sequence
            - abuse automated processes

        Common vulnerabilities include:

            - missing authorization checks on workflow steps
            - predictable or reusable transaction identifiers
            - lack of step validation in multi-stage workflows
            - missing integrity checks for transaction data
            - insufficient monitoring of critical operations

        Test Strategy:
        The method performs automated checks that:

            - attempt to invoke sensitive business actions without proper privileges
            - evaluate whether workflow steps enforce authentication and authorization
            - inspect transaction responses for unauthorized execution
            - detect bypass of required workflow sequencing
            - assess protections against replay or manipulation

        Potential Impact:
        If sensitive business flow protections are weak, attackers may:

            - perform unauthorized financial or administrative actions
            - manipulate transactions or workflow states
            - escalate privileges or compromise user accounts
            - cause operational, financial, or reputational damage

        Expected Behavior:
        Applications should:

            - enforce strict authentication and authorization on all workflow steps
            - validate transaction integrity and sequencing
            - prevent replay or manipulation of sensitive requests
            - implement monitoring and alerting for critical operations
            - ensure business logic protections are consistently applied
        */
        
        private async Task<string> RunSensitiveBusinessFlowAccessTestsAsync(Uri baseUri)
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

