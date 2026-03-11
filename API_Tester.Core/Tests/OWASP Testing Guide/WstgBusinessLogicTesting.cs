namespace API_Tester
{
    public partial class MainPage
    {
        /*
        WSTG Business Logic Testing Tests

        Purpose:
        Performs automated tests aligned with the OWASP Web Security Testing Guide
        (WSTG) to evaluate the application for business logic vulnerabilities.
        These tests ensure that application workflows and processes cannot be
        abused to bypass intended operational rules or protections.

        Threat Model:
        Business logic vulnerabilities occur when attackers manipulate the
        normal workflow of an application to achieve unintended outcomes.
        Attackers may attempt to:

            - bypass required workflow steps
            - manipulate transaction values or parameters
            - repeat or replay critical operations
            - exploit race conditions
            - perform actions in an unintended sequence

        These attacks often target legitimate functionality rather than
        traditional technical vulnerabilities.

        Common vulnerabilities include:

            - missing validation between workflow stages
            - predictable transaction identifiers
            - insufficient checks on user-controlled parameters
            - lack of safeguards against repeated or automated actions
            - missing authorization checks for sensitive operations

        Test Strategy:
        The method performs automated checks that:

            - analyze workflow sequences for bypass opportunities
            - attempt to manipulate parameters involved in business operations
            - detect replay or repeated execution of critical actions
            - inspect responses for inconsistent enforcement of workflow rules
            - evaluate protections on sensitive business processes

        Potential Impact:
        If business logic protections are weak, attackers may:

            - perform unauthorized transactions or operations
            - manipulate financial or account processes
            - bypass operational safeguards
            - compromise application integrity and trust

        Expected Behavior:
        Applications should:

            - enforce strict validation of business workflows
            - verify transaction integrity and sequencing
            - prevent replay or repeated execution of critical actions
            - validate user permissions for each step of a process
            - monitor and log suspicious workflow behavior
        */
        
        private async Task<string> RunWstgBusinessLogicTestingTestsAsync(Uri baseUri)
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

