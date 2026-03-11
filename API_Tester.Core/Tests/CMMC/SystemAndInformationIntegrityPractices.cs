namespace API_Tester
{
    public partial class MainPage
    {
        /*
        System and Information Integrity Practices Test

        Purpose:
        Evaluates whether the application protects the integrity of system
        operations and data by validating inputs, preventing tampering,
        and ensuring that responses and system state cannot be maliciously
        manipulated.

        Threat Model:
        System and information integrity controls ensure that data processed
        by the application has not been altered, corrupted, or injected with
        malicious content. Weak integrity protections may allow attackers to
        modify requests, responses, or stored data in ways that change system
        behavior.

        Integrity weaknesses often appear when applications:

            - fail to validate user input properly
            - trust client-provided data without verification
            - allow parameter tampering or request manipulation
            - fail to detect altered tokens or identifiers
            - process malformed or unexpected input values

        Example scenario:

            Request:
                POST /api/order
                {
                    "price": 10,
                    "discount": 90
                }

        If the server does not enforce server-side validation rules,
        an attacker could manipulate request parameters to alter pricing
        or business logic.

        Attack scenarios include:

            - modifying request parameters to change system behavior
            - injecting unexpected data structures
            - manipulating identifiers or references
            - altering tokens, IDs, or workflow state values
            - bypassing validation through malformed inputs

        Test Strategy:
        The scanner sends malformed, manipulated, or unexpected inputs to
        observe whether the application enforces validation and integrity
        controls. Responses are analyzed for signs that altered data was
        accepted or processed incorrectly.

        Potential Impact:
        If system integrity protections are weak, attackers may be able to:

            - manipulate business logic
            - corrupt system state
            - bypass validation rules
            - alter stored or transmitted data

        Expected Behavior:
        Applications should validate all inputs server-side, reject malformed
        or unexpected data, verify the integrity of tokens and identifiers,
        and enforce strict validation rules to prevent unauthorized
        modification of system behavior.
        */
        
        private async Task<string> RunSystemAndInformationIntegrityPracticesTestsAsync(Uri baseUri)
        {
            const string jsonBody = "{\"test\":\"value\"}";
            var response = await SafeSendAsync(() =>
            {
                var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
                req.Content = new StringContent(jsonBody, Encoding.UTF8, "text/plain");
                return req;
            });

            var findings = new List<string>
            {
                $"HTTP {FormatStatus(response)}",
                response is not null && (response.StatusCode == HttpStatusCode.UnsupportedMediaType || response.StatusCode == HttpStatusCode.BadRequest)
                    ? "Content-type validation appears enforced."
                    : "Potential risk: invalid content-type may be accepted."
            };

            return FormatSection("Content-Type Validation", baseUri, findings);
        }
    }
}

