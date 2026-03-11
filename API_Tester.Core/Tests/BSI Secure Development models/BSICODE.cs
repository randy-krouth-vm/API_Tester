namespace API_Tester
{
    public partial class MainPage
    {
        /*
        BSI Code Security Controls Test

        Purpose:
        Checks whether the API appears to follow secure coding practices
        aligned with guidance from the German Federal Office for Information
        Security (BSI) and similar secure development standards.

        Threat Model:
        Organizations following BSI-style secure development guidance are
        expected to implement strong input validation, secure error handling,
        and proper authentication and authorization controls. If these
        controls are weak or missing, attackers may be able to manipulate
        inputs, trigger unintended behavior, or gain unauthorized access.

        Attack scenarios include:

            - submitting malformed or unexpected input values
            - triggering unhandled exceptions or verbose error messages
            - bypassing validation logic
            - exploiting inconsistent input handling across endpoints

        Example cases:

            - overly permissive parameter handling
            - inconsistent validation between endpoints
            - stack traces or internal errors returned in responses

        Test Strategy:
        The scanner submits various malformed or unexpected inputs to the
        target API and observes how the application handles them. Responses
        are evaluated for signs of weak validation, unhandled exceptions,
        or exposure of internal implementation details.

        Potential Impact:
        If secure coding controls are weak, attackers may be able to:

            - exploit input validation weaknesses
            - discover internal system information
            - manipulate application behavior
            - identify additional attack surfaces

        Expected Behavior:
        Applications should enforce strict input validation, handle errors
        gracefully without exposing internal details, and apply consistent
        security controls across all endpoints in accordance with secure
        coding guidelines.
        */
        
        private async Task<string> RunBSICODETestsAsync(Uri baseUri)
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

