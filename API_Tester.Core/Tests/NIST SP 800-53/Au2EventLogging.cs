namespace API_Tester
{
    public partial class MainPage
    {
        /*
        AU-2 Event Logging Tests

        Purpose:
        Performs a malformed-request probe to evaluate whether error handling
        and logging paths expose internal exception details in responses.

        Threat Model:
        When APIs encounter invalid input, weak error handling may leak
        implementation details that help attackers map internals and tune
        follow-on attacks.

        Common vulnerabilities include:

            - Returning stack traces or exception type names to clients
            - Exposing framework/runtime internals in error payloads
            - Inconsistent sanitization of malformed-input failures
            - Logging-sensitive diagnostics being reflected to the caller

        Test Strategy:
        The method sends a request with malformed query encoding and inspects
        the returned body for exception/stack-trace indicators such as
        "exception", "stack trace", "at ", and "innerexception".

        Potential Impact:
        If internal error details are exposed, attackers may:

            - Identify platform/framework components and versions
            - Infer code paths and validation boundaries
            - Improve exploit reliability for other vulnerabilities
            - Increase overall reconnaissance effectiveness

        Expected Behavior:
        The API should fail safely on malformed input, returning sanitized
        error responses without stack traces or internal exception context.
        */
        
        private async Task<string> RunAu2EventLoggingTestsAsync(Uri baseUri)
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

