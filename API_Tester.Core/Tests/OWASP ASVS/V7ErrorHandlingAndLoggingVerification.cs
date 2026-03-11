namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Error Handling and Logging Verification Tests (V7)

        Purpose:
        Performs automated tests to verify that the application properly handles
        errors and logs security-relevant events without exposing sensitive
        information. These tests ensure that error responses are safe for clients
        while internal logs retain sufficient detail for monitoring and auditing.

        Threat Model:
        Improper error handling or logging may allow attackers to:

            - obtain internal system information from verbose error messages
            - discover stack traces, file paths, or framework details
            - extract sensitive data from logs or responses
            - evade detection if critical events are not logged

        Attackers commonly attempt to trigger:

            - unhandled exceptions
            - malformed requests
            - invalid authentication attempts
            - unexpected input or edge cases

        Common vulnerabilities include:

            - verbose error messages revealing stack traces or internal paths
            - exposure of configuration details or environment variables
            - logging of sensitive data such as passwords or tokens
            - missing logs for security-relevant events
            - inconsistent error handling across endpoints

        Test Strategy:
        The method performs automated checks that:

            - submit malformed or unexpected inputs to trigger errors
            - inspect responses for sensitive system details
            - verify that errors return generic client-safe messages
            - evaluate consistency of error handling across endpoints
            - detect logging of sensitive information in responses

        Potential Impact:
        If error handling and logging controls are weak, attackers may:

            - gain insight into application architecture
            - identify exploitable vulnerabilities
            - extract sensitive operational data
            - bypass detection due to insufficient logging

        Expected Behavior:
        Applications should:

            - return generic error messages to clients
            - avoid exposing stack traces or internal details
            - log security-relevant events internally
            - prevent sensitive data from appearing in logs
            - ensure consistent error handling across all endpoints
        */
        
        private async Task<string> RunV7ErrorHandlingAndLoggingVerificationTestsAsync(Uri baseUri)
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

