namespace API_Tester;

public partial class MainPage
{
    /*
    Error Handling and Information Leakage Tests

    Purpose:
    Performs automated tests to evaluate how the application handles 
    errors and whether error messages inadvertently leak sensitive 
    information about the system, environment, or data.

    Threat Model:
    Poor error handling can provide attackers with insights that may be 
    exploited to compromise the system, including:

        - Stack traces revealing internal code structure
        - Detailed database or file system errors
        - Configuration or environment information
        - Debugging information exposed to users or attackers

    Common vulnerabilities include:

        - Returning raw exception messages to clients
        - Disclosing database queries or schema details
        - Logging sensitive information in responses
        - Inconsistent error handling across endpoints

    Test Strategy:
    The method performs asynchronous automated checks to:

        - Trigger common error conditions in the application
        - Inspect error messages in HTTP responses
        - Identify sensitive information exposed via logs or responses
        - Verify that proper generic error messages are returned to clients

    Potential Impact:
    If error handling is weak, attackers may be able to:

        - Gather information useful for further attacks
        - Identify vulnerabilities such as SQL injection or file access
        - Exploit misconfigured services or endpoints
        - Circumvent security controls based on leaked details

    Expected Behavior:
    Applications should:

        - Return generic error messages to clients
        - Log detailed errors securely on the server only
        - Avoid exposing stack traces, database details, or sensitive info
        - Maintain consistent error handling across all endpoints
    */
    
    private async Task<string> RunErrorHandlingLeakageTestsAsync(Uri baseUri)
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

