namespace API_Tester;

public partial class MainPage
{
    /*
    HTTP Method Enumeration Test

    Purpose:
    Checks which HTTP methods (verbs) are supported by the target endpoint
    and whether unexpected or unsafe methods are enabled.

    Threat Model:
    Web servers and APIs may support multiple HTTP methods such as:

        GET
        POST
        PUT
        PATCH
        DELETE
        OPTIONS
        HEAD
        TRACE
        CONNECT

    If unnecessary methods are enabled, attackers may use them to discover
    hidden functionality or bypass security controls.

    Some methods may expose additional attack surface or allow unintended
    actions if not properly restricted.

    Attack scenarios include:

        - discovering undocumented API capabilities
        - abusing enabled methods that bypass access controls
        - exploiting rarely used methods like TRACE
        - interacting with resources using methods the application
        did not intend to expose

    Example:

        Endpoint expected:
            GET /api/users

        Server also allows:
            PUT /api/users
            DELETE /api/users

    If authorization or validation is weaker for those methods,
    attackers may manipulate resources unexpectedly.

    Test Strategy:
    The scanner sends requests using various HTTP methods to determine
    which ones are accepted by the server and observes the responses
    or Allow headers returned.

    Potential Impact:
    If unsafe or unnecessary methods are enabled, attackers may be able to:

        - discover hidden functionality
        - bypass application logic
        - manipulate resources unexpectedly
        - exploit server features such as TRACE

    Expected Behavior:
    Servers should allow only the HTTP methods required for the
    application’s functionality and reject all others with appropriate
    status codes such as 405 Method Not Allowed.
    */
    
    private async Task<string> RunHttpMethodTestsAsync(Uri baseUri)
    {
        var findings = new List<string>();

        var options = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Options, baseUri));
        if (options is not null)
        {
            findings.Add($"OPTIONS: {(int)options.StatusCode} {options.StatusCode}");
            var allow = TryGetHeader(options, "Allow");
            if (!string.IsNullOrWhiteSpace(allow))
            {
                findings.Add($"Allow: {allow}");
            }
        }
        else
        {
            findings.Add("OPTIONS: no response");
        }

        var trace = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Trace, baseUri));
        if (trace is not null)
        {
            findings.Add($"TRACE: {(int)trace.StatusCode} {trace.StatusCode}");
            if (trace.StatusCode != HttpStatusCode.MethodNotAllowed &&
            trace.StatusCode != HttpStatusCode.NotFound)
            {
                findings.Add("Potential risk: TRACE method appears enabled.");
            }
        }
        else
        {
            findings.Add("TRACE: no response");
        }

        return FormatSection("HTTP Methods", baseUri, findings);
    }

}

