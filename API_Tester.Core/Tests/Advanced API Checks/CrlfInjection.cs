namespace API_Tester;

public partial class MainPage
{
    /*
    CRLF Injection Test

    Purpose:
    Checks whether the application properly sanitizes carriage return (CR)
    and line feed (LF) characters in user-controlled input that may be
    included in HTTP headers or response content.

    Threat Model:
    CRLF injection occurs when attackers insert newline characters into
    inputs that are later used to construct HTTP responses. If not properly
    sanitized, these characters can terminate existing headers and inject
    new ones.

    Typical CRLF characters include:

        %0D  (carriage return)
        %0A  (line feed)

    Test Strategy:
    The scanner sends requests containing encoded CRLF sequences in
    parameters, paths, or headers and observes whether the server response
    contains injected headers or altered response structures.

    Potential Impact:
    If CRLF injection is possible, attackers may perform:

        - HTTP response splitting
        - cache poisoning
        - header injection
        - cross-site scripting (XSS) via injected headers
        - manipulation of redirect responses

    Expected Behavior:
    Applications should sanitize or reject inputs containing CRLF
    characters and ensure user-controlled data cannot modify HTTP
    response headers.
    */
    
    private async Task<string> RunCrlfInjectionTestsAsync(Uri baseUri)
    {
        var payload = "normal%0d%0aX-Injected-Header: api-tester";
        var testUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["redirect"] = payload
        });

        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, testUri));
        var body = await ReadBodyAsync(response);
        var location = response is null ? string.Empty : TryGetHeader(response, "Location");

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            location.Contains("X-Injected-Header", StringComparison.OrdinalIgnoreCase) ||
            body.Contains("X-Injected-Header", StringComparison.OrdinalIgnoreCase)
            ? "Potential risk: CRLF payload appears reflected unsafely."
            : "No obvious CRLF reflection indicator."
        };

        return FormatSection("CRLF Injection", testUri, findings);
    }

}

