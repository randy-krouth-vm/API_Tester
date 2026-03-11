namespace API_Tester;

public partial class MainPage
{
    /*
    Duplicate HTTP Header Test

    Purpose:
    Checks whether the server correctly handles requests containing duplicate
    HTTP headers.

    Threat Model:
    Some servers, proxies, or application frameworks interpret duplicate
    headers differently. For example, one component may use the first header
    value while another uses the last value or merges them together.

    This inconsistent behavior can allow attackers to bypass security
    controls or manipulate request processing.

    Headers commonly affected include:

        Authorization
        Host
        Content-Length
        X-Forwarded-For
        X-Forwarded-Host
        Cookie

    Test Strategy:
    The scanner sends requests containing duplicate headers with different
    values and observes how the server processes them.

    Potential Impact:
    Improper handling of duplicate headers may allow attackers to:

        - bypass authentication mechanisms
        - spoof client identity information
        - manipulate routing logic
        - trigger request smuggling conditions
        - override security headers

    Expected Behavior:
    Servers should either reject requests containing duplicate headers or
    consistently enforce a single header value according to HTTP standards.
    */
    
    private async Task<string> RunDuplicateHeaderTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
            req.Headers.TryAddWithoutValidation("X-Role", "user");
            req.Headers.TryAddWithoutValidation("X-Role", "admin");
            return req;
        });

        var body = await ReadBodyAsync(response);
        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            body.Contains("admin", StringComparison.OrdinalIgnoreCase)
            ? "Potential risk: duplicate header handling may allow privilege override."
            : "No obvious duplicate-header privilege indicator."
        };

        return FormatSection("Duplicate Header Handling", baseUri, findings);
    }

}

