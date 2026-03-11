namespace API_Tester;

public partial class MainPage
{
    /*
    Dual Content-Length Header Test

    Purpose:
    Checks whether the server properly handles requests containing multiple
    Content-Length headers.

    Threat Model:
    According to HTTP specifications, a request should contain only a single
    Content-Length header. If multiple Content-Length headers are present
    and interpreted differently by front-end and back-end servers, this may
    lead to HTTP request smuggling vulnerabilities.

    Request smuggling occurs when different components of the request
    processing chain (such as load balancers, proxies, or application
    servers) parse the request inconsistently. One server may use the first
    Content-Length value while another uses the second.

    Test Strategy:
    The scanner sends requests containing duplicate Content-Length headers
    with conflicting values and observes how the server processes them.

    Potential Impact:
    If inconsistent parsing occurs, attackers may be able to:

        - smuggle hidden HTTP requests
        - bypass authentication or security controls
        - poison caches
        - manipulate backend request handling

    Expected Behavior:
    The server should reject requests containing multiple Content-Length
    headers or enforce strict validation to ensure that only a single,
    consistent value is accepted.
    */
    
    private async Task<string> RunDualContentLengthTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Headers.TryAddWithoutValidation("Content-Length", "5");
            req.Headers.TryAddWithoutValidation("Content-Length", "40");
            req.Content = new StringContent("hello", Encoding.UTF8, "text/plain");
            return req;
        });

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && ((int)response.StatusCode is >= 200 and < 300)
            ? "Potential risk: duplicate Content-Length accepted."
            : "No obvious duplicate Content-Length acceptance."
        };

        return FormatSection("Dual Content-Length", baseUri, findings);
    }

}

