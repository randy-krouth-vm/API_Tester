namespace API_Tester;

public partial class MainPage
{
    /*
    HTTP TE.CL Desynchronization Test

    Purpose:
    Checks whether the server infrastructure is vulnerable to HTTP request
    smuggling caused by inconsistent handling of Transfer-Encoding (TE)
    and Content-Length (CL) headers.

    Threat Model:
    In layered web architectures (such as CDN → load balancer → reverse proxy
    → application server), different components may interpret request length
    headers differently.

    In a TE.CL desynchronization scenario:

        - The front-end server processes the request using
        Transfer-Encoding: chunked
        - The back-end server relies on the Content-Length header

    Because the two systems disagree about how to determine the request
    boundary, an attacker can craft a request where extra data is interpreted
    as a second hidden request by the back-end server.

    Test Strategy:
    The scanner sends requests containing both Transfer-Encoding and
    Content-Length headers arranged in a way that may trigger parsing
    differences between front-end and back-end systems. The response
    behavior is analyzed for signs of request queue desynchronization.

    Potential Impact:
    If a TE.CL vulnerability exists, attackers may be able to:

        - smuggle hidden HTTP requests
        - bypass authentication checks
        - poison shared caches
        - interfere with other users’ requests

    Expected Behavior:
    Servers should reject requests containing conflicting Transfer-Encoding
    and Content-Length headers or consistently follow the HTTP specification
    to prevent ambiguous parsing across infrastructure layers.
    */
    
    private async Task<string> RunHttpTeClDesyncTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Headers.TryAddWithoutValidation("Transfer-Encoding", "chunked");
            req.Headers.TryAddWithoutValidation("Content-Length", "50");
            req.Content = new StringContent("0\r\n\r\n", Encoding.ASCII, "text/plain");
            return req;
        });

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && ((int)response.StatusCode is >= 200 and < 300)
            ? "Potential risk: TE.CL ambiguous request accepted."
            : "No obvious TE.CL desync acceptance."
        };

        return FormatSection("HTTP TE.CL Desync Signal", baseUri, findings);
    }

}

