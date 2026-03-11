namespace API_Tester;

public partial class MainPage
{
    /*
    HTTP CL.TE Desynchronization Test

    Purpose:
    Checks whether the server infrastructure is vulnerable to HTTP request
    smuggling caused by inconsistent handling of the Content-Length (CL)
    and Transfer-Encoding (TE) headers.

    Threat Model:
    Modern web architectures often include multiple layers such as reverse
    proxies, load balancers, or API gateways. If different components parse
    HTTP requests differently, attackers may be able to exploit these
    inconsistencies to smuggle hidden requests through the front-end server.

    In a CL.TE desynchronization scenario:

        - The front-end server trusts the Content-Length header
        - The back-end server prioritizes Transfer-Encoding: chunked

    This mismatch can cause the two systems to disagree about where one
    request ends and the next begins.

    Test Strategy:
    The scanner sends specially crafted requests containing both
    Content-Length and Transfer-Encoding headers. It observes whether
    the server processes the request normally or shows signs of request
    queue desynchronization.

    Potential Impact:
    If the vulnerability exists, attackers may be able to:

        - smuggle hidden HTTP requests
        - bypass authentication or access controls
        - poison caches
        - access other users' requests or responses

    Expected Behavior:
    Servers should enforce strict parsing rules and reject requests that
    contain conflicting Content-Length and Transfer-Encoding headers.
    Modern servers should follow the HTTP specification and prioritize
    Transfer-Encoding or block ambiguous requests entirely.
    */

    private async Task<string> RunHttpClTeDesyncTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Headers.TryAddWithoutValidation("Transfer-Encoding", "chunked");
            req.Content = new StringContent("0\r\n\r\n", Encoding.ASCII, "text/plain");
            req.Content.Headers.ContentLength = 4;
            return req;
        });

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && ((int)response.StatusCode is >= 200 and < 300)
            ? "Potential risk: CL.TE ambiguous request accepted."
            : "No obvious CL.TE desync acceptance."
        };

        return FormatSection("HTTP CL.TE Desync Signal", baseUri, findings);
    }

}

