namespace API_Tester;

public partial class MainPage
{
    /*
    HTTP Request Smuggling Signal Test

    Purpose:
    Checks whether the API infrastructure may be vulnerable to HTTP
    request smuggling by probing for signals of inconsistent request
    parsing across front-end and back-end servers.

    Threat Model:
    HTTP request smuggling occurs when different components in the request
    processing chain (such as reverse proxies, load balancers, CDNs, or
    application servers) interpret HTTP request boundaries differently.

    This commonly happens when conflicting headers such as:

        Content-Length
        Transfer-Encoding

    are handled inconsistently between layers.

    For example:

        Front-end server uses Content-Length
        Back-end server uses Transfer-Encoding: chunked

    This disagreement can allow attackers to inject hidden requests into
    the connection.

    Attack scenarios include:

        - bypassing authentication controls
        - poisoning shared caches
        - stealing responses intended for other users
        - executing unauthorized requests through smuggled payloads

    Test Strategy:
    The scanner sends crafted HTTP requests containing ambiguous or
    conflicting header combinations and observes response behavior for
    indicators of parsing inconsistencies or connection desynchronization.

    Potential Impact:
    If request smuggling vulnerabilities exist, attackers may be able to:

        - bypass security controls at the proxy or gateway layer
        - inject hidden requests into persistent connections
        - manipulate request routing
        - access sensitive data from other users' requests

    Expected Behavior:
    Servers and intermediaries should strictly follow HTTP specifications
    and reject requests containing ambiguous or conflicting length headers.
    All components in the request chain should interpret request boundaries
    consistently.
    */
    
    private async Task<string> RunRequestSmugglingSignalTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Version = new Version(1, 1);
            req.Headers.TryAddWithoutValidation("Transfer-Encoding", "chunked");
            req.Headers.TryAddWithoutValidation("Transfer-Encoding", "chunked, identity");
            req.Content = new StringContent("0\r\n\r\n", Encoding.ASCII, "text/plain");
            return req;
        });

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.OK
            ? "Potential risk: ambiguous transfer-encoding payload accepted."
            : "No obvious smuggling-signal acceptance."
        };

        return FormatSection("Request Smuggling Signals", baseUri, findings);
    }

}

