namespace API_Tester;

public partial class MainPage
{
    /*
    Header Override Test

    Purpose:
    Checks whether client-supplied HTTP headers can override or influence
    server behavior in ways that bypass security controls.

    Threat Model:
    Many applications operate behind reverse proxies, load balancers, or
    API gateways that add special headers to convey information such as
    the original client IP address, protocol, host, or authentication
    context. If the application trusts these headers when they are supplied
    directly by clients, attackers may manipulate request handling.

    Common headers targeted in override attacks include:

        X-Forwarded-For
        X-Forwarded-Host
        X-Forwarded-Proto
        X-Original-URL
        X-Rewrite-URL
        X-Forwarded-Port

    Test Strategy:
    The scanner sends requests containing crafted header values to observe
    whether the application changes routing, authentication decisions, or
    response behavior based on client-supplied headers.

    Potential Impact:
    Improper handling of override headers may allow attackers to:

        - spoof the client IP address
        - bypass IP-based access restrictions
        - manipulate routing or internal URL rewriting
        - bypass security middleware
        - trigger incorrect redirect or host handling

    Expected Behavior:
    Applications should not trust override headers supplied by clients.
    These headers should only be accepted when inserted by trusted
    infrastructure such as reverse proxies, and requests should be
    validated to ensure they originate from those trusted sources.
    */

    private async Task<string> RunHeaderOverrideTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Get, baseUri);

            req.Headers.TryAddWithoutValidation("X-Original-URL", "/admin");
            req.Headers.TryAddWithoutValidation("X-Rewrite-URL", "/admin");
            req.Headers.TryAddWithoutValidation("X-Forwarded-For", "127.0.0.1");
            req.Headers.TryAddWithoutValidation("X-Real-IP", "127.0.0.1");
            req.Headers.TryAddWithoutValidation("Client-IP", "127.0.0.1");
            req.Headers.TryAddWithoutValidation("True-Client-IP", "127.0.0.1");
            req.Headers.TryAddWithoutValidation("X-Forwarded-Host", "localhost");
            req.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
            req.Headers.TryAddWithoutValidation("X-Forwarded-Port", "443");
            req.Headers.TryAddWithoutValidation("X-Forwarded-Uri", "/admin");
            req.Headers.TryAddWithoutValidation("X-Original-Uri", "/admin");
            req.Headers.TryAddWithoutValidation("Forwarded", "for=127.0.0.1;proto=https;host=localhost");
            req.Headers.TryAddWithoutValidation("X-User", "admin");
            req.Headers.TryAddWithoutValidation("X-Authenticated-User", "admin");
            req.Headers.TryAddWithoutValidation("X-Remote-User", "admin");
            req.Headers.TryAddWithoutValidation("Remote-User", "admin");
            req.Headers.TryAddWithoutValidation("X-Admin", "true");
            req.Headers.TryAddWithoutValidation("X-Is-Admin", "1");
            
            return req;
        });

        var body = await ReadBodyAsync(response);
        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.OK &&
            body.Contains("admin", StringComparison.OrdinalIgnoreCase)
            ? "Potential risk: gateway/header override behavior detected."
            : "No obvious header override bypass indicator."
        };

        return FormatSection("Header Override/Auth Bypass", baseUri, findings);
    }

}

