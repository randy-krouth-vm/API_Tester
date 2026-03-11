namespace API_Tester;

public partial class MainPage
{
    /*
    Host Header Injection Test

    Purpose:
    Checks whether the application improperly trusts or reflects the HTTP
    Host header when generating responses, links, or routing decisions.

    Threat Model:
    The Host header indicates which hostname the client is attempting to
    reach. Many applications use this header when generating absolute URLs,
    password reset links, redirects, or multi-tenant routing decisions.

    If the application does not validate the Host header, attackers may
    supply a malicious hostname that the application then reflects in
    responses or uses in security-sensitive operations.

    Test Strategy:
    The scanner sends requests containing manipulated Host headers and
    observes whether the application accepts them or reflects them in
    generated content.

    Potential Impact:
    If the Host header is not validated, attackers may be able to:

        - generate malicious password reset links
        - poison web caches
        - bypass virtual host routing controls
        - manipulate redirect targets
        - perform phishing or account takeover attacks

    Expected Behavior:
    The application or front-end server should enforce a strict allowlist
    of valid hostnames and reject requests containing unexpected Host
    values.
    */

    private async Task<string> RunHostHeaderInjectionTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
            req.Headers.Host = "example.invalid";

            req.Headers.TryAddWithoutValidation("X-Forwarded-Host", "example.invalid");
            req.Headers.TryAddWithoutValidation("X-Original-Host", "example.invalid");
            req.Headers.TryAddWithoutValidation("X-Host", "example.invalid");
            req.Headers.TryAddWithoutValidation("Forwarded", "host=example.invalid");
            req.Headers.TryAddWithoutValidation("X-Forwarded-Server", "example.invalid");
            req.Headers.TryAddWithoutValidation("X-HTTP-Host-Override", "example.invalid");
            req.Headers.TryAddWithoutValidation("X-Forwarded-Proto", "https");
            req.Headers.TryAddWithoutValidation("X-Forwarded-Port", "443");
            req.Headers.TryAddWithoutValidation("X-Original-URL", "/");
            req.Headers.TryAddWithoutValidation("X-Rewrite-URL", "/");
            req.Headers.TryAddWithoutValidation("Referer", "https://example.invalid/");
            req.Headers.TryAddWithoutValidation("Origin", "https://example.invalid");
            
            return req;
        });

        var body = await ReadBodyAsync(response);
        var location = response is null ? string.Empty : TryGetHeader(response, "Location");
        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            (!string.IsNullOrWhiteSpace(location) && location.Contains("example.invalid", StringComparison.OrdinalIgnoreCase)) ||
            body.Contains("example.invalid", StringComparison.OrdinalIgnoreCase)
            ? "Potential risk: host header value reflected/used by application."
            : "No obvious host-header reflection found."
        };

        return FormatSection("Host Header Injection", baseUri, findings);
    }

}

