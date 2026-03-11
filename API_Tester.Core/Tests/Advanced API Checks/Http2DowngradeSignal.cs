namespace API_Tester;

public partial class MainPage
{
    /*
    HTTP/2 Downgrade Signal Test

    Purpose:
    Checks whether the server or intermediary infrastructure may allow
    protocol downgrade behavior between HTTP/2 and HTTP/1.1.

    Threat Model:
    Modern APIs often support HTTP/2 for performance and multiplexing.
    However, some environments include multiple layers such as load
    balancers, reverse proxies, or gateways that translate between
    protocol versions.

    If these components handle protocol translation inconsistently,
    attackers may attempt to trigger downgrade conditions where a request
    is processed differently across layers.

    Test Strategy:
    The scanner probes endpoints using requests that may trigger protocol
    fallback or downgrade conditions. It observes response behavior to
    detect signals that HTTP/2 requests are being translated or handled
    differently by upstream components.

    Potential Impact:
    Improper handling of protocol downgrade scenarios can contribute to:

        - request smuggling conditions
        - inconsistent request parsing
        - bypass of security controls between layers
        - cache inconsistencies

    Expected Behavior:
    Servers and proxies should consistently enforce protocol handling
    rules and ensure that translation between HTTP/2 and HTTP/1.1 does
    not introduce parsing differences or security bypass opportunities.
    */
    
    private async Task<string> RunHttp2DowngradeSignalTestsAsync(Uri baseUri)
    {
        var http2Response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
            req.Version = new Version(2, 0);
            req.VersionPolicy = HttpVersionPolicy.RequestVersionOrLower;
            return req;
        });

        var http11Response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
            req.Version = new Version(1, 1);
            return req;
        });

        var findings = new List<string>
        {
            $"HTTP/2 attempt: {FormatStatus(http2Response)}",
            $"HTTP/1.1 attempt: {FormatStatus(http11Response)}",
            http2Response is not null && http11Response is not null && http2Response.StatusCode != http11Response.StatusCode
            ? "Protocol-version differential detected (review downgrade handling)."
            : "No obvious protocol downgrade differential indicator."
        };

        return FormatSection("HTTP/2 Downgrade Signals", baseUri, findings);
    }

}

