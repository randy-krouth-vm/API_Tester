namespace API_Tester;

public partial class MainPage
{
    /*
    DNS Rebinding Test

    Purpose:
    Checks whether the application is vulnerable to DNS rebinding attacks
    when processing user-supplied URLs or performing server-side requests.

    Threat Model:
    DNS rebinding occurs when a hostname initially resolves to a harmless
    external IP address but later resolves to an internal or restricted
    address such as:

        127.0.0.1
        169.254.169.254
        10.x.x.x
        192.168.x.x

    If the application validates only the hostname during the first lookup
    but the underlying HTTP client later connects using a different resolved
    IP address, an attacker may be able to bypass network restrictions.

    Test Strategy:
    The scanner attempts to access hostnames commonly used for DNS rebinding
    techniques (for example domains that dynamically resolve to embedded IP
    addresses). These domains may resolve to internal IP ranges after the
    initial request.

    Potential Impact:
    Successful DNS rebinding can allow attackers to access internal services
    that should normally be unreachable, including:

        - localhost services
        - internal APIs
        - cloud metadata endpoints
        - administrative interfaces

    This can lead to data exposure or privilege escalation depending on the
    accessible internal resources.

    Expected Behavior:
    Applications should resolve hostnames and validate the resulting IP
    addresses before making outbound requests, blocking private or
    loopback address ranges and preventing DNS rebinding exploitation.
    */
    
    private async Task<string> RunDnsRebindingTestsAsync(Uri baseUri)
    {
        var findings = new List<string>();
        var hosts = new[]
        {
            "127.0.0.1.nip.io",
            "localhost.nip.io",
            "0.0.0.0.nip.io",

            "127.0.0.1.sslip.io",
            "localhost.sslip.io",
            "0.0.0.0.sslip.io",

            "localhost.localtest.me",
            "127.0.0.1.localtest.me",

            "lvh.me",
            "127.0.0.1.lvh.me",
            "localhost.lvh.me",

            "127.0.0.1.xip.io",
            "localhost.xip.io",

            "127.0.0.1.rebind.it",
            "rebinder.net",

            "internal.test",
            "localhost.test",

            "127.0.0.1",
            "localhost",
            "0.0.0.0"
        };

        foreach (var host in hosts)
        {
            var response = await SafeSendAsync(() =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
                req.Headers.Host = host;
                req.Headers.TryAddWithoutValidation("X-Forwarded-Host", host);
                return req;
            });
            findings.Add($"{host}: {FormatStatus(response)}");
        }

        return FormatSection("DNS Rebinding Probe", baseUri, findings);
    }

}

