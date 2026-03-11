namespace API_Tester;

public partial class MainPage
{
    /*
    Header-Based Authentication Override Test

    Purpose:
    Detects whether authentication or authorization logic can be bypassed
    by supplying alternate or spoofed HTTP headers that override identity
    or security checks.

    Threat Model:
    Many applications rely on upstream infrastructure such as API gateways,
    reverse proxies, or authentication middleware to populate headers that
    identify the user or the request origin. If the application blindly
    trusts these headers when they are supplied by the client, attackers
    may spoof authentication or privilege information.

    Common headers involved in this type of issue include:

        X-Forwarded-User
        X-User
        X-Authenticated-User
        X-Original-User
        X-Forwarded-Email
        X-Auth-User
        X-Forwarded-Role
        X-Admin

    Test Strategy:
    The scanner sends requests containing various identity and privilege
    headers to determine whether the application accepts these values and
    changes behavior accordingly.

    Potential Impact:
    If these headers are trusted without validation, attackers may be able to:

        - impersonate other users
        - escalate privileges
        - bypass authentication controls
        - access restricted administrative endpoints

    Expected Behavior:
    Applications should not trust client-supplied identity headers. Any
    authentication headers should only be set by trusted infrastructure
    components and should be validated before being used for authorization
    decisions.
    */
    
    private async Task<string> RunHeaderAuthOverrideExpandedTestsAsync(Uri baseUri)
    {
        var openApi = await GetOpenApiProbeContextAsync(baseUri);
        var scanDepth = GetScanDepthProfile();
        var endpoints = (openApi.TargetEndpoints.Count > 0 ? openApi.TargetEndpoints : new List<Uri> { baseUri })
        .Take(scanDepth == "fast" ? 2 : scanDepth == "balanced" ? 4 : 8)
        .ToList();
        var findings = new List<string>();
        var suspicious = 0;
        var attempts = 0;

        var headerSets = new[]
        {
            new Dictionary<string, string> { ["X-User"] = "admin", ["X-Role"] = "admin" },
            new Dictionary<string, string> { ["X-Forwarded-User"] = "admin", ["X-Authenticated-User"] = "admin" },
            new Dictionary<string, string> { ["X-Original-URL"] = "/admin", ["X-Rewrite-URL"] = "/admin" },
            new Dictionary<string, string> { ["X-Forwarded-For"] = "127.0.0.1", ["X-Forwarded-Host"] = "localhost" },
            new Dictionary<string, string> { ["X-Forwarded-Proto"] = "https", ["X-Forwarded-Port"] = "443" },
            new Dictionary<string, string> { ["X-Real-IP"] = "127.0.0.1", ["Client-IP"] = "127.0.0.1" },
            new Dictionary<string, string> { ["Forwarded"] = "for=127.0.0.1;proto=https;host=localhost" },
            new Dictionary<string, string> { ["X-Client-IP"] = "127.0.0.1", ["True-Client-IP"] = "127.0.0.1" },
            new Dictionary<string, string> { ["X-Remote-User"] = "admin", ["Remote-User"] = "admin" },
            new Dictionary<string, string> { ["X-User-Id"] = "1", ["X-User-Role"] = "admin" },
            new Dictionary<string, string> { ["X-Admin"] = "true", ["X-Is-Admin"] = "1" },
            new Dictionary<string, string> { ["X-Forwarded-Uri"] = "/admin", ["X-Original-Uri"] = "/admin" },
            new Dictionary<string, string> { ["X-Rewrite-URL"] = "/internal", ["X-Original-URL"] = "/internal" }
        };

        foreach (var endpoint in endpoints)
        {
            foreach (var set in headerSets)
            {
                var response = await SafeSendAsync(() =>
                {
                    var req = new HttpRequestMessage(HttpMethod.Get, endpoint);
                    foreach (var kv in set)
                    {
                        req.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
                    }
                    return req;
                });
                attempts++;
                if (response is not null && (int)response.StatusCode is >= 200 and < 300)
                {
                    suspicious++;
                }
            }
        }
        findings.Add(suspicious > 0
        ? $"Potential risk: header-based identity override signals observed on {suspicious}/{attempts} probes."
        : "No obvious header-auth override acceptance detected.");
        return FormatSection("Header Authentication Override", baseUri, findings);
    }

}

