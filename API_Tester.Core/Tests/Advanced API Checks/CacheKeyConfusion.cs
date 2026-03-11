namespace API_Tester;

public partial class MainPage
{
    /*
    Cache Key Confusion Test

    Purpose:
    Detects inconsistencies between how a cache identifies responses (the cache key)
    and how the application generates those responses.

    Threat Model:
    Reverse proxies, CDNs, and server-side caches store responses using a cache key
    (often composed of method + host + path + selected headers or query parameters).
    If the application uses additional inputs that are NOT part of the cache key
    (such as headers or query parameters), attackers may manipulate those inputs to
    poison the cache or influence responses served to other users.

    Common inputs involved in cache key confusion include:

        Host
        X-Forwarded-Host
        X-Forwarded-Proto
        X-Original-Host
        Origin
        query parameters

    Test Strategy:
    The scanner sends requests that modify headers or parameters which may affect
    application behavior but may not be included in the cache key. It then compares
    responses from subsequent requests to determine whether attacker-controlled
    inputs influence cached responses.

    Potential Impact:
    If a cache stores responses influenced by attacker input but keyed only on
    partial request data, it may allow:

        - Web cache poisoning
        - Cache deception attacks
        - Malicious content injection into cached pages
        - Incorrect responses served to other users

    Expected Behavior:
    The cache key should include all request inputs that influence the response.
    Applications should avoid trusting client-controlled headers when generating
    cacheable responses.
    */
    
    private async Task<string> RunCacheKeyConfusionTestsAsync(Uri baseUri)
    {
        var scanDepth = GetScanDepthProfile();
        var findings = new List<string>();
        var headerSets = new[]
        {
            new Dictionary<string, string> { ["X-Forwarded-Host"] = "attacker.example", ["X-Forwarded-Proto"] = "http" },
            new Dictionary<string, string> { ["Forwarded"] = "host=attacker.example;proto=http", ["X-Rewrite-URL"] = "/admin" },
            new Dictionary<string, string> { ["X-Original-URL"] = "/admin", ["X-Forwarded-Host"] = "example.invalid" }
        };
        headerSets = LimitByScanDepth(headerSets, fastCount: 1, balancedCount: 2);
        var suspicious = 0;
        var attempts = 0;

        foreach (var headers in headerSets)
        {
            var response = await SafeSendAsync(() =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
                foreach (var kv in headers)
                {
                    req.Headers.TryAddWithoutValidation(kv.Key, kv.Value);
                }
                return req;
            });
            attempts++;
            var cacheControl = response is null ? string.Empty : TryGetHeader(response, "Cache-Control");
            var vary = response is null ? string.Empty : TryGetHeader(response, "Vary");
            var age = response is null ? string.Empty : TryGetHeader(response, "Age");
            findings.Add($"Probe {attempts}: {FormatStatus(response)} | Cache-Control='{cacheControl}' | Vary='{vary}' | Age='{age}'");
            if (!string.IsNullOrWhiteSpace(age) || cacheControl.Contains("public", StringComparison.OrdinalIgnoreCase))
            {
                suspicious++;
            }
        }
        findings.Add(suspicious > 0
        ? "Potential risk: cache behavior indicates key confusion/poisoning opportunity (review Vary and forwarding headers)."
        : "No obvious cache key confusion signal detected.");
        return FormatSection("Cache Key Confusion", baseUri, findings);
    }

}

