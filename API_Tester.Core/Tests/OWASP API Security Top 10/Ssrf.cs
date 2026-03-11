namespace API_Tester
{
    public partial class MainPage
    {
        /*
        OWASP API Security Top 10 – Server-Side Request Forgery (SSRF) Tests

        Purpose:
        Performs automated tests to determine whether the API is vulnerable
        to Server-Side Request Forgery (SSRF). SSRF occurs when an application
        accepts user-supplied input that causes the server to initiate requests
        to unintended internal or external resources.

        Threat Model:
        APIs that fetch remote resources (URLs, images, webhooks, integrations,
        or file imports) may allow attackers to manipulate request destinations.

        Attackers may attempt to:

            - access internal services not exposed to the internet
            - query cloud metadata services
            - scan internal networks
            - bypass firewall protections
            - retrieve sensitive system information

        Common SSRF targets include:

            - localhost or loopback interfaces
            - internal private IP ranges
            - container or orchestration services
            - cloud instance metadata endpoints
            - internal admin APIs

        Common vulnerabilities include:

            - accepting arbitrary URLs without validation
            - failing to restrict outbound requests
            - lack of IP filtering or allowlists
            - improper handling of redirects
            - insufficient validation of URL schemes or hosts

        Test Strategy:
        The method performs automated checks that:

            - submit crafted URLs targeting internal or restricted resources
            - analyze responses for signs of internal network access
            - detect access to cloud metadata endpoints
            - evaluate outbound request filtering controls
            - inspect application behavior when external URLs are supplied

        Potential Impact:
        If SSRF vulnerabilities exist, attackers may:

            - access internal services or infrastructure
            - retrieve cloud credentials or metadata
            - perform internal network reconnaissance
            - pivot to additional systems within the environment
            - compromise application infrastructure

        Expected Behavior:
        Applications should:

            - validate and restrict user-supplied URLs
            - enforce outbound request allowlists
            - block requests to internal or metadata endpoints
            - sanitize redirects and URL parsing behavior
            - monitor and log outbound requests for anomalies
        */
        private async Task<string> RunOWASPAPISecurityTop10SsrfTestsAsync(Uri baseUri)
        {
            var openApi = await GetOpenApiProbeContextAsync(baseUri);
            var probeTargets = new[]
            {
                "http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1:80/",
                "http://localhost/admin",
                "http://[::1]/",
                "ldap://127.0.0.1:389/",
                "ldap://localhost:389/"
            };
            var scanDepth = GetScanDepthProfile();
            probeTargets = ExpandHttpToHttps(GetManualPayloadsOrDefault(probeTargets, ManualPayloadCategory.Ssrf));
            probeTargets = LimitByScanDepth(probeTargets, fastCount: 2, balancedCount: 3);
            var endpoints = (openApi.TargetEndpoints.Count > 0 ? openApi.TargetEndpoints : new List<Uri> { baseUri })
            .Take(scanDepth == "fast" ? 2 : scanDepth == "balanced" ? 4 : 8)
            .ToList();
            var ssrfLikelyNames = new[] { "url", "uri", "callback", "redirect", "returnurl", "next", "dest", "destination", "webhook", "endpoint", "target", "link", "resource", "proxy" };
            var queryFields = openApi.QueryParameterNames
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Where(x => !openApi.NonStringQueryParameterNames.Contains(x, StringComparer.OrdinalIgnoreCase))
            .Where(x => ssrfLikelyNames.Any(name => x.Contains(name, StringComparison.OrdinalIgnoreCase)))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
            if (queryFields.Length == 0)
            {
                queryFields = new[] { "url", "callback" };
            }
            queryFields = queryFields.Take(scanDepth == "fast" ? 2 : scanDepth == "balanced" ? 4 : 8).ToArray();

            var findings = new List<string>();
            var suspiciousSignals = 0;
            var totalAttempts = 0;
            var noResponse = 0;

            foreach (var endpoint in endpoints)
            {
                foreach (var target in probeTargets)
                {
                    foreach (var q in queryFields)
                    {
                        var queryUri = AppendQuery(endpoint, new Dictionary<string, string> { [q] = target });
                        var queryResponse = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, queryUri));
                        var queryBody = await ReadBodyAsync(queryResponse);
                        totalAttempts++;
                        if (queryResponse is null)
                        {
                            noResponse++;
                            continue;
                        }

                        if (ContainsAny(queryBody, "meta-data", "instance-id", "ami-id", "localhost", "169.254.169.254", "root:x:"))
                        {
                            suspiciousSignals++;
                        }
                    }

                    var bodyField = openApi.BodyPropertyNames
                    .Where(x => !openApi.NonStringBodyPropertyNames.Contains(x, StringComparer.OrdinalIgnoreCase))
                    .FirstOrDefault(x => ssrfLikelyNames.Any(name => x.Contains(name, StringComparison.OrdinalIgnoreCase)))
                    ?? "url";
                    var jsonResponse = await SafeSendAsync(() =>
                    {
                        var req = new HttpRequestMessage(HttpMethod.Post, endpoint);
                        req.Content = new StringContent(
                        JsonSerializer.Serialize(new Dictionary<string, string> { [bodyField] = target }),
                        Encoding.UTF8,
                        "application/json");
                        return req;
                    });
                    var jsonBody = await ReadBodyAsync(jsonResponse);
                    totalAttempts++;
                    if (jsonResponse is null)
                    {
                        noResponse++;
                        continue;
                    }

                    if (ContainsAny(jsonBody, "meta-data", "instance-id", "ami-id", "localhost", "169.254.169.254", "root:x:"))
                    {
                        suspiciousSignals++;
                    }
                }
            }
            findings.Add(noResponse == totalAttempts
            ? "No responses received across SSRF probes."
            : suspiciousSignals > 0
            ? $"Potential risk: internal-resource SSRF markers observed on {suspiciousSignals}/{totalAttempts} probes."
            : "No obvious SSRF marker responses across tested vectors.");
            AddVerbosePayloadDetails(findings, probeTargets, queryFields, openApi.BodyPropertyNames.FirstOrDefault() is { Length: > 0 } primaryBodyField ? [primaryBodyField] : ["url"]);

            return FormatSection("SSRF", baseUri, findings);
        }
    }
}

