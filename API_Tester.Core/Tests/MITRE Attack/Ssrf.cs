namespace API_Tester;

public partial class MainPage
{
    /*
    MITRE ATT&CK – Server-Side Request Forgery (SSRF) Tests

    Purpose:
    Performs automated tests to detect Server-Side Request Forgery (SSRF)
    vulnerabilities in the application, where an attacker can induce the
    server to make unintended HTTP or network requests.

    Threat Model:
    SSRF occurs when user-controlled input is used to generate server-side
    requests. Attackers can exploit SSRF to:

        - Access internal services not exposed externally
        - Retrieve sensitive data from internal endpoints
        - Scan internal networks for vulnerabilities
        - Interact with cloud metadata services (e.g., AWS, Azure, GCP)
        - Bypass firewalls or security controls

    Common SSRF targets include:

        - URL or host parameters in HTTP requests
        - File download or fetch endpoints
        - Image, XML, or RSS processing with external references
        - Open redirect or proxy endpoints
        - Cloud service metadata endpoints (e.g., /latest/meta-data)

    Test Strategy:
    The method performs automated requests using crafted payloads that:

        - Point to internal IPs or localhost addresses
        - Access cloud metadata endpoints
        - Attempt to trigger requests to restricted resources
        - Analyze server responses for indications of SSRF

    Potential Impact:
    If SSRF vulnerabilities exist, attackers may:

        - Exfiltrate sensitive internal data
        - Pivot within internal networks or cloud environments
        - Exploit internal services for further attacks
        - Gain administrative credentials or access cloud resources

    Expected Behavior:
    Applications should:

        - Validate and sanitize all user-supplied URLs or hosts
        - Restrict server-side requests to known, safe destinations
        - Avoid exposing internal network or cloud metadata services
        - Implement monitoring and alerting for unexpected outbound requests
        - Apply principle of least privilege for services making outbound requests
    */
    
    private async Task<string> RunMITREATTampCKFrameworkSsrfTestsAsync(Uri baseUri)
    {
        var openApi = await GetOpenApiProbeContextAsync(baseUri);
        var probeTargets = new[]
        {
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1:80/",
            "http://localhost/admin",
            "http://[::1]/",
            "ldap://127.0.0.1:389/",
            "ldap://localhost:389/",
            "http://localhost:9200/", 
            "http://127.0.0.1:9200/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/api/token",
            "http://172.16.0.1/",
            "http://10.0.0.1:8080/",
            "http://192.168.1.1/",
            "http://192.168.0.1/",
            "http://10.0.0.138/",
            "http://10.10.10.10/",
            "http://172.30.0.1/",
            "http://169.254.169.254:80/",
            "http://[::1]:8080/",
            "http://localhost:8000/admin",
            "http://localhost:8080/",
            "http://127.0.0.1:3000/",
            "http://172.16.0.10:8080/",
            "http://localhost:9999/",
            "http://192.168.100.1/",
            "http://localhost:5000/",
            "http://172.16.254.1/"
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

