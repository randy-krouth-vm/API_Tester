namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Container Network Boundary Tests

        Purpose:
        Performs automated tests to evaluate the security of container network
        boundaries, ensuring that containerized services are properly isolated
        and protected from unauthorized access or lateral movement.

        Threat Model:
        Weak container network boundaries may allow attackers to:

            - Access internal container services from external networks
            - Move laterally between containers or services
            - Exploit misconfigured container networking rules
            - Interact with sensitive internal APIs or infrastructure services

        Common vulnerabilities include:

            - Overly permissive container networking policies
            - Exposed container ports that should remain internal
            - Lack of network segmentation between container workloads
            - Misconfigured service discovery or internal routing
            - Insufficient monitoring of container network traffic

        Test Strategy:
        The method performs automated checks that:

            - Identify exposed container services and network interfaces
            - Attempt access across container boundaries
            - Verify network segmentation between services
            - Assess enforcement of container networking policies
            - Detect misconfigurations that allow unauthorized network access

        Potential Impact:
        If container network boundaries are weak, attackers may:

            - Access sensitive internal container services
            - Move laterally across workloads within the environment
            - Exfiltrate sensitive data from internal services
            - Compromise container infrastructure or orchestration components

        Expected Behavior:
        Containerized environments should:

            - Enforce strict network segmentation between container services
            - Restrict external exposure of container ports and APIs
            - Implement network policies to limit inter-container communication
            - Monitor container network activity for anomalies
            - Ensure container networking configurations follow least privilege principles
        */
        
        private async Task<string> RunContainerNetworkBoundaryTestsAsync(Uri baseUri)
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
                "http://172.17.0.1/", 
                "http://172.18.0.1/", 
                "http://172.19.0.1/", 
                "http://172.20.0.1/", 
                "http://10.0.0.1:8080/",
                "http://172.16.0.1/",
                "http://10.0.0.1/",
                "http://192.168.0.1/",
                "http://192.168.1.1/",
                "http://172.30.0.1/",
                "http://10.10.10.10/",
                "http://localhost:5000/",
                "http://localhost:8080/",
                "http://localhost:3000/",
                "http://localhost:9000/"
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

