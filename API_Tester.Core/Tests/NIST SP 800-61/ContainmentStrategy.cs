namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Containment Strategy Tests

        Purpose:
        Performs automated tests to evaluate the application’s containment 
        strategies, ensuring that security incidents, breaches, or anomalies 
        are effectively isolated to prevent further impact.

        Threat Model:
        Weak containment strategies may allow attackers to:

            - Spread laterally within systems or networks
            - Escalate privileges or access additional resources
            - Exploit uncontained vulnerabilities or compromised components
            - Evade detection and impact critical systems

        Common vulnerabilities include:

            - Lack of network or system segmentation to contain breaches
            - Absence of automated isolation mechanisms for compromised assets
            - Ineffective incident response procedures to limit impact
            - Insufficient monitoring to detect spread of malicious activity
            - No failover or mitigation plans for critical components

        Test Strategy:
        The method performs automated checks that:

            - Assess the ability to isolate compromised systems or services
            - Verify enforcement of network and application segmentation
            - Evaluate response mechanisms for containing security events
            - Detect weaknesses that could allow lateral movement or escalation
            - Examine monitoring and alerting for containment effectiveness

        Potential Impact:
        If containment strategies are weak, attackers may:

            - Compromise additional systems beyond the initial breach
            - Access sensitive data or critical resources
            - Escalate attacks without detection
            - Cause broader operational, financial, or reputational damage

        Expected Behavior:
        Applications should:

            - Implement mechanisms to isolate and contain compromised assets
            - Enforce segmentation to limit lateral movement
            - Integrate containment strategies with incident response workflows
            - Monitor and detect attempts to circumvent containment controls
            - Ensure containment policies are consistent and effective across environments
        */

        private async Task<string> RunContainmentStrategyTestsAsync(Uri baseUri)
        {
            var activeKey = _activeStandardTestKey.Value;
            var (attempts, burstSize, methods) = GetRateLimitPlan(activeKey);
            var findings = new List<string>();
            findings.Add($"Probe profile: {(string.IsNullOrWhiteSpace(activeKey) ? "default" : activeKey)} | Attempts: {attempts} | Burst size: {burstSize}");
            var responses = new List<HttpResponseMessage?>(attempts);

            for (var i = 0; i < attempts;)
            {
                var batchSize = Math.Min(burstSize, attempts - i);
                var batchTasks = new List<Task<HttpResponseMessage?>>(batchSize);
                for (var j = 0; j < batchSize; j++)
                {
                    var reqIndex = i + j;
                    var method = methods[reqIndex % methods.Length];
                    var uri = AppendQuery(baseUri, new Dictionary<string, string>
                    {
                        ["ratelimit_probe"] = "1",
                        ["nonce"] = $"{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}-{reqIndex}"
                    });

                    batchTasks.Add(SafeSendAsync(() => new HttpRequestMessage(method, uri)));
                }

                var batch = await Task.WhenAll(batchTasks);
                responses.AddRange(batch);
                i += batchSize;
            }

            for (var i = 0; i < responses.Count; i++)
            {
                var response = responses[i];
                findings.Add(response is null
                ? $"Request {i + 1}: no response"
                : $"Request {i + 1}: HTTP {(int)response.StatusCode} {response.StatusCode}");
            }

            var lastResponse = responses.LastOrDefault(r => r is not null);
            if (lastResponse is null)
            {
                return FormatSection("Rate Limiting", baseUri, findings);
            }

            var rateHeaders = new[] { "X-RateLimit-Limit", "X-RateLimit-Remaining", "Retry-After", "RateLimit-Limit", "RateLimit-Remaining" };
            var foundHeaders = rateHeaders.Where(h => HasHeader(lastResponse, h)).ToList();
            var throttled = responses.Count(r => r is not null && (int)r.StatusCode == 429);

            findings.Add(foundHeaders.Count > 0
            ? $"Rate-limit headers found: {string.Join(", ", foundHeaders)}"
            : "No standard rate-limit headers found.");
            findings.Add(throttled > 0
            ? $"Rate-limit throttling detected on {throttled}/{responses.Count} requests."
            : "No explicit 429 throttling observed in this probe window.");

            return FormatSection("Rate Limiting", baseUri, findings);
        }
    }
}

