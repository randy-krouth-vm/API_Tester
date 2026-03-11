namespace API_Tester
{
    public partial class MainPage
    {
        /*
        SC-5 Denial of Service (DoS) Protection Tests

        Purpose:
        Performs automated tests to evaluate the application’s protections 
        against Denial of Service (DoS) attacks in accordance with SC-5 
        security requirements, ensuring that the system remains available 
        and responsive under high load or malicious traffic conditions.

        Threat Model:
        Weak DoS protections may allow attackers to:

            - Overwhelm application resources or services
            - Cause outages or degraded performance
            - Exploit unhandled resource exhaustion vulnerabilities
            - Disrupt access to critical functionality for legitimate users

        Common vulnerabilities include:

            - Lack of rate limiting or throttling mechanisms
            - Unprotected endpoints susceptible to resource exhaustion
            - Insufficient monitoring for traffic spikes or anomalies
            - Poorly configured load balancers or service limits
            - Absence of automated mitigation strategies (e.g., request filtering)

        Test Strategy:
        The method performs automated checks that:

            - Generate high request volumes to evaluate system resilience
            - Assess enforcement of throttling and rate-limiting controls
            - Observe system behavior under resource stress
            - Verify detection and mitigation of potential DoS conditions
            - Detect endpoints lacking adequate protection mechanisms

        Potential Impact:
        If DoS protection controls are weak, attackers may:

            - Make the application or services unavailable to legitimate users
            - Exploit resource exhaustion to compromise stability or security
            - Cause operational disruptions or reputational damage
            - Escalate attacks against other parts of the system

        Expected Behavior:
        Applications should:

            - Implement rate limiting, throttling, and other DoS mitigation mechanisms
            - Detect and respond to anomalous traffic or resource usage
            - Maintain availability and performance under high load conditions
            - Protect critical endpoints and services from resource exhaustion
            - Monitor and log DoS-related events for analysis and response
        */

        private async Task<string> RunSc5DenialOfServiceProtectionTestsAsync(Uri baseUri)
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

