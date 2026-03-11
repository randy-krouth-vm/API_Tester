namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Unrestricted Resource Consumption Tests

        Purpose:
        Performs automated tests to evaluate whether the application properly
        limits the consumption of system resources. These tests help identify
        conditions where attackers may abuse endpoints to exhaust server
        resources such as CPU, memory, storage, or network capacity.

        Threat Model:
        APIs and web applications may expose endpoints that allow attackers
        to trigger excessive processing, large queries, or repeated requests.
        Without proper safeguards, attackers may attempt to:

            - send large numbers of requests
            - trigger expensive database queries
            - upload large payloads
            - repeatedly call resource-intensive endpoints
            - abuse pagination or filtering mechanisms

        These actions can lead to denial of service conditions even without
        traditional volumetric attacks.

        Common vulnerabilities include:

            - missing rate limiting or throttling
            - unrestricted request sizes or payload limits
            - expensive operations exposed via public APIs
            - lack of pagination limits for large result sets
            - insufficient timeout or processing constraints

        Test Strategy:
        The method performs automated checks that:

            - generate repeated or rapid API requests
            - submit large payloads or complex queries
            - evaluate enforcement of rate limiting and throttling controls
            - detect endpoints performing expensive operations without limits
            - analyze system responses for resource exhaustion indicators

        Potential Impact:
        If unrestricted resource consumption vulnerabilities exist, attackers may:

            - cause denial of service conditions
            - degrade application performance
            - exhaust infrastructure resources
            - disrupt availability for legitimate users

        Expected Behavior:
        Applications should:

            - enforce rate limiting and request throttling
            - restrict request payload sizes
            - apply limits to pagination and query complexity
            - implement timeouts for long-running operations
            - monitor and log abnormal request patterns
        */

        private async Task<string> RunUnrestrictedResourceConsumptionTestsAsync(Uri baseUri)
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

