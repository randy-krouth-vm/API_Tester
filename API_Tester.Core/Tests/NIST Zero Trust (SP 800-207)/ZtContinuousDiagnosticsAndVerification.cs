namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Zero Trust Continuous Diagnostics and Verification Tests

        Purpose:
        Performs automated tests to evaluate whether the application supports
        continuous diagnostics and verification as part of a Zero Trust security
        model. This ensures that system posture, user activity, and security
        telemetry are continuously monitored and validated.

        Threat Model:
        In environments lacking continuous diagnostics and verification,
        attackers may:

            - Maintain persistent access without detection
            - Exploit compromised credentials or sessions
            - Operate laterally across systems without triggering alerts
            - Exploit gaps in monitoring or telemetry collection

        Common vulnerabilities include:

            - Limited visibility into system activity or telemetry
            - Absence of real-time monitoring or anomaly detection
            - Lack of integration between monitoring and access controls
            - Incomplete logging of user, system, or network events
            - Delayed or ineffective response to suspicious behavior

        Test Strategy:
        The method performs automated checks that:

            - Evaluate logging and telemetry coverage for system activity
            - Assess monitoring and anomaly detection capabilities
            - Verify integration between diagnostics and security controls
            - Detect gaps in continuous monitoring or verification processes
            - Examine alerting and response mechanisms tied to diagnostics

        Potential Impact:
        If continuous diagnostics and verification controls are weak, attackers may:

            - Maintain long-term persistence within the environment
            - Exploit compromised identities or devices without detection
            - Evade monitoring while performing malicious actions
            - Increase risk of data breaches or operational disruption

        Expected Behavior:
        Applications and supporting infrastructure should:

            - Continuously collect and analyze system and security telemetry
            - Monitor user behavior, device posture, and network activity
            - Integrate diagnostics with access control and response systems
            - Generate alerts for anomalies or suspicious activity
            - Maintain visibility across all components of the environment
        */

        private async Task<string> RunZtContinuousDiagnosticsAndVerificationTestsAsync(Uri baseUri)
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

