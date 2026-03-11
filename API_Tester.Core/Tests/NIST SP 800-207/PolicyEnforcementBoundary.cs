namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Policy Enforcement Boundary Tests

        Purpose:
        Performs automated tests to evaluate whether security policies are
        consistently enforced at defined system and network boundaries,
        ensuring that access decisions and protections are applied before
        requests reach protected resources.

        Threat Model:
        Weak policy enforcement boundaries may allow attackers to:

            - Bypass security policies through alternate paths
            - Access internal services without proper validation
            - Circumvent authentication or authorization controls
            - Exploit gaps between network, API, or application layers

        Common vulnerabilities include:

            - Missing enforcement points at API gateways or proxies
            - Inconsistent policy checks between services
            - Direct access to backend services bypassing security layers
            - Lack of validation at trust boundaries
            - Misconfigured security middleware or routing rules

        Test Strategy:
        The method performs automated checks that:

            - Attempt to access services through alternate paths
            - Evaluate whether policy checks occur at boundary interfaces
            - Inspect enforcement of authentication and authorization policies
            - Detect inconsistencies between external and internal access controls
            - Assess whether backend services can be accessed directly

        Potential Impact:
        If policy enforcement boundaries are weak, attackers may:

            - Bypass security policies and controls
            - Access internal resources or services directly
            - Perform unauthorized operations
            - Compromise sensitive data or system integrity

        Expected Behavior:
        Applications should:

            - Enforce security policies at all trust boundaries
            - Route requests through controlled gateways or enforcement points
            - Prevent direct access to internal services
            - Apply consistent policy checks across all interfaces
            - Monitor and log boundary policy violations
        */
        
        private async Task<string> RunPolicyEnforcementBoundaryTestsAsync(Uri baseUri)
        {
            var findings = new List<string>();

            var options = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Options, baseUri));
            if (options is not null)
            {
                findings.Add($"OPTIONS: {(int)options.StatusCode} {options.StatusCode}");
                var allow = TryGetHeader(options, "Allow");
                if (!string.IsNullOrWhiteSpace(allow))
                {
                    findings.Add($"Allow: {allow}");
                }
            }
            else
            {
                findings.Add("OPTIONS: no response");
            }

            var trace = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Trace, baseUri));
            if (trace is not null)
            {
                findings.Add($"TRACE: {(int)trace.StatusCode} {trace.StatusCode}");
                if (trace.StatusCode != HttpStatusCode.MethodNotAllowed &&
                trace.StatusCode != HttpStatusCode.NotFound)
                {
                    findings.Add("Potential risk: TRACE method appears enabled.");
                }
            }
            else
            {
                findings.Add("TRACE: no response");
            }

            return FormatSection("HTTP Methods", baseUri, findings);
        }
    }
}

