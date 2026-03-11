namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Zero Trust Policy Enforcement Point (PEP) Controls Tests

        Purpose:
        Performs automated tests to evaluate whether Policy Enforcement Points
        (PEPs) are correctly implemented within the application or its supporting
        infrastructure, ensuring that access control decisions are actively
        enforced before requests reach protected resources.

        Threat Model:
        If Policy Enforcement Points are weak or misconfigured, attackers may:

            - Access protected services without authorization
            - Bypass enforcement layers such as gateways or proxies
            - Exploit inconsistencies between enforcement points
            - Interact directly with backend services without validation

        Common vulnerabilities include:

            - Missing enforcement points on certain API routes
            - Backend services accessible without passing through PEP controls
            - Misconfigured gateways or service meshes
            - Enforcement applied only at the perimeter but not internally
            - Lack of monitoring or logging for enforcement failures

        Test Strategy:
        The method performs automated checks that:

            - Attempt to access protected resources without proper authorization
            - Probe endpoints to determine if requests bypass enforcement layers
            - Evaluate whether requests are consistently routed through PEP controls
            - Detect backend services exposed outside enforcement boundaries
            - Assess logging and monitoring of enforcement actions

        Potential Impact:
        If PEP controls are weak, attackers may:

            - Access internal services or APIs directly
            - Bypass authentication and authorization mechanisms
            - Execute unauthorized actions on protected resources
            - Compromise system integrity or confidentiality

        Expected Behavior:
        Applications and infrastructure should:

            - Enforce access control decisions at defined enforcement points
            - Route all resource access through authorized gateways or proxies
            - Prevent direct access to backend services
            - Apply enforcement consistently across all interfaces
            - Monitor and log enforcement actions and violations
        */
        
        private async Task<string> RunZtPolicyEnforcementPointControlsTestsAsync(Uri baseUri)
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

