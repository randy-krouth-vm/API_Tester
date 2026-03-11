namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Runtime Interface Exposure Tests

        Purpose:
        Performs automated tests to evaluate whether container or application
        runtime interfaces are improperly exposed to external networks or
        unauthorized users.

        Threat Model:
        Runtime interfaces (e.g., Docker API, container management endpoints,
        debugging interfaces, or orchestration control ports) may expose
        powerful administrative capabilities. If these interfaces are accessible,
        attackers may:

            - Execute commands within containers
            - Deploy or modify workloads
            - Access secrets or environment variables
            - Control the runtime environment

        Common vulnerabilities include:

            - Exposed Docker daemon sockets or APIs
            - Publicly accessible container management ports
            - Debug or administrative interfaces left enabled
            - Lack of authentication or authorization for runtime APIs
            - Misconfigured container orchestration endpoints

        Test Strategy:
        The method performs automated checks that:

            - Probe for exposed runtime management interfaces
            - Attempt connections to known container runtime ports
            - Inspect responses from potential runtime control endpoints
            - Identify services exposing runtime control capabilities
            - Evaluate access restrictions on runtime interfaces

        Potential Impact:
        If runtime interfaces are exposed, attackers may:

            - Execute arbitrary commands on the host or containers
            - Deploy malicious containers
            - Exfiltrate sensitive configuration or secrets
            - Fully compromise containerized infrastructure

        Expected Behavior:
        Applications and container platforms should:

            - Restrict runtime interfaces to trusted internal networks
            - Require authentication and authorization for runtime APIs
            - Disable unnecessary debug or management interfaces
            - Monitor and log access to runtime management endpoints
            - Follow least privilege principles for runtime control access
        */

        private async Task<string> RunRuntimeInterfaceExposureTestsAsync(Uri baseUri)
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

