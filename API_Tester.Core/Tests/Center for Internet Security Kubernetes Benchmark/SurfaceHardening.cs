namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Attack Surface Hardening Test

        Purpose:
        Checks whether the application minimizes its exposed attack surface
        by disabling unnecessary endpoints, headers, services, or debugging
        features that could provide attackers with additional entry points.

        Threat Model:
        An expanded attack surface increases the number of ways attackers
        can interact with a system. Unused routes, debug endpoints, default
        framework pages, and diagnostic interfaces can expose functionality
        that was never intended to be publicly accessible.

        If these components are left enabled in production environments,
        attackers may discover and exploit them to gain system information,
        trigger administrative actions, or bypass normal application logic.

        Common examples include:

            - exposed diagnostic or health endpoints
            - development or debug routes
            - framework default pages
            - test or staging APIs deployed to production
            - verbose server headers revealing technology details

        Example exposure:

            /debug
            /health
            /metrics
            /test
            /admin

        While some endpoints may be legitimate, they should be protected,
        restricted, or disabled when not required.

        Test Strategy:
        The scanner probes common administrative, diagnostic, and framework
        paths and inspects responses for indications that unnecessary features
        are enabled or publicly accessible.

        Potential Impact:
        If attack surface hardening is weak, attackers may be able to:

            - discover hidden or undocumented endpoints
            - access administrative interfaces
            - gather reconnaissance information about the system
            - exploit debugging or diagnostic functionality

        Expected Behavior:
        Production environments should expose only the endpoints required
        for application functionality. Debug features, test routes, and
        diagnostic interfaces should be disabled or properly restricted.
        Unnecessary headers and framework identifiers should also be removed
        to reduce information leakage and attack surface.
        */
        
        private async Task<string> RunSurfaceHardeningTestsAsync(Uri baseUri)
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

