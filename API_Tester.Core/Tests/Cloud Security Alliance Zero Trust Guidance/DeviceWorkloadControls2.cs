namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Device and Workload Security Controls Test

        Purpose:
        Evaluates whether the API enforces security controls related to
        devices, workloads, or service identities that interact with
        the system.

        Threat Model:
        Modern applications frequently run in distributed environments
        such as containers, serverless platforms, or microservices.
        Each workload or device interacting with the system should be
        properly authenticated and authorized.

        If device or workload identity controls are weak or missing,
        attackers may impersonate trusted services or gain unauthorized
        access to internal APIs.

        Common weaknesses include:

            - accepting requests from unauthenticated services
            - missing service-to-service authentication
            - lack of device identity validation
            - allowing internal endpoints to be called from untrusted sources
            - trusting client-supplied device identifiers

        Example scenario:

            Internal endpoint:
                POST /internal/process-job

        If the endpoint assumes only trusted services will call it and
        does not require authentication, an external attacker could
        invoke it directly.

        Attack scenarios include:

            - impersonating trusted workloads or services
            - invoking internal APIs intended for backend systems
            - bypassing security controls by spoofing device identifiers
            - exploiting weak service-to-service authentication

        Test Strategy:
        The scanner attempts requests that simulate calls from
        unauthenticated or improperly authenticated clients and
        observes whether device or workload-level controls are enforced.

        Potential Impact:
        If device or workload controls are weak, attackers may be able to:

            - access internal service endpoints
            - impersonate backend workloads
            - trigger internal processing tasks
            - manipulate system operations

        Expected Behavior:
        Systems should require strong authentication for service-to-service
        communication, validate device or workload identities, and ensure
        that internal endpoints are protected by authentication and network
        restrictions.
        */

        private async Task<string> RunDeviceWorkloadControlsTestsAsync(Uri baseUri)
        {
            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, baseUri));
            var findings = new List<string>();

            if (response is null)
            {
                findings.Add("No response received.");
                return FormatSection("Security Headers", baseUri, findings);
            }

            findings.Add($"HTTP {(int)response.StatusCode} {response.StatusCode}");
            var requiredHeaders = new[]
            {
                    "Content-Security-Policy",
                    "X-Content-Type-Options",
                    "X-Frame-Options",
                    "Referrer-Policy"
                };

            foreach (var header in requiredHeaders)
            {
                findings.Add(HasHeader(response, header)
                ? $"Present: {header}"
                : $"Missing: {header}");
            }

            if (baseUri.Scheme == Uri.UriSchemeHttps)
            {
                findings.Add(response.Headers.Contains("Strict-Transport-Security")
                ? "Present: Strict-Transport-Security"
                : "Missing: Strict-Transport-Security");
            }

            return FormatSection("Security Headers", baseUri, findings);
        }
    }
}

