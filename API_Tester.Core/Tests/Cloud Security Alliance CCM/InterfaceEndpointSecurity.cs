namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Interface Endpoint Security Test

        Purpose:
        Checks whether API interfaces and exposed endpoints are properly
        secured and do not expose unintended functionality, administrative
        controls, or internal services.

        Threat Model:
        APIs often expose multiple endpoints for application functionality.
        If endpoints are poorly protected, undocumented, or left accessible
        without proper security controls, attackers may interact with them
        to gain unauthorized access or manipulate system behavior.

        Weak interface security may allow attackers to:

            - access internal or administrative endpoints
            - invoke hidden or undocumented functionality
            - bypass intended workflows or validation logic
            - discover debugging or diagnostic interfaces

        Common risky endpoints include:

            /admin
            /debug
            /internal
            /management
            /metrics
            /health
            /actuator

        While some endpoints may be legitimate, they should typically require
        authentication, be restricted to internal networks, or be disabled in
        production environments.

        Attack scenarios include:

            - accessing administrative panels without authentication
            - invoking internal APIs intended only for trusted services
            - retrieving operational data from monitoring or metrics endpoints
            - triggering debugging features or configuration interfaces

        Test Strategy:
        The scanner probes common administrative, management, and diagnostic
        paths to determine whether they are exposed or accessible without
        appropriate access controls.

        Potential Impact:
        If interface endpoints are improperly secured, attackers may be able to:

            - perform administrative actions
            - retrieve internal system information
            - manipulate system configuration
            - discover additional attack surface

        Expected Behavior:
        APIs should expose only necessary endpoints publicly. Administrative,
        management, and internal endpoints should require authentication,
        be restricted by network controls, or be disabled in production.
        */

        private async Task<string> RunInterfaceEndpointSecurityTestsAsync(Uri baseUri)
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

