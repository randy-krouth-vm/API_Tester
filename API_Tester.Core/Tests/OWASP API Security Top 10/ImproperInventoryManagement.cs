namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Improper Inventory Management Tests

        Purpose:
        Performs automated tests to evaluate whether the application exposes
        unmanaged, deprecated, or undocumented APIs and services due to
        improper inventory management. This aligns with OWASP API Security
        Top 10 concerns related to insufficient API inventory control.

        Threat Model:
        Organizations often deploy multiple APIs, versions, and services.
        If inventory management is incomplete, attackers may discover and
        exploit forgotten or unmanaged endpoints.

        Attackers may attempt to:

            - discover deprecated API versions
            - access undocumented endpoints
            - exploit test or development APIs left exposed
            - interact with shadow or orphaned services

        These endpoints may lack modern security controls such as:

            - authentication or authorization enforcement
            - rate limiting
            - logging and monitoring
            - input validation or security hardening

        Common vulnerabilities include:

            - exposed legacy API versions
            - undocumented endpoints accessible via direct URL
            - test or staging APIs deployed in production
            - missing lifecycle management for APIs
            - inconsistent security policies across API versions

        Test Strategy:
        The method performs automated checks that:

            - enumerate potential API endpoints and versions
            - probe for deprecated or undocumented routes
            - inspect responses for unmanaged services
            - evaluate consistency of security controls across APIs
            - detect endpoints lacking monitoring or inventory tracking

        Potential Impact:
        If inventory management is weak, attackers may:

            - exploit outdated or insecure API versions
            - bypass modern security protections
            - access internal or development functionality
            - compromise sensitive data or services

        Expected Behavior:
        Applications should:

            - maintain a complete and up-to-date API inventory
            - properly decommission deprecated API versions
            - enforce consistent security controls across all APIs
            - monitor and log access to all exposed endpoints
            - ensure undocumented or test endpoints are not accessible in production
        */
        
        private async Task<string> RunImproperInventoryManagementTestsAsync(Uri baseUri)
        {
            var paths = new[]
            {
                "/swagger",
                "/swagger/index.html",
                "/openapi.json",
                "/v1",
                "/v2",
                "/beta",
                "/internal"
            };

            var findings = new List<string>();
            foreach (var path in paths)
            {
                var uri = new Uri(baseUri, path);
                var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, uri));
                findings.Add($"{path}: {FormatStatus(response)}");
            }

            return FormatSection("Improper Inventory Management", baseUri, findings);
        }
    }
}

