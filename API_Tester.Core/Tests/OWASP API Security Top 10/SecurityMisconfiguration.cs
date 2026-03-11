namespace API_Tester
{
    public partial class MainPage
    {
        /*
        OWASP API Security Top 10 – Security Misconfiguration Tests

        Purpose:
        Performs automated tests to evaluate whether the application suffers
        from security misconfigurations. Misconfigurations are among the most
        common causes of security vulnerabilities in APIs and infrastructure.

        Threat Model:
        Security misconfiguration occurs when systems, frameworks, or services
        are deployed with insecure settings or default configurations. Attackers
        may attempt to exploit these weaknesses to:

            - access administrative interfaces
            - retrieve debug or diagnostic information
            - exploit exposed services or default credentials
            - gain insight into system architecture

        Common vulnerabilities include:

            - default credentials left enabled
            - unnecessary services or features exposed
            - verbose error messages revealing system details
            - improperly configured security headers
            - exposed configuration files or administrative endpoints
            - insecure cloud or container configuration settings

        Test Strategy:
        The method performs automated checks that:

            - inspect responses for debug or verbose error information
            - probe for exposed configuration files or administrative interfaces
            - evaluate security headers and configuration settings
            - detect default or insecure service configurations
            - identify exposed framework or infrastructure metadata

        Potential Impact:
        If security misconfigurations exist, attackers may:

            - gain insight into internal system structure
            - exploit exposed administrative interfaces
            - bypass security protections
            - access sensitive configuration information

        Expected Behavior:
        Applications should:

            - disable unnecessary services and debug features
            - use secure configuration baselines
            - restrict access to administrative interfaces
            - minimize information exposure in error responses
            - regularly audit and validate configuration settings
        */
        
        private async Task<string> RunOWASPAPISecurityTop10SecurityMisconfigurationTestsAsync(Uri baseUri)
        {
            var headers = await RunSecurityHeaderTestsAsync(baseUri);
            var cors = await RunCorsTestsAsync(baseUri);
            var methods = await RunHttpMethodTestsAsync(baseUri);
            return $"{headers}{Environment.NewLine}{Environment.NewLine}{cors}{Environment.NewLine}{Environment.NewLine}{methods}";
        }
    }
}

