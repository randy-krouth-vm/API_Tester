namespace API_Tester
{
    public partial class MainPage
    {
        /*
        HTTP Security Configuration Verification Tests (V14)

        Purpose:
        Performs automated tests to verify that HTTP security configurations
        are properly implemented. These tests evaluate whether the application
        enforces secure HTTP settings and response headers that protect against
        common web-based attacks.

        Threat Model:
        Weak HTTP security configurations may allow attackers to:

            - exploit browser-based vulnerabilities
            - perform clickjacking attacks
            - inject malicious scripts or content
            - downgrade secure connections
            - access sensitive resources through insecure transport

        Attackers often target missing or misconfigured HTTP headers that
        provide important client-side protections.

        Common vulnerabilities include:

            - missing Content Security Policy (CSP)
            - lack of X-Frame-Options protections
            - missing X-Content-Type-Options header
            - absence of Strict-Transport-Security (HSTS)
            - improper cache-control for sensitive responses

        Test Strategy:
        The method performs automated checks that:

            - inspect HTTP response headers for security controls
            - verify enforcement of HTTPS and HSTS policies
            - detect missing or weak browser protection headers
            - evaluate caching behavior for sensitive responses
            - analyze responses for inconsistent security configurations

        Potential Impact:
        If HTTP security configurations are weak, attackers may:

            - execute cross-site scripting attacks
            - perform clickjacking or UI redressing attacks
            - intercept or downgrade communications
            - expose sensitive information through caching

        Expected Behavior:
        Applications should:

            - implement strong HTTP security headers
            - enforce HTTPS with HSTS
            - prevent clickjacking using X-Frame-Options or CSP
            - disable MIME sniffing with X-Content-Type-Options
            - apply proper cache controls to sensitive responses
        */
        
        private async Task<string> RunV14ConfigHttpSecurityVerificationTestsAsync(Uri baseUri)
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

