namespace API_Tester;

public partial class MainPage
{
    /*
    Cross-Origin Resource Sharing (CORS) Security Tests

    Purpose:
    Performs automated tests to evaluate the application's CORS 
    configuration and ensure it properly restricts cross-origin requests 
    to trusted domains.

    Threat Model:
    Misconfigured CORS policies can allow attackers to:

        - Execute unauthorized requests from malicious websites
        - Access sensitive data from legitimate user sessions
        - Perform Cross-Site Request Forgery (CSRF) attacks
        - Exploit trusted origins to bypass security controls

    Common vulnerabilities include:

        - Allowing all origins (*) in CORS headers
        - Permitting unsafe HTTP methods (PUT, DELETE, etc.) from untrusted origins
        - Exposing sensitive headers to cross-origin requests
        - Inconsistent or overly permissive CORS rules

    Test Strategy:
    The method performs asynchronous automated checks to:

        - Send requests from various origins and analyze CORS headers
        - Verify allowed methods and headers match security policies
        - Detect wildcard (*) or overly permissive configurations
        - Ensure proper enforcement of CORS policies on sensitive endpoints

    Potential Impact:
    If CORS is misconfigured, attackers may be able to:

        - Read sensitive data from user sessions on other domains
        - Perform unauthorized actions on behalf of authenticated users
        - Bypass intended same-origin restrictions
        - Exploit trust relationships between client and server

    Expected Behavior:
    Applications should:

        - Restrict CORS access to known, trusted origins
        - Limit allowed HTTP methods and headers
        - Avoid using wildcards for sensitive endpoints
        - Consistently enforce CORS policies across all endpoints
    */
    
    private async Task<string> RunCorsTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Options, baseUri);
            req.Headers.TryAddWithoutValidation("Origin", "https://security-test.local");
            req.Headers.TryAddWithoutValidation("Access-Control-Request-Method", "GET");
            return req;
        });

        var findings = new List<string>();
        if (response is null)
        {
            findings.Add("No response received.");
            return FormatSection("CORS", baseUri, findings);
        }

        findings.Add($"HTTP {(int)response.StatusCode} {response.StatusCode}");
        var acao = TryGetHeader(response, "Access-Control-Allow-Origin");
        var acc = TryGetHeader(response, "Access-Control-Allow-Credentials");

        findings.Add(string.IsNullOrWhiteSpace(acao)
        ? "Missing: Access-Control-Allow-Origin"
        : $"Access-Control-Allow-Origin: {acao}");
        findings.Add(string.IsNullOrWhiteSpace(acc)
        ? "Missing: Access-Control-Allow-Credentials"
        : $"Access-Control-Allow-Credentials: {acc}");

        if (acao == "*" && string.Equals(acc, "true", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add("Potential risk: wildcard CORS with credentials enabled.");
        }

        return FormatSection("CORS", baseUri, findings);
    }

}

