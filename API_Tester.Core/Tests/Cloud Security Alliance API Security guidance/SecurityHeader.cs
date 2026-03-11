namespace API_Tester;

public partial class MainPage
{
    /*
    Security Header Configuration Test

    Purpose:
    Checks whether the application includes recommended HTTP security
    headers that help protect clients against common browser-based attacks
    such as clickjacking, cross-site scripting (XSS), and insecure content
    loading.

    Threat Model:
    Modern browsers rely on security headers to enforce protections at the
    client side. If these headers are missing or misconfigured, attackers
    may exploit browser behavior to inject scripts, frame the application,
    or load insecure resources.

    Common security headers include:

        - Content-Security-Policy (CSP)
        - X-Frame-Options
        - X-Content-Type-Options
        - Strict-Transport-Security (HSTS)
        - Referrer-Policy
        - Permissions-Policy

    Example protections provided by these headers:

        Content-Security-Policy
            Restricts which scripts, images, and resources the browser
            is allowed to load, helping prevent XSS attacks.

        X-Frame-Options
            Prevents the site from being embedded in an iframe,
            mitigating clickjacking attacks.

        X-Content-Type-Options
            Prevents browsers from MIME-type sniffing, reducing the risk
            of malicious file execution.

        Strict-Transport-Security
            Forces browsers to use HTTPS for future requests, preventing
            downgrade attacks.

    Attack scenarios include:

        - injecting malicious scripts when CSP is missing
        - embedding the application in a malicious iframe (clickjacking)
        - loading mixed or insecure resources
        - leaking referrer information to third-party sites

    Test Strategy:
    The scanner sends requests to the target endpoint and inspects HTTP
    response headers to determine whether recommended security headers
    are present and correctly configured.

    Potential Impact:
    If security headers are missing or misconfigured, attackers may be able to:

        - perform clickjacking attacks
        - exploit browser content sniffing behavior
        - inject or execute malicious scripts
        - expose sensitive referrer information

    Expected Behavior:
    Applications should include appropriate security headers in HTTP
    responses to enforce browser-level protections and reduce exposure
    to client-side attack vectors.
    */

    private async Task<string> RunSecurityHeaderTestsAsync(Uri baseUri)
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

