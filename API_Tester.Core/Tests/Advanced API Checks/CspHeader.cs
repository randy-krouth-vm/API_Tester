namespace API_Tester;

public partial class MainPage
{
    /*
    Content Security Policy (CSP) Header Test

    Purpose:
    Checks whether the application includes a Content-Security-Policy (CSP)
    header in HTTP responses to restrict the sources from which scripts,
    styles, images, and other resources can be loaded.

    Threat Model:
    Without a properly configured CSP, attackers who discover cross-site
    scripting (XSS) injection points may be able to execute arbitrary
    JavaScript within a user's browser. A strong CSP limits where scripts
    can be loaded from and can significantly reduce the impact of XSS.

    Test Strategy:
    The scanner inspects response headers to determine whether a
    Content-Security-Policy header is present and whether it defines
    restrictive directives such as:

        default-src
        script-src
        object-src
        frame-ancestors
        base-uri

    The test may also identify overly permissive configurations such as:

        script-src *
        script-src 'unsafe-inline'
        script-src 'unsafe-eval'

    Potential Impact:
    Missing or weak CSP policies may allow attackers to:

        - execute injected JavaScript
        - load malicious scripts from external domains
        - bypass some client-side protections against XSS

    Expected Behavior:
    Applications should include a restrictive Content-Security-Policy header
    that limits resource loading to trusted origins and avoids unsafe
    directives wherever possible.
    */
    
    private async Task<string> RunCspHeaderTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, baseUri));
        if (response is null)
        {
            return FormatSection("CSP Header", baseUri, new[] { "No response." });
        }

        var csp = TryGetHeader(response, "Content-Security-Policy");
        var cspReportOnly = TryGetHeader(response, "Content-Security-Policy-Report-Only");
        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            string.IsNullOrWhiteSpace(csp) ? "Content-Security-Policy missing." : $"Content-Security-Policy: {csp}",
            string.IsNullOrWhiteSpace(cspReportOnly) ? "CSP-Report-Only not present." : $"CSP-Report-Only: {cspReportOnly}"
        };

        if (!string.IsNullOrWhiteSpace(csp) && ContainsAny(csp, "'unsafe-inline'", "'unsafe-eval'"))
        {
            findings.Add("Potential risk: CSP allows unsafe-inline and/or unsafe-eval.");
        }

        return FormatSection("CSP Header", baseUri, findings);
    }

}

