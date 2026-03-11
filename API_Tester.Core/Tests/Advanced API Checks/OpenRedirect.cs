namespace API_Tester;

public partial class MainPage
{
    /*
    Open Redirect Test

    Purpose:
    Checks whether the application allows user-controlled input to determine
    redirect destinations without proper validation.

    Threat Model:
    Open redirect vulnerabilities occur when an application accepts a URL
    parameter (such as "redirect", "returnUrl", or "next") and redirects the
    user to that location without verifying that the destination is trusted.

    Attackers may craft links that appear to originate from a legitimate
    site but redirect victims to malicious websites.

    Attack scenarios include:

        - phishing campaigns using trusted domains
        - redirecting users to credential harvesting pages
        - chaining redirects into OAuth or authentication flows
        - abusing trusted domains to bypass security filters

    Example vulnerable pattern:

        https://example.com/login?redirect=https://attacker.com

    If the application redirects directly to the supplied URL, the attacker
    can abuse the trusted domain to lure users.

    Test Strategy:
    The scanner sends requests containing external or manipulated redirect
    parameters and observes whether the server performs the redirect.

    Potential Impact:
    If open redirects are present, attackers may be able to:

        - trick users into visiting malicious websites
        - steal login credentials through phishing attacks
        - abuse OAuth or authentication flows
        - bypass URL allowlists or security filters

    Expected Behavior:
    Applications should validate redirect destinations against an allowlist
    of trusted domains or restrict redirects to internal paths only.
    Untrusted redirect targets should be rejected or ignored.
    */
    
    private async Task<string> RunOpenRedirectTestsAsync(Uri baseUri)
    {
        var testUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["redirect"] = "https://example.invalid",
            ["next"] = "https://example.invalid"
        });

        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, testUri));
        var body = await ReadBodyAsync(response);
        var location = response is null ? string.Empty : TryGetHeader(response, "Location");

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            (!string.IsNullOrWhiteSpace(location) && location.Contains("example.invalid", StringComparison.OrdinalIgnoreCase)) ||
            body.Contains("example.invalid", StringComparison.OrdinalIgnoreCase)
            ? "Potential risk: redirect target reflected or accepted."
            : "No obvious open redirect indicator found."
        };

        return FormatSection("Open Redirect", testUri, findings);
    }

}

