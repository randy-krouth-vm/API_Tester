namespace API_Tester;

public partial class MainPage
{
    /*
    Clickjacking Protection Header Test

    Purpose:
    Checks whether HTTP responses include headers that prevent the application
    from being embedded inside frames or iframes on external websites.

    Threat Model:
    Clickjacking is a UI redressing attack where a malicious site embeds the
    target application inside an invisible or disguised frame and tricks users
    into clicking buttons or performing actions unknowingly.

    Without proper protections, attackers may cause users to:

        - Authorize unintended actions
        - Change account settings
        - Trigger transactions
        - Perform administrative operations

    Test Strategy:
    The scanner inspects responses for headers designed to block framing,
    including:

        X-Frame-Options
        Content-Security-Policy (frame-ancestors directive)

    Secure configurations typically include:

        X-Frame-Options: DENY
        X-Frame-Options: SAMEORIGIN

    or

        Content-Security-Policy: frame-ancestors 'none'
        Content-Security-Policy: frame-ancestors 'self'

    Potential Impact:
    If these protections are missing, attackers may embed the application
    in hidden frames and trick users into interacting with the interface
    without their knowledge.

    Expected Behavior:
    Applications should send appropriate anti-framing headers to prevent
    unauthorized embedding of sensitive pages.
    */

    private async Task<string> RunClickjackingHeaderTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, baseUri));
        if (response is null)
        {
            return FormatSection("Clickjacking Headers", baseUri, new[] { "No response." });
        }

        var xfo = TryGetHeader(response, "X-Frame-Options");
        var csp = TryGetHeader(response, "Content-Security-Policy");
        var hasFrameAncestors = csp.Contains("frame-ancestors", StringComparison.OrdinalIgnoreCase);

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            string.IsNullOrWhiteSpace(xfo) ? "X-Frame-Options missing." : $"X-Frame-Options: {xfo}",
            hasFrameAncestors ? "CSP frame-ancestors present." : "CSP frame-ancestors not found."
        };

        if (string.IsNullOrWhiteSpace(xfo) && !hasFrameAncestors)
        {
            findings.Add("Potential risk: no visible clickjacking frame protections.");
        }

        return FormatSection("Clickjacking Headers", baseUri, findings);
    }

}

