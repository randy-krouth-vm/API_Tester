namespace API_Tester;

public partial class MainPage
{
    /*
    DOM-Based XSS Signal Test

    Purpose:
    Attempts to detect signals that the application may contain
    DOM-based cross-site scripting (XSS) vulnerabilities.

    Threat Model:
    DOM-based XSS occurs when client-side JavaScript reads data from
    untrusted sources (such as URL parameters, fragments, or document
    properties) and injects it into the page without proper sanitization.

    Common sources of DOM input include:

        location.search
        location.hash
        document.URL
        document.referrer
        window.name

    If this data is inserted into the DOM using unsafe methods, attackers
    may be able to execute arbitrary JavaScript in a victim's browser.

    Test Strategy:
    The scanner sends requests containing common XSS markers and observes
    responses for patterns indicating that user-controlled input may be
    reflected into client-side scripts or page content.

    The test also looks for JavaScript patterns commonly associated with
    DOM-based XSS sinks, such as:

        document.write
        innerHTML
        outerHTML
        eval
        setTimeout
        setInterval

    Potential Impact:
    If DOM-based XSS is present, attackers may be able to:

        - execute malicious JavaScript in the user's browser
        - steal session cookies or tokens
        - perform actions on behalf of authenticated users
        - redirect users to malicious sites

    Expected Behavior:
    Applications should sanitize all user-controlled input before inserting
    it into the DOM and should avoid unsafe JavaScript APIs when processing
    external data.
    */
    
    private async Task<string> RunDomXssSignalTestsAsync(Uri baseUri)
    {
        const string marker = "__apitester_dom_xss__<svg/onload=alert(1)>";
        var probeUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["q"] = marker,
            ["search"] = marker,
            ["next"] = marker
        });

        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, probeUri));
        var body = await ReadBodyAsync(response);
        var reflected = body.Contains(marker, StringComparison.OrdinalIgnoreCase) ||
        body.Contains(Uri.EscapeDataString(marker), StringComparison.OrdinalIgnoreCase);
        var domSink = ContainsAny(body, "innerHTML", "document.write(", "location.hash", "eval(", "outerHTML");

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            reflected ? "Input marker reflected in response." : "No obvious marker reflection.",
            domSink ? "DOM sink patterns detected in client script." : "No common DOM sink pattern detected.",
            reflected && domSink
            ? "Potential risk: reflected input + DOM sink pattern may indicate DOM-XSS exposure."
            : "No obvious DOM-XSS signal from this lightweight probe."
        };

        return FormatSection("DOM XSS Signals", probeUri, findings);
    }

}

