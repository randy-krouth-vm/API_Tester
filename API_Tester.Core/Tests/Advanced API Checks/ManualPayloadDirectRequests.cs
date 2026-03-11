namespace API_Tester;

public partial class MainPage
{
    /*
    Manual Payload Direct Requests Test

    Purpose:
    Sends a set of predefined payloads as query parameters to various endpoints 
    in the application to test for vulnerabilities like SQL injection, XSS, SSRF, 
    and command injection.

    Threat Model:
    Applications often accept user input through query parameters, form fields, 
    or headers without sufficient sanitization. This input may be directly reflected 
    or processed in ways that lead to vulnerabilities. Attackers can exploit this 
    by injecting malicious payloads through these entry points.

    Attack techniques may include:

        - injecting malicious scripts (XSS)
        - bypassing authentication (SQL injection)
        - manipulating server-side processing (SSRF, command injection)
        - triggering unexpected behaviors via path traversal or file inclusion

    For example, an attacker may send a request containing:

        "?username=<script>alert('XSS')</script>"

    If the application does not properly sanitize the input, the script may execute 
    in the user's browser, potentially leading to session hijacking, data theft, or 
    other malicious actions.

    Test Strategy:
    The scanner sends requests containing payloads designed to exploit potential 
    vulnerabilities in various entry fields (e.g., query parameters, URL paths). 
    It observes the server response to determine if any of the payloads cause 
    unexpected behavior or vulnerabilities.

    Potential Impact:
    If an application is vulnerable to the tested payloads, attackers may be able to:

        - execute scripts in user browsers (XSS)
        - execute unauthorized database queries (SQL injection)
        - access internal systems or services (SSRF)
        - execute arbitrary system commands (command injection)
        - access sensitive files or data (file inclusion, path traversal)

    Expected Behavior:
    Applications should properly sanitize or encode user input to prevent injection 
    attacks. The application should not reflect malicious payloads, execute 
    unauthorized queries, or allow unintended system commands to run.
    */
    
    private async Task<string> RunManualPayloadDirectRequestsAsync(Uri baseUri)
    {
        var targets = GetManualPayloadDirectRequestUrls();
        var findings = new List<string>();

        if (targets.Length == 0)
        {
            findings.Add("No direct-request payloads found (add http/https lines in Manual Payloads).");
            return FormatSection("Manual Payload Direct Requests", baseUri, findings);
        }

        foreach (var target in targets)
        {
            if (!Uri.TryCreate(target, UriKind.Absolute, out var uri))
            {
                findings.Add($"{target}: invalid URL.");
                continue;
            }

            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, uri));
            findings.Add($"{uri}: {FormatStatus(response)}");
        }

        return FormatSection("Manual Payload Direct Requests", baseUri, findings);
    }
}
