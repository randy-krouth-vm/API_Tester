namespace API_Tester;

public partial class MainPage
{
    /*
    Log Poisoning Test

    Purpose:
    Checks whether user-controlled input can inject malicious or misleading
    entries into application logs.

    Threat Model:
    Applications often record request data such as headers, query parameters,
    user agents, or request bodies in server logs for debugging, monitoring,
    or auditing. If user input is written directly to logs without proper
    sanitization, attackers may be able to manipulate the log contents.

    Attack techniques may include:

        - injecting newline characters to create fake log entries
        - inserting control characters that alter log formatting
        - embedding misleading messages that hide malicious activity
        - injecting payloads that trigger log processing tools

    For example, an attacker may send a request containing:

        "User-Agent: attacker\n[INFO] Admin login successful"

    If the input is written directly to logs, it may appear as a legitimate
    log entry and mislead administrators during incident investigations.

    Test Strategy:
    The scanner sends requests containing payloads designed to manipulate
    log formatting or inject new log entries. It observes the server response
    and records whether the request is accepted or handled normally.

    Potential Impact:
    If log poisoning is possible, attackers may be able to:

        - hide malicious activity in logs
        - mislead incident response investigations
        - manipulate monitoring or alerting systems
        - inject payloads that execute in log viewers or analysis tools

    Expected Behavior:
    Applications should sanitize or encode user input before writing it to
    logs and should prevent control characters or newline injection from
    altering log structure.
    */

    private async Task<string> RunLogPoisoningTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
            req.Headers.TryAddWithoutValidation("User-Agent", "apitester\r\nX-Log-Injection: true");
            req.Headers.TryAddWithoutValidation("X-Correlation-ID", "corr-123\r\ninjected=true");
            return req;
        });
        var body = await ReadBodyAsync(response);

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            ContainsAny(body, "X-Log-Injection", "injected=true")
            ? "Potential risk: log/header injection markers reflected."
            : "No obvious log poisoning reflection indicator."
        };

        return FormatSection("Log Poisoning", baseUri, findings);
    }

}

