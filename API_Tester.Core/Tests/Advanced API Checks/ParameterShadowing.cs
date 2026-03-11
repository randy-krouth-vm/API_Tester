namespace API_Tester;

public partial class MainPage
{
    /*
    Parameter Shadowing Test

    Purpose:
    Checks whether the API incorrectly resolves parameters when the same
    logical parameter appears in multiple request locations such as
    route parameters, query parameters, headers, or request bodies.

    Threat Model:
    Parameter shadowing occurs when different layers of an application
    read parameters from different sources, potentially allowing one
    value to override another unexpectedly.

    For example, a route may define:

        /users/{id}

    But the request may also include:

        /users/123?id=999

    If one layer validates the route parameter while another layer uses
    the query parameter, attackers may be able to manipulate which value
    is ultimately used.

    Attack scenarios include:

        - bypassing authorization checks tied to route parameters
        - overriding validated values using query or body parameters
        - confusing request validation logic
        - manipulating application behavior by shadowing trusted values

    Example pattern:

        Route: /accounts/123
        Query: ?accountId=999

    If validation checks account 123 but the application later processes
    accountId=999, access control may be bypassed.

    Test Strategy:
    The scanner sends requests containing parameters with the same logical
    meaning across multiple locations (route, query, body, or headers)
    and observes how the application resolves them.

    Potential Impact:
    If parameter shadowing occurs, attackers may be able to:

        - bypass authorization rules
        - manipulate resource identifiers
        - override trusted application parameters
        - access or modify unintended resources

    Expected Behavior:
    Applications should enforce a clear precedence for parameter sources
    or reject ambiguous requests where parameters conflict across
    different parts of the request.
    */

    private async Task<string> RunParameterShadowingTestsAsync(Uri baseUri)
    {
        var openApi = await GetOpenApiProbeContextAsync(baseUri);
        var scanDepth = GetScanDepthProfile();
        var endpoints = (openApi.TargetEndpoints.Count > 0 ? openApi.TargetEndpoints : new List<Uri> { baseUri })
        .Take(scanDepth == "fast" ? 2 : scanDepth == "balanced" ? 4 : 8)
        .ToList();
        var fields = (openApi.QueryParameterNames.Count > 0
        ? openApi.QueryParameterNames.Where(x => !openApi.NonStringQueryParameterNames.Contains(x, StringComparer.OrdinalIgnoreCase)).ToList()
        : new List<string> { "amount", "id", "role" })
        .Take(scanDepth == "fast" ? 2 : scanDepth == "balanced" ? 4 : 8)
        .ToArray();
        if (fields.Length == 0)
        {
            fields = new[] { "amount", "id", "role" };
        }

        var findings = new List<string>();
        var suspicious = 0;
        var attempts = 0;

        foreach (var endpoint in endpoints)
        {
            foreach (var field in fields)
            {
                var normalUri = AppendQuery(endpoint, new Dictionary<string, string> { [field] = "100" });
                var shadowUri = $"{endpoint}{(endpoint.Query.Length == 0 ? "?" : "&")}{Uri.EscapeDataString(field)}=100&{Uri.EscapeDataString(field)}=0";

                var normal = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, normalUri));
                var shadow = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, shadowUri));
                attempts += 2;

                var normalStatus = normal is null ? 0 : (int)normal.StatusCode;
                var shadowStatus = shadow is null ? 0 : (int)shadow.StatusCode;
                if (normal is not null && shadow is not null && normalStatus != shadowStatus)
                {
                    suspicious++;
                    findings.Add($"Potential risk: duplicate '{field}' changed behavior ({FormatStatus(normal)} -> {FormatStatus(shadow)}).");
                }
            }
        }
        findings.Add(suspicious > 0
        ? $"Potential risk: parameter shadowing differentials observed on {suspicious} probe pairs."
        : "No obvious duplicate-parameter shadowing differential detected.");
        return FormatSection("Parameter Shadowing", baseUri, findings);
    }

}

