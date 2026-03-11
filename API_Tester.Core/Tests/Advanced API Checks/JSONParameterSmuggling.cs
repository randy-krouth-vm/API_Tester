namespace API_Tester;

public partial class MainPage
{
    /*
    JSON Parameter Smuggling Test

    Purpose:
    Checks whether the API processes duplicate, conflicting, or hidden JSON
    parameters inconsistently between parsing layers.

    Threat Model:
    In some architectures, JSON payloads may be parsed by multiple components
    such as API gateways, middleware, validation layers, and application
    controllers. If these components interpret duplicate keys or nested
    parameters differently, attackers may be able to smuggle unexpected
    values past validation logic.

    Example JSON payload:
    {
        "role": "user",
        "role": "admin"
    }

    Some parsers may use the first value while others use the last. If a
    security check validates one value but the application later processes
    another, the attacker may bypass authorization or input validation.

    Test Strategy:
    The scanner sends JSON payloads containing duplicated keys, nested
    parameter structures, or conflicting values and observes how the server
    handles them.

    Potential Impact:
    If JSON parameter parsing is inconsistent, attackers may be able to:

        - bypass validation rules
        - override trusted values
        - manipulate application logic
        - bypass authorization checks

    Expected Behavior:
    Applications should reject JSON payloads containing duplicate keys or
    ambiguous structures and ensure that all layers of the system interpret
    JSON inputs consistently.
    */

    private async Task<string> RunJsonParameterSmugglingTestsAsync(Uri baseUri)
    {
        var openApi = await GetOpenApiProbeContextAsync(baseUri);
        var scanDepth = GetScanDepthProfile();
        var endpoints = (openApi.TargetEndpoints.Count > 0 ? openApi.TargetEndpoints : new List<Uri> { baseUri })
        .Take(scanDepth == "fast" ? 2 : scanDepth == "balanced" ? 4 : 8)
        .ToList();
        var field = openApi.BodyPropertyNames
        .FirstOrDefault(x => !openApi.NonStringBodyPropertyNames.Contains(x, StringComparer.OrdinalIgnoreCase))
        ?? "amount";
        var variants = new[]
        {
            $"{{\"{field}\":100,\"{field}\":0}}",
            $"{{\"{field}\":100,\"{char.ToUpperInvariant(field[0])}{field[1..]}\":0}}",
            $"{{\"{field}\":100,\"{field} \":0}}",
            $"{{\"{field}\":100,\"{field}\\u0000\":0}}"
        };

        var findings = new List<string>();
        var suspicious = 0;
        var attempts = 0;

        foreach (var endpoint in endpoints)
        {
            foreach (var body in variants)
            {
                var response = await SafeSendAsync(() =>
                {
                    var req = new HttpRequestMessage(HttpMethod.Post, endpoint);
                    req.Content = new StringContent(body, Encoding.UTF8, "application/json");
                    return req;
                });
                attempts++;
                if (response is not null && (int)response.StatusCode is >= 200 and < 300)
                {
                    suspicious++;
                }
            }
        }
        findings.Add(suspicious > 0
        ? $"Potential risk: ambiguous/duplicate JSON key variants accepted on {suspicious}/{attempts} probes."
        : "No obvious JSON parameter smuggling acceptance across tested variants.");
        return FormatSection("JSON Parameter Smuggling", baseUri, findings);
    }

}

