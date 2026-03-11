namespace API_Tester;

public partial class MainPage
{
    /*
    API Version Discovery Test

    Purpose:
    Attempts to identify exposed API versions and documentation endpoints.

    Threat Model:
    Version enumeration itself is not typically a vulnerability, but it can
    reveal additional attack surface. Older or undocumented API versions
    may remain enabled and contain weaker authentication, outdated
    validation logic, or forgotten internal endpoints.

    Endpoints commonly discovered include:
    - Versioned APIs (/v1, /v2, /api/v1)
    - Documentation endpoints (/swagger, /openapi.json)
    - Development or internal routes (/dev, /internal)

    Potential Impact:
    Attackers may use discovered endpoints to access deprecated APIs,
    bypass security controls, or obtain full API specifications.

    Expected Behavior:
    Production environments should disable or restrict unnecessary
    documentation endpoints and ensure deprecated API versions are removed
    or properly secured.
    */
    
    private async Task<string> RunApiVersionDiscoveryTestsAsync(Uri baseUri)
    {
        var paths = new[] { "/v1", "/v2", "/v3", "/beta", "/internal", "/swagger", "/openapi.json" };
        var findings = new List<string>();
        foreach (var path in paths)
        {
            var uri = new Uri(baseUri, path);
            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, uri));
            findings.Add($"{path}: {FormatStatus(response)}");
        }

        return FormatSection("API Version Discovery", baseUri, findings);
    }

}

