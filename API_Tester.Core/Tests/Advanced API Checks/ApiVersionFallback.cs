namespace API_Tester;

public partial class MainPage
{
    /*
    API Version Fallback Test

    Purpose:
    Tests whether the API automatically falls back to a default or legacy
    version when a requested version does not exist.

    Threat Model:
    Some APIs silently redirect or fall back to older versions (e.g. v1)
    when a client requests an invalid or unsupported version. This behavior
    can expose deprecated API functionality that may contain weaker
    authentication, outdated validation logic, or previously patched flaws.

    Test Strategy:
    The scanner sends requests using non-existent or unexpected API version
    identifiers and observes whether the server returns responses from a
    valid version instead of rejecting the request.

    Potential Impact:
    If fallback occurs, an attacker may intentionally request unsupported
    versions to access legacy endpoints that bypass newer security controls.

    Expected Behavior:
    The server should return an error such as 404 (Not Found) or
    400 (Invalid API version) rather than silently routing the request
    to another version.
    */
    
    private async Task<string> RunApiVersionFallbackTestsAsync(Uri baseUri)
    {
        var scanDepth = GetScanDepthProfile();
        var findings = new List<string>();
        var candidates = new[]
        {
            "/api/v3/users",
            "/api/v2/users",
            "/api/v1/users",
            "/v3",
            "/v2",
            "/v1"
        };
        candidates = LimitByScanDepth(candidates, fastCount: 3, balancedCount: 5);
        var statuses = new List<(string Path, HttpStatusCode? Status)>();
        foreach (var path in candidates)
        {
            var uri = new Uri(baseUri, path);
            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, uri));
            statuses.Add((path, response?.StatusCode));
            findings.Add($"{path}: {FormatStatus(response)}");
        }

        var weakFallback = statuses.Any(s => s.Path.Contains("/v1", StringComparison.OrdinalIgnoreCase) && s.Status is HttpStatusCode.OK);
        findings.Add(weakFallback
        ? "Potential risk: legacy API version appears accessible (fallback/rollback exposure)."
        : "No obvious legacy version fallback exposure detected.");
        return FormatSection("API Version Fallback", baseUri, findings);
    }

}

