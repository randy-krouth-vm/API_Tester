namespace API_Tester;

public partial class MainPage
{
    /*
    Forced Browsing Tests

    Purpose:
    Performs automated tests to determine whether the application exposes
    restricted resources through direct URL access. Forced browsing occurs
    when attackers attempt to access hidden or protected pages by manually
    manipulating URL paths.

    Threat Model:
    If access controls are weak or improperly enforced, attackers may
    directly access sensitive resources that should require authentication
    or authorization. Attackers may attempt to:

        - access administrative panels
        - retrieve backup or configuration files
        - view internal application directories
        - reach undocumented endpoints

    Common vulnerabilities include:

        - missing authorization checks on sensitive endpoints
        - predictable or discoverable resource paths
        - improperly protected administrative interfaces
        - exposed development or debugging resources
        - publicly accessible backup or archive files

    Test Strategy:
    The method performs automated checks that:

        - request commonly restricted paths and administrative endpoints
        - attempt direct access to sensitive resources without authentication
        - inspect server responses for unauthorized data exposure
        - detect improperly protected directories or files
        - evaluate consistency of authorization enforcement

    Potential Impact:
    If forced browsing vulnerabilities exist, attackers may:

        - access restricted administrative functionality
        - retrieve sensitive system or configuration data
        - discover hidden endpoints for further exploitation
        - bypass intended application navigation or access controls

    Expected Behavior:
    Applications should:

        - enforce authorization checks on all protected resources
        - restrict access to administrative and internal endpoints
        - avoid exposing sensitive files or directories
        - return appropriate access control responses (e.g., 403/401)
        - monitor and log suspicious access attempts
    */
    private async Task<string> RunForcedBrowsingTestsAsync(Uri baseUri)
    {
        var sensitivePaths = new[]
        {
            "/admin",
            "/internal",
            "/debug",
            "/manage",
            "/actuator",
            "/console"
        };

        var profileName = _activeAuthProfile.Value?.Name ?? "unknown";
        var isAdminProfile = string.Equals(profileName, "admin", StringComparison.OrdinalIgnoreCase);
        var findings = new List<string>();
        var exposed = 0;

        foreach (var path in sensitivePaths)
        {
            var uri = new Uri(baseUri, path);
            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, uri));
            var body = await ReadBodyAsync(response);
            findings.Add($"{path}: {FormatStatus(response)}");

            if (response is not null && (int)response.StatusCode is >= 200 and < 400)
            {
                if (!isAdminProfile || ContainsAny(body, "admin", "debug", "internal", "manage"))
                {
                    exposed++;
                }
            }
        }

        findings.Insert(0, $"Auth profile: {profileName}");
        findings.Add(exposed > 0
        ? $"Potential risk: {exposed} sensitive routes appeared reachable for this profile."
        : "No obvious forced-browsing exposure across tested sensitive routes.");

        return FormatSection("Forced Browsing", baseUri, findings);
    }
}

