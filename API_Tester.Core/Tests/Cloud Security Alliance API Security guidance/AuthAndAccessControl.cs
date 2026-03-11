namespace API_Tester;

public partial class MainPage
{
    /*
    Authentication and Access Control Test

    Purpose:
    Checks whether the API properly enforces authentication and authorization
    controls to ensure that only authorized users can access protected
    resources and perform sensitive operations.

    Threat Model:
    Authentication verifies the identity of a user or client, while
    authorization determines what actions that identity is allowed to
    perform. If these controls are weak or improperly implemented,
    attackers may access resources without proper credentials or perform
    actions beyond their permissions.

    Common weaknesses include:

        - endpoints accessible without authentication
        - missing authorization checks for sensitive operations
        - inconsistent access control across endpoints
        - trusting client-supplied identifiers or roles
        - exposing administrative functionality without restrictions

    Example scenario:

        Endpoint:
            GET /api/users/123

    If the server only checks that the user is authenticated but does not
    verify ownership or permissions, one user may retrieve another user's
    data by modifying the identifier.

    Attack scenarios include:

        - accessing other users' data (IDOR / broken object-level authorization)
        - invoking administrative endpoints without proper privileges
        - bypassing authentication for protected resources
        - escalating privileges through missing role validation

    Test Strategy:
    The scanner sends requests with missing, invalid, or manipulated
    authentication tokens and attempts to access protected endpoints or
    resources belonging to other users. Responses are analyzed to determine
    whether authentication and authorization checks are consistently
    enforced.

    Potential Impact:
    If authentication or access control is weak, attackers may be able to:

        - access sensitive user data
        - modify or delete resources without permission
        - escalate privileges
        - execute administrative actions

    Expected Behavior:
    All protected endpoints should require valid authentication, and
    authorization checks should verify that the authenticated user has
    permission to perform the requested action. Access control decisions
    should be enforced server-side and must not rely on client-supplied
    data.
    */
    
    private async Task<string> RunAuthAndAccessControlTestsAsync(Uri baseUri)
    {
        var activeKey = _activeStandardTestKey.Value;
        var findings = new List<string>();
        findings.Add($"Probe profile: {(string.IsNullOrWhiteSpace(activeKey) ? "default" : activeKey)}");
        var probes = BuildAuthProbeRequests(baseUri, activeKey);
        var accepted = 0;
        var blocked = 0;
        var noResponse = 0;

        foreach (var probe in probes)
        {
            var response = await SafeSendAsync(() => probe.BuildRequest());
            if (response is null)
            {
                noResponse++;
                findings.Add($"{probe.Name}: no response");
                continue;
            }

            var status = (int)response.StatusCode;
            findings.Add($"{probe.Name}: HTTP {status} {response.StatusCode}");
            if (status is >= 200 and < 300)
            {
                accepted++;
            }
            else if (status is 401 or 403)
            {
                blocked++;
            }
        }

        findings.Add(accepted > 0
        ? $"Potential risk: {accepted}/{probes.Count} auth probes were accepted."
        : blocked > 0
        ? $"Auth barrier observed in {blocked}/{probes.Count} probes."
        : noResponse == probes.Count
        ? "No auth probe responses received."
        : "No obvious auth barrier signal from current probes.");
        return FormatSection("Authentication and Access Control", baseUri, findings);
    }

}

