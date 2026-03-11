namespace API_Tester
{
    public partial class MainPage
    {
        /*
        IAM Control Objectives Test

        Purpose:
        Evaluates whether the API appears to follow core Identity and Access
        Management (IAM) security objectives such as proper authentication,
        authorization, role enforcement, and privilege separation.

        Threat Model:
        Identity and Access Management controls ensure that users and services
        can only access resources they are authorized to use. If IAM controls
        are weak or inconsistent, attackers may access protected resources,
        escalate privileges, or impersonate other users.

        Common IAM weaknesses include:

            - endpoints accessible without authentication
            - missing authorization checks on sensitive operations
            - trusting client-supplied user identifiers or roles
            - privilege escalation due to improper role validation
            - inconsistent enforcement of access control across endpoints

        Example scenario:

            Endpoint:
                GET /api/accounts/{accountId}

        If the application only checks that a user is authenticated but does
        not verify that the user owns or is authorized to access the requested
        account, an attacker may retrieve other users' data by modifying the
        identifier.

        Attack scenarios include:

            - accessing resources belonging to other users (IDOR)
            - escalating privileges by modifying role identifiers
            - performing administrative actions without proper permissions
            - invoking internal or restricted endpoints

        Test Strategy:
        The scanner attempts requests with missing, invalid, or manipulated
        identity tokens and observes whether the server enforces authentication
        and authorization consistently across endpoints.

        Potential Impact:
        If IAM controls are weak, attackers may be able to:

            - access sensitive user or organizational data
            - escalate privileges to administrative levels
            - modify or delete protected resources
            - impersonate legitimate users

        Expected Behavior:
        Applications should enforce authentication for protected endpoints,
        validate authorization server-side, apply role-based or attribute-based
        access control consistently, and avoid trusting client-supplied identity
        or privilege information.
        */
        
        private async Task<string> RunIamControlObjectivesTestsAsync(Uri baseUri)
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
}

