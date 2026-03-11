namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Identification and Authentication Practices Test

        Purpose:
        Evaluates whether the API enforces proper identification and
        authentication practices before allowing access to protected
        resources or operations.

        Threat Model:
        Identification determines who the requester claims to be, while
        authentication verifies that claim using credentials such as
        passwords, tokens, certificates, or multi-factor authentication.

        If identification or authentication controls are weak or missing,
        attackers may gain unauthorized access to systems, impersonate
        users, or interact with protected endpoints without credentials.

        Common weaknesses include:

            - endpoints accessible without authentication
            - accepting invalid or expired authentication tokens
            - inconsistent authentication enforcement across endpoints
            - allowing credentials to be transmitted insecurely
            - weak validation of authentication headers

        Example scenario:

            Request:
                GET /api/account/profile

        If the endpoint does not require authentication or incorrectly
        accepts invalid credentials, an attacker may access sensitive
        account data without being properly verified.

        Attack scenarios include:

            - accessing protected resources without authentication
            - bypassing login mechanisms
            - using malformed or expired tokens that are still accepted
            - exploiting inconsistent authentication enforcement

        Test Strategy:
        The scanner submits requests with missing, invalid, or manipulated
        authentication credentials and analyzes whether the server properly
        rejects unauthorized access attempts.

        Potential Impact:
        If identification and authentication practices are weak, attackers
        may be able to:

            - access sensitive user or system data
            - impersonate legitimate users
            - bypass login or authentication mechanisms
            - escalate privileges within the system

        Expected Behavior:
        Applications should require strong authentication for protected
        endpoints, validate credentials or tokens securely, enforce
        consistent authentication checks across all interfaces, and reject
        unauthenticated or improperly authenticated requests.
        */
        
        private async Task<string> RunIdentificationAndAuthenticationPracticesTestsAsync(Uri baseUri)
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

