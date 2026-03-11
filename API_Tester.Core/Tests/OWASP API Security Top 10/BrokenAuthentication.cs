namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Broken Authentication Tests

        Purpose:
        Performs automated tests to evaluate the application’s authentication
        mechanisms for weaknesses that could allow attackers to bypass or
        compromise login protections.

        Threat Model:
        Broken authentication vulnerabilities occur when applications fail to
        properly verify user identity or protect authentication credentials.
        Attackers may attempt to:

            - bypass login mechanisms
            - exploit weak password policies
            - reuse stolen or leaked credentials
            - hijack active sessions

        Common vulnerabilities include:

            - weak password complexity or reuse policies
            - lack of multi-factor authentication (MFA)
            - insufficient protections against brute-force attacks
            - insecure session token handling
            - improper logout or session invalidation

        Test Strategy:
        The method performs automated checks that:

            - attempt authentication using invalid or manipulated credentials
            - evaluate enforcement of password policies and MFA
            - inspect session management and token handling
            - test protections against brute-force or credential stuffing attacks
            - detect endpoints that allow authentication bypass

        Potential Impact:
        If authentication controls are weak, attackers may:

            - gain unauthorized access to user accounts
            - impersonate legitimate users
            - access sensitive information or perform unauthorized actions
            - escalate privileges within the system

        Expected Behavior:
        Applications should:

            - enforce strong password policies
            - require multi-factor authentication where appropriate
            - protect authentication tokens and session identifiers
            - limit repeated failed login attempts
            - ensure authentication checks are consistently enforced
        */
        
        private async Task<string> RunBrokenAuthenticationTestsAsync(Uri baseUri)
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

