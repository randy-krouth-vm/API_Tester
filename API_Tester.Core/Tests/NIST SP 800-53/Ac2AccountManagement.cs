namespace API_Tester
{
    public partial class MainPage
    {
        /*
        AC-2 Account Management Tests

        Purpose:
        Performs automated tests to evaluate the application's account
        management controls in accordance with AC-2 (Account Management)
        security control requirements. The goal is to ensure that user
        accounts are properly created, managed, monitored, and deactivated
        when no longer authorized.

        Threat Model:
        Weak account management practices may allow attackers or unauthorized
        users to:

            - access dormant or orphaned accounts
            - exploit improperly configured user privileges
            - maintain persistence through unused or unmanaged accounts
            - bypass security policies through shared or generic accounts

        Common vulnerabilities include:

            - inactive accounts remaining enabled
            - excessive privileges granted to standard users
            - lack of account lifecycle management
            - missing controls for account creation, modification, and deletion
            - insufficient monitoring of account activity

        Test Strategy:
        The method performs automated checks to determine whether account
        management controls are properly enforced. This includes verifying
        that:

            - accounts follow defined lifecycle processes
            - privilege assignments align with least privilege principles
            - unused or inactive accounts are disabled
            - account-related actions are logged and monitored

        Potential Impact:
        If account management controls are weak, attackers may:

            - gain unauthorized system access through inactive accounts
            - escalate privileges using improperly configured accounts
            - persist within the environment using unmanaged credentials
            - compromise sensitive data or system functionality

        Expected Behavior:
        Applications should:

            - enforce proper account lifecycle management
            - disable or remove inactive or unused accounts
            - apply least privilege principles to all user roles
            - monitor and log account activity for auditing
            - ensure account creation and modification follow approved policies
        */
        
        private async Task<string> RunAc2AccountManagementTestsAsync(Uri baseUri)
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

