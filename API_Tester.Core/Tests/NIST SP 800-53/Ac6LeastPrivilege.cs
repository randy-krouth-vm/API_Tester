namespace API_Tester
{
    public partial class MainPage
    {
        /*
        AC-6 Least Privilege Tests

        Purpose:
        Performs automated tests to evaluate the application’s adherence to
        the principle of least privilege (AC-6), ensuring that users, processes,
        and systems are granted only the minimum privileges necessary to perform
        their assigned tasks.

        Threat Model:
        Excessive privileges can allow attackers or compromised accounts to:

            - Access or modify sensitive data beyond their role
            - Escalate privileges or compromise additional accounts
            - Execute unauthorized system functions
            - Bypass security policies or controls

        Common vulnerabilities include:

            - Over-permissioned accounts or service principals
            - Administrative access granted to standard users
            - Unrestricted access to critical system functions
            - Failure to remove privileges when roles change or accounts are disabled

        Test Strategy:
        The method performs automated checks that:

            - Verify assigned privileges align with defined roles
            - Detect accounts or processes with excessive permissions
            - Test for the ability to perform unauthorized actions
            - Assess consistency of privilege enforcement across endpoints

        Potential Impact:
        If least privilege controls are weak, attackers may:

            - Access or modify sensitive data without authorization
            - Escalate privileges to compromise additional systems
            - Bypass security controls or policy enforcement
            - Cause operational, data, or compliance-related damage

        Expected Behavior:
        Applications and systems should:

            - Enforce the principle of least privilege for all users and processes
            - Grant only necessary privileges to perform assigned tasks
            - Remove or adjust privileges when roles or responsibilities change
            - Monitor and audit privilege assignments and usage
            - Ensure privilege enforcement is consistent across all system components
        */
        
        private async Task<string> RunAc6LeastPrivilegeTestsAsync(Uri baseUri)
        {
            var findings = new List<string>();
            var response = await SafeSendAsync(() =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
                req.Headers.TryAddWithoutValidation("X-Role", "admin");
                req.Headers.TryAddWithoutValidation("X-User-Type", "superuser");
                return req;
            });

            findings.Add($"HTTP {FormatStatus(response)}");
            findings.Add(response is not null && response.StatusCode == HttpStatusCode.OK
            ? "Potential risk: elevated role headers accepted."
            : "No obvious privilege escalation indicator.");

            return FormatSection("Privilege Escalation Header Probe", baseUri, findings);
        }
    }
}

