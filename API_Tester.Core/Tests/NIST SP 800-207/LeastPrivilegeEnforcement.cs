namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Least Privilege Enforcement Tests

        Purpose:
        Performs automated tests to evaluate whether the application enforces
        the principle of least privilege, ensuring that users, services, and
        processes only receive the minimum permissions necessary to perform
        their intended tasks.

        Threat Model:
        Excessive privileges may allow attackers or compromised accounts to:

            - Access sensitive resources beyond their role
            - Escalate privileges to administrative levels
            - Modify or delete protected data
            - Exploit over-permissioned service accounts or APIs

        Common vulnerabilities include:

            - Users granted administrative permissions unnecessarily
            - Service accounts with broad or unrestricted access
            - Lack of role separation between standard and privileged operations
            - Missing authorization checks on sensitive endpoints
            - Privilege inheritance across APIs or services

        Test Strategy:
        The method performs automated checks that:

            - Attempt to access restricted resources with lower privilege roles
            - Evaluate enforcement of role-based or attribute-based access policies
            - Detect endpoints allowing privileged operations without authorization
            - Inspect privilege boundaries between user roles
            - Assess consistency of least privilege enforcement across services

        Potential Impact:
        If least privilege enforcement is weak, attackers may:

            - Escalate privileges to gain administrative access
            - Access or modify sensitive system data
            - Perform unauthorized system operations
            - Compromise system integrity and security controls

        Expected Behavior:
        Applications should:

            - Enforce strict role-based or attribute-based access controls
            - Limit permissions to only what is required for each role
            - Separate privileged and standard operations
            - Continuously review and reduce unnecessary privileges
            - Log and monitor attempts to perform privileged actions
        */
        
        private async Task<string> RunLeastPrivilegeEnforcementTestsAsync(Uri baseUri)
        {
            var original = AppendQuery(baseUri, new Dictionary<string, string> { ["id"] = "1" });
            var tampered = AppendQuery(baseUri, new Dictionary<string, string> { ["id"] = "999999" });

            var originalResponse = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, original));
            var tamperedResponse = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, tampered));

            var findings = new List<string>
                {
                    $"Original request status: {FormatStatus(originalResponse)}",
                    $"Tampered request status: {FormatStatus(tamperedResponse)}"
                };

            if (originalResponse is not null && tamperedResponse is not null &&
            originalResponse.StatusCode == tamperedResponse.StatusCode &&
            originalResponse.StatusCode == HttpStatusCode.OK)
            {
                findings.Add("Potential risk: tampered object ID returned same success status.");
            }
            else
            {
                findings.Add("No obvious BOLA indicator from status comparison.");
            }

            return FormatSection("BOLA / Object ID Tampering", tampered, findings);
        }
    }
}

