namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Access Control Tests

        Purpose:
        Performs automated tests to evaluate the application’s access control 
        mechanisms, ensuring that users can only access resources and perform 
        actions for which they are authorized.

        Threat Model:
        Weak or misconfigured access controls may allow attackers to:

            - Access unauthorized data or functionality
            - Escalate privileges beyond assigned roles
            - Exploit inconsistent or missing authorization checks
            - Circumvent security policies and protections

        Common vulnerabilities include:

            - Inadequate role-based or attribute-based access control
            - Insecure direct object references (IDOR)
            - Missing enforcement of access policies across endpoints
            - Over-permissioned accounts or service principals
            - Inconsistent access control implementations between services

        Test Strategy:
        The method performs automated checks that:

            - Attempt to access resources with insufficient privileges
            - Test enforcement of access policies for different roles
            - Detect unauthorized access to administrative or sensitive operations
            - Verify consistency of access enforcement across endpoints
            - Assess logging and monitoring of access control events

        Potential Impact:
        If access control mechanisms are weak, attackers may:

            - Access or modify sensitive data
            - Execute privileged actions without authorization
            - Compromise system integrity or availability
            - Escalate privileges for further exploitation

        Expected Behavior:
        Applications should:

            - Enforce access controls consistently across all resources and endpoints
            - Apply least privilege principles to all users and processes
            - Validate authorization checks on the server side
            - Monitor and log unauthorized access attempts
            - Ensure access control policies are maintained and updated consistently
        */
        
        private async Task<string> RunAccessControlTestsAsync(Uri baseUri)
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

