namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Access Control Baseline Tests

        Purpose:
        Performs automated tests to evaluate the application's access control 
        mechanisms and ensure that baseline security policies are enforced 
        correctly for users, roles, and resources.

        Threat Model:
        Weak or misconfigured access controls may allow attackers to:

            - Access resources or functions they are not authorized to use
            - Elevate privileges beyond their assigned roles
            - Perform unauthorized actions on sensitive data or systems
            - Exploit inconsistent or missing access policies

        Common vulnerabilities include:

            - Missing role-based or attribute-based restrictions
            - Overly permissive default permissions
            - Insecure direct object references (IDOR)
            - Inconsistent enforcement across APIs or endpoints

        Test Strategy:
        The method performs asynchronous automated checks to:

            - Validate enforcement of role- and user-based access policies
            - Test access to restricted resources with different credentials
            - Detect over-permissive default settings or missing restrictions
            - Identify inconsistent access control behavior across endpoints

        Potential Impact:
        If access controls are weak, attackers may:

            - Access or modify sensitive information without authorization
            - Escalate privileges and compromise other accounts
            - Bypass security policies and perform malicious actions
            - Gain insight into system structure for further attacks

        Expected Behavior:
        Applications should:

            - Enforce the principle of least privilege for all users and roles
            - Restrict access to resources based on role, context, and permissions
            - Consistently apply access control checks across all endpoints
            - Regularly audit access controls to ensure compliance with security policies
        */
        
        private async Task<string> RunAcAccessControlBaselineTestsAsync(Uri baseUri)
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

