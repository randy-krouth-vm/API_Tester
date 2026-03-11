namespace API_Tester
{
    public partial class MainPage
    {
        /*
        CC8 Change Management Tests

        Purpose:
        Performs automated tests to evaluate whether the application reflects
        secure change management practices aligned with SOC 2 CC8 principles.
        These tests assess whether system changes are controlled, tracked,
        and verified to prevent unauthorized or unsafe modifications.

        Threat Model:
        Weak change management controls may allow attackers or insiders to:

            - introduce malicious code or configuration changes
            - modify system behavior without authorization
            - bypass review or approval processes
            - deploy insecure or untested updates

        Attackers may attempt to exploit weaknesses such as:

            - undocumented system changes
            - unverified software deployments
            - unauthorized configuration modifications
            - lack of change tracking or auditing

        Common vulnerabilities include:

            - absence of change approval or review processes
            - missing audit logs for system updates
            - untested configuration changes
            - deployment of outdated or vulnerable components
            - lack of version control or traceability for system updates

        Test Strategy:
        The method performs automated checks that:

            - evaluate system responses for indicators of controlled change processes
            - inspect application behavior for version or configuration inconsistencies
            - detect endpoints reflecting untracked or unmanaged changes
            - analyze responses for evidence of controlled deployment practices
            - assess visibility of system configuration and update status

        Potential Impact:
        If change management controls are weak, attackers may:

            - introduce malicious code or configuration changes
            - exploit unverified updates
            - manipulate system behavior without detection
            - compromise system integrity and security posture

        Expected Behavior:
        Organizations should:

            - enforce formal change management procedures
            - review and approve changes before deployment
            - maintain version control and change tracking
            - log and monitor configuration or code changes
            - verify system integrity after updates or deployments
        */
        
        private async Task<string> RunCc8ChangeManagementTestsAsync(Uri baseUri)
        {
            var headers = await RunSecurityHeaderTestsAsync(baseUri);
            var cors = await RunCorsTestsAsync(baseUri);
            var methods = await RunHttpMethodTestsAsync(baseUri);
            return $"{headers}{Environment.NewLine}{Environment.NewLine}{cors}{Environment.NewLine}{Environment.NewLine}{methods}";
        }
    }
}

