namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Verification Practice Tests

        Purpose:
        Performs automated tests to evaluate whether security verification
        practices are consistently applied throughout the application.
        These tests assess whether security controls, configurations,
        and behaviors can be validated and confirmed through testing.

        Threat Model:
        Weak verification practices may allow vulnerabilities or
        misconfigurations to persist undetected. Attackers may:

            - exploit untested security controls
            - take advantage of inconsistent validation mechanisms
            - bypass protections due to gaps in verification processes
            - leverage configuration drift or unverified deployments

        Security verification typically involves:

            - validating security controls through testing
            - confirming enforcement of authentication and authorization
            - verifying proper configuration of system protections
            - ensuring security mechanisms behave as expected

        Common weaknesses include:

            - lack of automated security verification
            - incomplete validation of security controls
            - inconsistent testing across system components
            - absence of verification after configuration changes
            - insufficient monitoring of control effectiveness

        Test Strategy:
        The method performs automated checks that:

            - verify enforcement of implemented security controls
            - inspect application responses for verification indicators
            - assess consistency of verification mechanisms across endpoints
            - detect gaps where controls exist but are not validated
            - analyze system behavior to confirm expected protections

        Potential Impact:
        If verification practices are weak, attackers may:

            - exploit unnoticed security weaknesses
            - bypass misconfigured protections
            - operate within systems without triggering safeguards
            - compromise system integrity and security posture

        Expected Behavior:
        Applications should:

            - implement continuous verification of security controls
            - integrate automated verification into development and deployment
            - regularly validate configurations and protections
            - monitor control effectiveness over time
            - maintain consistent verification practices across all components
        */
        
        private async Task<string> RunVerificationPracticeTestsAsync(Uri baseUri)
        {
            var input = await RunInputAndInjectionTestingTestsAsync(baseUri);
            var auth = await RunAuthenticationAndSessionTestingTestsAsync(baseUri);
            var api = await RunV13ApiAndWebServiceVerificationTestsAsync(baseUri);

            return string.Join(
                $"{Environment.NewLine}{Environment.NewLine}",
                new[] { input, auth, api });
        }
    }
}
