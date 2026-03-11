namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Execution and Technical Testing Tests

        Purpose:
        Performs automated tests to evaluate the application’s execution and 
        technical testing controls, ensuring that security functionality and 
        protective mechanisms operate as intended under realistic conditions.

        Threat Model:
        Weak execution or technical testing may allow attackers to:

            - Exploit untested or misconfigured application features
            - Bypass security controls due to implementation flaws
            - Trigger unintended behaviors or vulnerabilities
            - Compromise system integrity, availability, or confidentiality

        Common vulnerabilities include:

            - Incomplete functional or security testing
            - Lack of automated or manual testing for critical components
            - Inadequate coverage of edge cases or failure scenarios
            - Missing verification of security controls in deployed environments
            - Poor integration between testing and operational monitoring

        Test Strategy:
        The method performs automated checks that:

            - Execute application functions under controlled test conditions
            - Verify that security controls behave as expected
            - Detect misconfigurations, errors, or unexpected behaviors
            - Evaluate coverage and effectiveness of technical testing procedures
            - Assess consistency of execution and testing practices across environments

        Potential Impact:
        If execution and technical testing controls are weak, attackers may:

            - Exploit untested or improperly configured features
            - Circumvent security protections or monitoring mechanisms
            - Access sensitive data or system functionality
            - Cause operational, financial, or reputational damage

        Expected Behavior:
        Applications should:

            - Implement comprehensive technical testing for security and functionality
            - Validate that security controls operate as intended
            - Detect and correct deviations or failures during execution
            - Ensure consistency of testing procedures across all environments
            - Integrate testing results into security and operational monitoring
        */

        private async Task<string> RunExecutionAndTechnicalTestingTestsAsync(Uri baseUri)
        {
            var auth = await RunAuthenticationAndSessionTestingTestsAsync(baseUri);
            var input = await RunInputAndInjectionTestingTestsAsync(baseUri);
            var headers = await RunSecurityHeaderTestsAsync(baseUri);
            var cors = await RunCorsTestsAsync(baseUri);

            return string.Join(
                $"{Environment.NewLine}{Environment.NewLine}",
                new[] { auth, input, headers, cors });
        }
    }
}
