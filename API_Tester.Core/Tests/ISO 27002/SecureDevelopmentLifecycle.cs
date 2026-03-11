namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Secure Development Lifecycle (SDLC) Tests

        Purpose:
        Performs automated tests to evaluate the implementation of secure 
        development lifecycle practices within the application, ensuring 
        that security is integrated throughout design, development, testing, 
        and deployment phases.

        Threat Model:
        Weak SDLC practices may allow attackers to:

            - Exploit vulnerabilities introduced during development
            - Deploy insecure code into production
            - Bypass controls due to untested or poorly reviewed changes
            - Gain access to sensitive data or functionality through flaws in design or implementation

        Common vulnerabilities include:

            - Lack of secure coding practices or code reviews
            - Missing security testing in the build and deployment process
            - Inadequate handling of third-party libraries or dependencies
            - Insufficient threat modeling or design review
            - Absence of automated security checks in CI/CD pipelines

        Test Strategy:
        The method performs asynchronous automated checks to:

            - Verify adherence to secure coding standards
            - Ensure security testing is performed during development and deployment
            - Inspect dependency management and vulnerability scanning processes
            - Assess design reviews, threat modeling, and security integration
            - Detect gaps in security enforcement across the development lifecycle

        Potential Impact:
        If secure development lifecycle controls are weak, attackers may:

            - Exploit application vulnerabilities introduced during development
            - Compromise production systems due to insecure code
            - Access sensitive information through design or implementation flaws
            - Evade detection and monitoring due to insufficient testing

        Expected Behavior:
        Applications should:

            - Integrate security into all phases of the development lifecycle
            - Apply secure coding standards and code review practices
            - Conduct automated security testing and vulnerability scans
            - Manage third-party dependencies securely
            - Ensure continuous monitoring, review, and improvement of security practices
        */
        
        private async Task<string> RunSecureDevelopmentLifecycleTestsAsync(Uri baseUri)
        {
            var headers = await RunSecurityHeaderTestsAsync(baseUri);
            var cors = await RunCorsTestsAsync(baseUri);
            var methods = await RunHttpMethodTestsAsync(baseUri);
            return $"{headers}{Environment.NewLine}{Environment.NewLine}{cors}{Environment.NewLine}{Environment.NewLine}{methods}";
        }
    }
}

