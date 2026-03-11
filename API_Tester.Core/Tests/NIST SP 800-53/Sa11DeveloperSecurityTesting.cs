namespace API_Tester
{
    public partial class MainPage
    {
        /*
        SA-11 Developer Security Testing Tests

        Purpose:
        Performs automated tests to evaluate the application’s adherence to 
        developer security testing practices in accordance with SA-11 security 
        requirements, ensuring that security testing is integrated into the 
        software development lifecycle (SDLC).

        Threat Model:
        Applications lacking developer security testing may allow attackers to:

            - Exploit untested or poorly reviewed code
            - Take advantage of security vulnerabilities introduced during development
            - Bypass controls due to design or implementation flaws
            - Escalate privileges or compromise sensitive data

        Common vulnerabilities include:

            - Absence of static and dynamic code analysis
            - Missing automated security testing in CI/CD pipelines
            - Unreviewed third-party libraries or dependencies
            - Lack of unit and integration tests for security-relevant code
            - Failure to remediate identified vulnerabilities

        Test Strategy:
        The method performs automated checks that:

            - Assess coverage and implementation of security tests during development
            - Verify integration of static and dynamic analysis tools
            - Inspect dependency management and vulnerability scanning practices
            - Detect gaps in security testing across modules and components
            - Evaluate adherence to secure coding standards and best practices

        Potential Impact:
        If developer security testing controls are weak, attackers may:

            - Exploit undiscovered vulnerabilities in deployed applications
            - Circumvent security protections due to unchecked code
            - Compromise system integrity, confidentiality, or availability
            - Cause operational, regulatory, or reputational damage

        Expected Behavior:
        Applications should:

            - Incorporate automated and manual security testing during development
            - Conduct static, dynamic, and dependency analysis regularly
            - Remediate vulnerabilities before deployment
            - Enforce secure coding standards and practices
            - Maintain consistent security testing across all development stages
        */
        
        private async Task<string> RunSa11DeveloperSecurityTestingTestsAsync(Uri baseUri)
        {
            var sqli = await RunSqlInjectionTestsAsync(baseUri);
            var xss = await RunXssTestsAsync(baseUri);
            var nosql = await RunNoSqlInjectionTestsAsync(baseUri);
            var typeConfusion = await RunTypeConfusionTestsAsync(baseUri);

            return string.Join(
                $"{Environment.NewLine}{Environment.NewLine}",
                new[] { sqli, xss, nosql, typeConfusion });
        }
    }
}
