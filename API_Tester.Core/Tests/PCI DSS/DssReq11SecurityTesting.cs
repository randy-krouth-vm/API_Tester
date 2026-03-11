namespace API_Tester
{
    public partial class MainPage
    {
        /*
        PCI DSS Requirement 11 – Security Testing Tests

        Purpose:
        Performs automated tests to verify that the application supports
        ongoing security testing practices in accordance with PCI DSS
        Requirement 11. These tests evaluate whether systems are regularly
        assessed for vulnerabilities and security weaknesses.

        Requirement 11 focuses on proactively identifying security issues
        through processes such as vulnerability scanning, penetration
        testing, and continuous monitoring.

        Threat Model:
        If regular security testing is not performed, attackers may:

            - exploit unpatched vulnerabilities
            - leverage misconfigurations that remain undetected
            - access sensitive systems without detection
            - maintain persistence within the environment

        Attackers commonly target:

            - untested application endpoints
            - outdated components or libraries
            - exposed services or network interfaces
            - unmonitored infrastructure components

        Common vulnerabilities include:

            - absence of regular vulnerability scanning
            - lack of penetration testing for critical systems
            - missing monitoring for unauthorized network activity
            - untested changes to application code or infrastructure
            - outdated security controls that are no longer effective

        Test Strategy:
        The method performs automated checks that:

            - evaluate system responses for indicators of security testing controls
            - inspect application behavior for vulnerability scanning protections
            - detect exposed services or unprotected endpoints
            - analyze responses for signs of security assessment coverage
            - verify consistency of security testing mechanisms across services

        Potential Impact:
        If security testing controls are weak, attackers may:

            - exploit undiscovered vulnerabilities
            - gain unauthorized access to payment systems
            - compromise cardholder data environments
            - remain undetected within the infrastructure

        Expected Behavior:
        Organizations should:

            - perform regular vulnerability scans and penetration tests
            - continuously monitor systems for security weaknesses
            - test new code and configuration changes for vulnerabilities
            - address identified vulnerabilities promptly
            - maintain documented security testing processes
        */
        
        private async Task<string> RunDssReq11SecurityTestingTestsAsync(Uri baseUri)
        {
            var findings = new List<string>();

            var options = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Options, baseUri));
            if (options is not null)
            {
                findings.Add($"OPTIONS: {(int)options.StatusCode} {options.StatusCode}");
                var allow = TryGetHeader(options, "Allow");
                if (!string.IsNullOrWhiteSpace(allow))
                {
                    findings.Add($"Allow: {allow}");
                }
            }
            else
            {
                findings.Add("OPTIONS: no response");
            }

            var trace = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Trace, baseUri));
            if (trace is not null)
            {
                findings.Add($"TRACE: {(int)trace.StatusCode} {trace.StatusCode}");
                if (trace.StatusCode != HttpStatusCode.MethodNotAllowed &&
                trace.StatusCode != HttpStatusCode.NotFound)
                {
                    findings.Add("Potential risk: TRACE method appears enabled.");
                }
            }
            else
            {
                findings.Add("TRACE: no response");
            }

            return FormatSection("HTTP Methods", baseUri, findings);
        }
    }
}

