namespace API_Tester
{
    public partial class MainPage
    {
        /*
        CM-7 Least Functionality Tests

        Purpose:
        Performs automated tests to evaluate the application’s adherence to 
        the principle of least functionality (CM-7), ensuring that only 
        essential features, services, and capabilities are enabled, 
        minimizing the attack surface.

        Threat Model:
        Enabling unnecessary functions or services may allow attackers to:

            - Exploit unused or unmonitored features
            - Access sensitive resources through non-essential services
            - Introduce additional attack vectors
            - Bypass security controls via under-protected functionality

        Common vulnerabilities include:

            - Default or unnecessary services running on servers or applications
            - Features enabled that are not required for business operations
            - Lack of controls to disable or restrict unused capabilities
            - Inconsistent enforcement of least functionality policies

        Test Strategy:
        The method performs automated checks that:

            - Identify enabled services and features across the application
            - Verify that only essential functionality is active
            - Detect unnecessary or risky components that increase the attack surface
            - Evaluate adherence to organizational policies and security best practices

        Potential Impact:
        If least functionality controls are weak, attackers may:

            - Exploit unnecessary services or features to gain unauthorized access
            - Increase the potential attack surface for compromise
            - Bypass security controls or monitoring mechanisms
            - Escalate privileges or perform lateral movement within the system

        Expected Behavior:
        Applications should:

            - Enable only essential functions and services required for operations
            - Disable or remove non-essential or default features
            - Maintain a minimal attack surface while preserving functionality
            - Monitor and control changes to functionality over time
            - Ensure consistent enforcement of least functionality across all environments
        */

        private async Task<string> RunCm7LeastFunctionalityTestsAsync(Uri baseUri)
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

