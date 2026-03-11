namespace API_Tester
{
    public partial class MainPage
    {
        /*
        CM-6 Configuration Settings Tests

        Purpose:
        Performs automated tests to evaluate the application’s configuration 
        management controls in accordance with CM-6 (Configuration Settings) 
        security requirements, ensuring that systems are securely configured 
        and deviations from approved settings are detected and corrected.

        Threat Model:
        Weak configuration management may allow attackers to:

            - Exploit insecure or misconfigured system settings
            - Access unauthorized features or services
            - Escalate privileges through improperly configured controls
            - Circumvent security mechanisms due to non-compliant configurations

        Common vulnerabilities include:

            - Default or insecure configuration settings
            - Misconfigured services, applications, or endpoints
            - Inconsistent enforcement of security policies
            - Lack of monitoring or auditing for configuration changes
            - Deviations from baseline configuration standards

        Test Strategy:
        The method performs automated checks that:

            - Compare system configuration settings against secure baselines
            - Identify insecure or non-compliant settings
            - Assess the consistency of configuration across environments
            - Detect unauthorized or unintended configuration changes
            - Verify adherence to security policies and best practices

        Potential Impact:
        If configuration settings controls are weak, attackers may:

            - Exploit insecure configurations to gain unauthorized access
            - Bypass security controls or protective measures
            - Compromise system integrity, confidentiality, or availability
            - Escalate privileges or maintain persistence in the environment

        Expected Behavior:
        Applications should:

            - Implement secure baseline configurations for all systems and components
            - Enforce and maintain approved configuration settings consistently
            - Monitor and audit configuration changes for deviations
            - Correct non-compliant or insecure configurations promptly
            - Ensure that configuration management policies are applied across all environments
        */

        private async Task<string> RunCm6ConfigurationSettingsTestsAsync(Uri baseUri)
        {
            var headers = await RunSecurityHeaderTestsAsync(baseUri);
            var cors = await RunCorsTestsAsync(baseUri);
            var methods = await RunHttpMethodTestsAsync(baseUri);
            return $"{headers}{Environment.NewLine}{Environment.NewLine}{cors}{Environment.NewLine}{Environment.NewLine}{methods}";
        }
    }
}

