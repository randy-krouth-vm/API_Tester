namespace API_Tester;

public partial class MainPage
{
    /*
    DISA STIG / SRG Security Misconfiguration Tests

    Purpose:
    Performs automated tests to identify misconfigurations in the 
    application and underlying infrastructure, based on DISA STIG 
    (Defense Information Systems Agency Security Technical Implementation 
    Guides) and SRG (Security Requirements Guide) standards.

    Threat Model:
    Misconfigured systems can expose applications to attackers who may:

        - Exploit insecure settings or default configurations
        - Gain unauthorized access to sensitive resources
        - Elevate privileges due to weak permissions
        - Circumvent security controls due to missing hardening

    Common misconfigurations include:

        - Default or weak passwords
        - Unrestricted administrative access
        - Insecure file or directory permissions
        - Missing security patches or hardening controls
        - Overly permissive network or service configurations

    Test Strategy:
    The method performs asynchronous automated checks to:

        - Verify compliance with DISA STIG and SRG security controls
        - Detect insecure default settings or missing hardening measures
        - Analyze permissions, access controls, and configuration files
        - Identify endpoints or services with insecure settings

    Potential Impact:
    If misconfigurations exist, attackers may be able to:

        - Access sensitive data or system resources
        - Execute unauthorized commands or scripts
        - Escalate privileges and compromise systems
        - Exploit other vulnerabilities more easily due to weak settings

    Expected Behavior:
    Applications and systems should:

        - Follow DISA STIG / SRG hardening and configuration guidelines
        - Apply least privilege principles to accounts and services
        - Restrict access to sensitive files, directories, and endpoints
        - Regularly patch and update systems to mitigate known vulnerabilities
        - Consistently enforce secure configurations across all environments
    */

    private async Task<string> RunDISASTIGSRGSecurityMisconfigurationTestsAsync(Uri baseUri)
    {
        var headers = await RunSecurityHeaderTestsAsync(baseUri);
        var cors = await RunCorsTestsAsync(baseUri);
        var methods = await RunHttpMethodTestsAsync(baseUri);
        return $"{headers}{Environment.NewLine}{Environment.NewLine}{cors}{Environment.NewLine}{Environment.NewLine}{methods}";
    }

}

