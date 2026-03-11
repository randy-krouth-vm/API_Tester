namespace API_Tester;

public partial class MainPage
{
/*
    Unsafe API Consumption Tests

    Purpose:
    Performs automated tests to evaluate whether the application safely
    consumes data from external or third-party APIs. These tests ensure
    that responses from external services are validated, sanitized, and
    handled securely before being trusted or processed.

    Threat Model:
    Applications frequently rely on external APIs for services such as
    payments, identity verification, analytics, or integrations. If the
    application blindly trusts external responses, attackers may attempt to:

        - manipulate API responses through compromised services
        - inject malicious data into application workflows
        - exploit weak validation of third-party data
        - cause logic errors or privilege escalation

    Common vulnerabilities include:

        - trusting external API responses without validation
        - missing integrity verification of external responses
        - insecure handling of API tokens or credentials
        - improper parsing of external data formats
        - lack of timeout or error handling for external API calls

    Test Strategy:
    The method performs automated checks that:

        - evaluate validation of external API responses
        - inspect how external data is processed within the application
        - detect insecure handling of third-party API responses
        - analyze error handling and fallback mechanisms
        - verify secure use of authentication when interacting with external APIs

    Potential Impact:
    If unsafe API consumption vulnerabilities exist, attackers may:

        - manipulate application behavior through malicious responses
        - inject malicious data into internal systems
        - gain unauthorized access through trust abuse
        - disrupt business logic or service availability

    Expected Behavior:
    Applications should:

        - validate and sanitize all external API responses
        - enforce strict schema validation for incoming data
        - protect API credentials and tokens
        - implement robust error handling and timeouts
        - avoid blindly trusting third-party service responses
    */
    
    private async Task<string> RunUnsafeApiConsumptionTestsAsync(Uri baseUri)
    {
        var ssrf = await RunMITREATTampCKFrameworkSsrfTestsAsync(baseUri);
        var openRedirect = await RunOpenRedirectTestsAsync(baseUri);
        return $"{ssrf}{Environment.NewLine}{Environment.NewLine}{openRedirect}";
    }

}

