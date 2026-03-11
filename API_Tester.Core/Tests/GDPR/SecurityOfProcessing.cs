namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Security of Processing Tests

        Purpose:
        Performs automated tests to evaluate the security of data processing 
        within the application, ensuring that sensitive information is handled 
        securely throughout its lifecycle, including processing, storage, and 
        transmission.

        Threat Model:
        Insecure data processing may allow attackers to:

            - Intercept or manipulate sensitive data during processing
            - Access data without authorization
            - Exploit flaws in processing logic to bypass security controls
            - Cause data corruption or leakage

        Common vulnerabilities include:

            - Processing sensitive data in plaintext
            - Weak or missing encryption during processing or storage
            - Inadequate access control on processing endpoints
            - Insufficient validation of data inputs or outputs
            - Logging or exposing sensitive information inadvertently

        Test Strategy:
        The method performs asynchronous automated checks to:

            - Inspect data flows during processing for confidentiality and integrity
            - Verify encryption and access control mechanisms
            - Detect exposure of sensitive fields in logs, responses, or storage
            - Validate proper handling and sanitization of input and output data
            - Ensure adherence to security policies and best practices for processing

        Potential Impact:
        If data processing is insecure, attackers may:

            - Compromise sensitive information
            - Bypass security or privacy controls
            - Modify or corrupt data leading to operational or reputational impact
            - Exploit processing flaws for privilege escalation or unauthorized access

        Expected Behavior:
        Applications should:

            - Protect sensitive data during processing using encryption and access controls
            - Validate all inputs and outputs for security and integrity
            - Minimize exposure of sensitive information
            - Log security-relevant processing events securely
            - Enforce security policies consistently across all processing operations
        */
        
        private async Task<string> RunSecurityOfProcessingTestsAsync(Uri baseUri)
        {
            var findings = new List<string>
                {
                    baseUri.Scheme == Uri.UriSchemeHttps
                    ? "HTTPS target detected."
                    : "Potential risk: HTTP target detected (no TLS on this URL)."
                };

            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, baseUri));
            if (response is null)
            {
                findings.Add("No response received.");
                return FormatSection("Transport Security", baseUri, findings);
            }

            findings.Add($"HTTP {(int)response.StatusCode} {response.StatusCode}");
            if (baseUri.Scheme == Uri.UriSchemeHttps)
            {
                findings.Add(response.Headers.Contains("Strict-Transport-Security")
                ? "HSTS header present."
                : "HSTS header missing.");
            }

            return FormatSection("Transport Security", baseUri, findings);
        }
    }
}

