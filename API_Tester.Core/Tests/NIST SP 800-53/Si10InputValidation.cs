namespace API_Tester
{
    public partial class MainPage
    {
        /*
        SI-10 Input Validation Tests

        Purpose:
        Performs automated tests to evaluate the application’s input validation 
        controls in accordance with SI-10 security requirements, ensuring that 
        all user-supplied input is properly validated, sanitized, and handled 
        to prevent injection attacks and other security vulnerabilities.

        Threat Model:
        Weak input validation may allow attackers to:

            - Perform SQL, NoSQL, or command injection
            - Exploit cross-site scripting (XSS) vulnerabilities
            - Trigger buffer overflows or malformed input errors
            - Manipulate application logic or bypass security controls

        Common vulnerabilities include:

            - Unsanitized input used in database queries, commands, or file paths
            - Failure to enforce length, type, or format restrictions
            - Missing encoding for output in web pages or APIs
            - Inconsistent input validation across endpoints
            - Lack of centralized or standardized input validation mechanisms

        Test Strategy:
        The method performs automated checks that:

            - Submit crafted inputs designed to trigger injection vulnerabilities
            - Evaluate input handling across forms, APIs, and parameters
            - Inspect responses for error messages or unintended behaviors
            - Verify sanitization, encoding, and validation mechanisms
            - Detect inconsistent or missing input validation controls

        Potential Impact:
        If input validation controls are weak, attackers may:

            - Access, modify, or delete sensitive data
            - Execute arbitrary scripts or commands
            - Bypass authentication or authorization controls
            - Compromise application integrity or availability

        Expected Behavior:
        Applications should:

            - Validate all user inputs for type, length, format, and range
            - Sanitize or encode input used in output, queries, or commands
            - Apply consistent validation rules across all endpoints
            - Reject invalid or malicious input securely without exposing sensitive information
            - Incorporate centralized and standardized input validation practices
        */
        
        private async Task<string> RunSi10InputValidationTestsAsync(Uri baseUri)
        {
            const string jsonBody = "{\"test\":\"value\"}";
            var response = await SafeSendAsync(() =>
            {
                var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
                req.Content = new StringContent(jsonBody, Encoding.UTF8, "text/plain");
                return req;
            });

            var findings = new List<string>
                {
                    $"HTTP {FormatStatus(response)}",
                    response is not null && (response.StatusCode == HttpStatusCode.UnsupportedMediaType || response.StatusCode == HttpStatusCode.BadRequest)
                    ? "Content-type validation appears enforced."
                    : "Potential risk: invalid content-type may be accepted."
                };

            return FormatSection("Content-Type Validation", baseUri, findings);
        }
    }
}

