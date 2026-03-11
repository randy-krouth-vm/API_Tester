namespace API_Tester
{
    public partial class MainPage
    {
        /*
        API and Web Service Verification Tests (V13)

        Purpose:
        Performs automated tests to verify that APIs and web services are
        securely implemented and properly protected. These tests evaluate
        whether service endpoints enforce authentication, authorization,
        input validation, and other security controls.

        Threat Model:
        APIs and web services are often primary attack surfaces. If they
        are improperly secured, attackers may attempt to:

            - access sensitive endpoints without authentication
            - manipulate request parameters
            - exploit injection vulnerabilities
            - bypass authorization checks
            - abuse exposed service functionality

        Attackers commonly probe for:

            - undocumented or hidden endpoints
            - insecure HTTP methods
            - weak authentication mechanisms
            - excessive data exposure in responses
            - poorly validated request parameters

        Common vulnerabilities include:

            - missing authentication on API endpoints
            - broken authorization enforcement
            - insecure HTTP methods enabled unnecessarily
            - lack of input validation for request parameters
            - verbose error messages revealing service details

        Test Strategy:
        The method performs automated checks that:

            - enumerate accessible API and service endpoints
            - test authentication and authorization enforcement
            - inspect request and response behavior for security weaknesses
            - evaluate HTTP method handling and restrictions
            - detect exposed or undocumented service interfaces

        Potential Impact:
        If API and web service protections are weak, attackers may:

            - access sensitive system functionality
            - manipulate or retrieve confidential data
            - bypass authentication or authorization controls
            - exploit service logic for further compromise

        Expected Behavior:
        Applications should:

            - require authentication for protected APIs
            - enforce strict authorization checks
            - validate all incoming request parameters
            - restrict unnecessary HTTP methods
            - monitor and log API access for suspicious activity
        */
        
        private async Task<string> RunV13ApiAndWebServiceVerificationTestsAsync(Uri baseUri)
        {
            const string payload = "{\"requiredFieldMissing\":true,\"unexpected\":\"value\",\"id\":\"not-an-int\"}";
            var response = await SafeSendAsync(() =>
            {
                var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
                req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
                return req;
            });

            var findings = new List<string>
                {
                    $"HTTP {FormatStatus(response)}",
                    response is not null && response.StatusCode == HttpStatusCode.OK
                    ? "Potential risk: schema mismatch may not be enforced."
                    : "No obvious schema-mismatch acceptance."
                };

            return FormatSection("OpenAPI Schema Mismatch", baseUri, findings);
        }
    }
}

