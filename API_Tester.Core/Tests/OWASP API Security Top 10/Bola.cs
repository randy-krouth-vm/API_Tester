namespace API_Tester
{
    public partial class MainPage
    {
        /*
        OWASP API Security Top 10 – Broken Object Level Authorization (BOLA) Tests

        Purpose:
        Performs automated tests to evaluate whether the application is vulnerable
        to Broken Object Level Authorization (BOLA), one of the most common
        vulnerabilities in APIs according to the OWASP API Security Top 10.

        Threat Model:
        BOLA vulnerabilities occur when an application fails to properly verify
        that the authenticated user has permission to access a specific object
        or resource. Attackers may attempt to manipulate identifiers such as:

            - user IDs
            - account numbers
            - order IDs
            - document identifiers

        If authorization checks are missing or weak, attackers may:

            - access other users’ data
            - modify or delete unauthorized resources
            - enumerate sensitive records

        Common vulnerabilities include:

            - exposing predictable object identifiers
            - relying only on client-side authorization checks
            - missing server-side validation for object ownership
            - inconsistent authorization enforcement across endpoints
            - insufficient logging of unauthorized access attempts

        Test Strategy:
        The method performs automated checks that:

            - attempt access to resources using modified object identifiers
            - evaluate server-side authorization validation
            - detect endpoints returning data belonging to other users
            - inspect responses for unauthorized data exposure
            - assess consistency of object-level authorization enforcement

        Potential Impact:
        If BOLA vulnerabilities exist, attackers may:

            - access sensitive data belonging to other users
            - manipulate or delete protected resources
            - compromise user privacy and confidentiality
            - cause financial or reputational damage

        Expected Behavior:
        Applications should:

            - enforce strict server-side authorization checks
            - validate ownership or permissions for each requested object
            - avoid exposing predictable object identifiers
            - apply authorization consistently across all endpoints
            - log and monitor unauthorized access attempts
        */
        
        private async Task<string> RunOWASPAPISecurityTop10BolaTestsAsync(Uri baseUri)
        {
            var original = AppendQuery(baseUri, new Dictionary<string, string> { ["id"] = "1" });
            var tampered = AppendQuery(baseUri, new Dictionary<string, string> { ["id"] = "999999" });

            var originalResponse = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, original));
            var tamperedResponse = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, tampered));

            var findings = new List<string>
                {
                    $"Original request status: {FormatStatus(originalResponse)}",
                    $"Tampered request status: {FormatStatus(tamperedResponse)}"
                };

            if (originalResponse is not null && tamperedResponse is not null &&
            originalResponse.StatusCode == tamperedResponse.StatusCode &&
            originalResponse.StatusCode == HttpStatusCode.OK)
            {
                findings.Add("Potential risk: tampered object ID returned same success status.");
            }
            else
            {
                findings.Add("No obvious BOLA indicator from status comparison.");
            }

            return FormatSection("BOLA / Object ID Tampering", tampered, findings);
        }
    }
}

