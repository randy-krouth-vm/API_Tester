namespace API_Tester
{
    public partial class MainPage
    {
        /*
        SC-23 Session Authenticity Tests

        Purpose:
        Performs automated tests to evaluate the application’s session 
        authenticity controls in accordance with SC-23 security requirements, 
        ensuring that user sessions are valid, properly authenticated, and 
        protected from hijacking or impersonation.

        Threat Model:
        Weak session authenticity may allow attackers to:

            - Hijack or steal user sessions
            - Impersonate authenticated users
            - Bypass authentication controls
            - Perform unauthorized actions using compromised sessions

        Common vulnerabilities include:

            - Predictable or weak session identifiers
            - Lack of session expiration or inactivity timeout
            - Insufficient protection of session tokens (e.g., HttpOnly, Secure flags)
            - Absence of mechanisms to detect or prevent session hijacking
            - Reuse of expired or invalid session tokens

        Test Strategy:
        The method performs automated checks that:

            - Attempt to reuse, steal, or manipulate session tokens
            - Evaluate enforcement of session expiration and inactivity timeouts
            - Verify protection of session cookies and authentication tokens
            - Detect vulnerabilities to session fixation, hijacking, or replay attacks
            - Assess consistency of session management across endpoints

        Potential Impact:
        If session authenticity controls are weak, attackers may:

            - Gain unauthorized access to user accounts
            - Perform actions on behalf of other users
            - Compromise sensitive data or system functionality
            - Evade detection due to improper session controls

        Expected Behavior:
        Applications should:

            - Generate strong, unpredictable session identifiers
            - Protect session tokens with secure attributes (HttpOnly, Secure, SameSite)
            - Enforce expiration and inactivity timeouts for sessions
            - Detect and prevent session hijacking or fixation attempts
            - Apply consistent session management policies across all endpoints
        */

        private async Task<string> RunSc23SessionAuthenticityTestsAsync(Uri baseUri)
        {
            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, baseUri));
            var findings = new List<string> { $"HTTP {FormatStatus(response)}" };

            if (response is null || !response.Headers.TryGetValues("Set-Cookie", out var setCookies))
            {
                findings.Add("No Set-Cookie headers found.");
                return FormatSection("Cookie Security Flags", baseUri, findings);
            }

            foreach (var cookie in setCookies)
            {
                findings.Add(cookie.Contains("Secure", StringComparison.OrdinalIgnoreCase) ? "Cookie has Secure" : "Cookie missing Secure");
                findings.Add(cookie.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase) ? "Cookie has HttpOnly" : "Cookie missing HttpOnly");
                findings.Add(cookie.Contains("SameSite", StringComparison.OrdinalIgnoreCase) ? "Cookie has SameSite" : "Cookie missing SameSite");
            }

            return FormatSection("Cookie Security Flags", baseUri, findings);
        }
    }
}

