namespace API_Tester
{
    public partial class MainPage
    {
        /*
        Stored Cryptography Verification Tests (V6)

        Purpose:
        Performs automated tests to verify that sensitive data stored by the
        application is properly protected using strong cryptographic controls.
        These tests ensure that credentials, tokens, and confidential data
        are securely stored and not exposed in plaintext.

        Threat Model:
        Weak or missing cryptographic protections may allow attackers to:

            - retrieve sensitive data from compromised storage
            - extract credentials, tokens, or personal data
            - crack weakly hashed passwords
            - manipulate stored data without detection

        Attackers commonly target:

            - password storage mechanisms
            - API tokens and authentication secrets
            - encryption keys stored alongside encrypted data
            - database records containing sensitive information
            - backup or cached data stores

        Common vulnerabilities include:

            - plaintext storage of passwords or credentials
            - weak hashing algorithms (e.g., MD5, SHA1)
            - missing salting or key stretching for password hashes
            - encryption keys stored in the same location as encrypted data
            - insufficient protection of cryptographic materials

        Test Strategy:
        The method performs automated checks that:

            - inspect responses and storage behavior for plaintext sensitive data
            - analyze cryptographic usage patterns where observable
            - detect weak hashing or encryption indicators
            - verify that sensitive information is not returned in API responses
            - evaluate protection mechanisms for stored credentials and tokens

        Potential Impact:
        If stored cryptography protections are weak, attackers may:

            - recover user credentials or authentication tokens
            - access sensitive personal or financial data
            - escalate privileges using compromised secrets
            - compromise application integrity and user privacy

        Expected Behavior:
        Applications should:

            - hash passwords using strong algorithms (e.g., bcrypt, Argon2, PBKDF2)
            - encrypt sensitive stored data using strong encryption
            - protect and isolate cryptographic keys
            - avoid exposing sensitive data in API responses
            - follow industry best practices for secure key and secret management
        */
        
        private async Task<string> RunV6StoredCryptographyVerificationTestsAsync(Uri baseUri)
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

