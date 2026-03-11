namespace API_Tester;

public partial class MainPage
{
    /*
    Transport Security Test

    Purpose:
    Checks whether the application properly enforces secure transport
    mechanisms for client-server communication, ensuring that sensitive
    data is transmitted only over encrypted connections.

    Threat Model:
    Transport security vulnerabilities occur when applications allow
    communication over insecure channels such as HTTP instead of HTTPS.
    If transport encryption is not enforced, attackers may intercept,
    modify, or observe traffic through man-in-the-middle (MITM) attacks.

    Sensitive data such as authentication tokens, session cookies,
    credentials, or personal information could be exposed if transmitted
    over an unencrypted connection.

    Attack scenarios include:

        - intercepting login credentials on insecure networks
        - capturing session cookies or API tokens
        - modifying requests or responses in transit
        - performing downgrade attacks to force HTTP connections

    Example insecure behavior:

        http://api.example.com/login

    If the server allows authentication or sensitive operations over HTTP,
    an attacker on the network may intercept the request.

    Test Strategy:
    The scanner attempts requests over HTTP and observes whether the server
    rejects insecure transport, redirects to HTTPS, or allows sensitive
    operations to proceed without encryption.

    Potential Impact:
    If transport security is weak or not enforced, attackers may be able to:

        - intercept sensitive data
        - hijack authenticated sessions
        - modify requests and responses
        - impersonate users

    Expected Behavior:
    Applications should enforce HTTPS for all sensitive endpoints and
    redirect HTTP requests to HTTPS. Security headers such as
    Strict-Transport-Security (HSTS) should be enabled to ensure that
    browsers always use encrypted connections.
    */
    
    private async Task<string> RunTransportSecurityTestsAsync(Uri baseUri)
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

