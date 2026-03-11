namespace API_Tester;

public partial class MainPage
{
    /*
    mTLS Required Enforcement Test

    Purpose:
    Verifies that API endpoints configured to require mutual TLS (mTLS)
    correctly enforce the requirement for a valid client certificate.

    Threat Model:
    Mutual TLS requires both the server and the client to present valid
    certificates during the TLS handshake. It is commonly used to secure
    high-privilege APIs, internal service communication, and sensitive
    administrative endpoints.

    If mTLS is expected but not enforced, any client capable of establishing
    a normal TLS connection may be able to access endpoints that were
    intended to be restricted to trusted services or devices.

    Attack scenarios include:

        - direct access to privileged endpoints without a client certificate
        - bypassing service-to-service authentication
        - interacting with APIs assumed to be protected by certificate trust
        - exploiting gateway or proxy misconfiguration

    Test Strategy:
    The scanner attempts to access the endpoint without presenting a client
    certificate. The response behavior is observed to determine whether the
    server correctly rejects the connection or allows the request.

    Potential Impact:
    If endpoints requiring mTLS do not enforce client certificate validation,
    attackers may be able to:

        - access internal or administrative APIs
        - impersonate trusted services
        - bypass network trust boundaries
        - interact with sensitive endpoints without proper authentication

    Expected Behavior:
    Endpoints configured to require mutual TLS should reject requests that
    do not present a valid client certificate. The connection should fail
    during the TLS handshake or return an explicit authentication error.
    */
    
    private async Task<string> RunMtlsRequiredTestsAsync(Uri baseUri)
    {
        var findings = new List<string>();
        if (baseUri.Scheme != Uri.UriSchemeHttps)
        {
            findings.Add("Target is not HTTPS; mTLS cannot be validated on plaintext HTTP.");
            return FormatSection("mTLS Required Client Certificate", baseUri, findings);
        }

        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, baseUri));
        findings.Add($"HTTP {FormatStatus(response)}");
        findings.Add(response is not null && response.StatusCode == HttpStatusCode.OK
        ? "Potential risk: endpoint reachable without client certificate."
        : "Endpoint did not return 200 without client certificate (review if mTLS expected).");

        return FormatSection("mTLS Required Client Certificate", baseUri, findings);
    }

}

