namespace API_Tester;

public partial class MainPage
{
    /*
    mTLS Endpoint Exposure Test

    Purpose:
    Checks whether API endpoints intended to require mutual TLS (mTLS)
    authentication are accessible without presenting a valid client
    certificate.

    Threat Model:
    Mutual TLS requires both the server and the client to present valid
    certificates during the TLS handshake. This mechanism is often used
    to secure sensitive internal APIs, service-to-service communication,
    or high-privilege administrative endpoints.

    If an endpoint that should require mTLS is accessible without a client
    certificate, attackers may be able to reach internal services that were
    assumed to be protected by certificate-based authentication.

    Attack scenarios include:

        - accessing internal microservice APIs exposed behind gateways
        - reaching administrative endpoints intended only for trusted clients
        - bypassing client certificate validation due to misconfiguration
        - exploiting reverse proxies that terminate TLS without enforcing mTLS

    Test Strategy:
    The scanner sends requests to the target endpoint without presenting
    a client certificate and observes the response behavior. If the endpoint
    responds normally rather than rejecting the request during TLS negotiation
    or returning an authentication error, it may indicate that mTLS protection
    is not being enforced.

    Potential Impact:
    If mTLS enforcement is missing or misconfigured, attackers may be able to:

        - access internal or privileged APIs
        - impersonate trusted services
        - bypass service-to-service authentication controls
        - interact with endpoints assumed to be restricted to trusted clients

    Expected Behavior:
    Endpoints requiring mutual TLS should reject connections that do not
    present a valid client certificate. Requests without a trusted client
    certificate should fail during TLS negotiation or return an explicit
    authentication failure.
    */
    
    private async Task<string> RunMtlsEndpointExposureTestsAsync(Uri baseUri)
    {
        var mtlsPaths = new[] 
        { 
            "/mtls", 
            "/internal", 
            "/admin", 
            "/private", 
            "/secure", 
            "/protected", 
            "/api/v1/private", 
            "/api/v2/secure", 
            "/user/settings", 
            "/user/profile", 
            "/config/secret", 
            "/data/private", 
            "/management", 
            "/settings/secure", 
            "/api/v1/config", 
            "/admin/console" 
        };
        
        var findings = new List<string>();
        foreach (var path in mtlsPaths)
        {
            var uri = new Uri(baseUri, path);
            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, uri));
            findings.Add($"{path}: {FormatStatus(response)}");
        }

        return FormatSection("mTLS Endpoint Exposure", baseUri, findings);
    }

}

