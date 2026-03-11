namespace API_Tester;

public partial class MainPage
{
    /*
    OIDC Discovery Hijacking Test

    Purpose:
    Checks whether the application improperly trusts or dynamically loads
    OpenID Connect (OIDC) discovery metadata from untrusted or attacker-
    controlled locations.

    Threat Model:
    OIDC clients often retrieve configuration information from a discovery
    endpoint, typically located at:

        /.well-known/openid-configuration

    This document provides critical security information such as:

        - issuer
        - authorization endpoint
        - token endpoint
        - JWKS signing keys
        - supported algorithms

    If an application allows the discovery endpoint location to be
    influenced by user input or external configuration without validation,
    an attacker may redirect the client to a malicious discovery document.

    Attack scenarios include:

        - supplying an attacker-controlled discovery URL
        - redirecting OIDC configuration lookups to malicious servers
        - injecting fake JWKS signing keys
        - manipulating token validation parameters

    Test Strategy:
    The scanner attempts to influence discovery configuration resolution
    or probes discovery endpoints to determine whether the application
    dynamically trusts externally supplied OIDC configuration documents.

    Potential Impact:
    If OIDC discovery is improperly trusted, attackers may be able to:

        - forge authentication tokens
        - impersonate legitimate users
        - bypass authentication controls
        - manipulate identity provider configuration

    Expected Behavior:
    Applications should only trust discovery documents from predefined
    identity providers and should strictly validate issuer values and
    JWKS sources before using them for token validation.
    */
    private async Task<string> RunOidcDiscoveryHijackingTestsAsync(Uri baseUri)
    {
        var discoveryUri = new Uri(baseUri, "/.well-known/openid-configuration?issuer=https://example.invalid");
        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, discoveryUri));
        var body = await ReadBodyAsync(response);

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            body.Contains("example.invalid", StringComparison.OrdinalIgnoreCase)
            ? "Potential risk: discovery metadata may reflect or trust attacker-supplied issuer."
            : "No obvious discovery-issuer hijack indicator."
        };

        return FormatSection("OIDC Discovery Hijacking", discoveryUri, findings);
    }

}

