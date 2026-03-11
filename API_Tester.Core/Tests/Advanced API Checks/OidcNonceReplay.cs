namespace API_Tester;

public partial class MainPage
{
    /*
    OIDC Nonce Replay Test

    Purpose:
    Checks whether the application properly enforces nonce validation in
    OpenID Connect (OIDC) authentication flows to prevent replay attacks.

    Threat Model:
    In OpenID Connect, the nonce parameter is used to bind an authentication
    request to the resulting ID token. The client generates a random nonce
    value during the authorization request, and the identity provider
    includes that value in the issued ID token.

    If the application does not validate the nonce or allows previously used
    nonces to be reused, attackers may replay captured ID tokens to gain
    unauthorized access.

    Attack scenarios include:

        - replaying a previously issued ID token
        - using tokens captured from network traffic or logs
        - reusing authentication responses in session fixation attacks
        - bypassing replay protections when nonce validation is missing

    Test Strategy:
    The scanner attempts to submit authentication responses or tokens that
    contain reused or invalid nonce values and observes whether the
    application accepts them.

    Potential Impact:
    If nonce validation is missing or improperly implemented, attackers may
    be able to:

        - replay authentication tokens
        - hijack user sessions
        - impersonate authenticated users
        - bypass replay protection mechanisms

    Expected Behavior:
    Applications should generate cryptographically strong nonce values,
    store them securely during the authentication flow, and verify that
    the nonce returned in the ID token matches the original request and
    has not been reused.
    */
    
    private async Task<string> RunOidcNonceReplayTestsAsync(Uri baseUri)
    {
        var authorizeUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["response_type"] = "id_token token",
            ["client_id"] = "api-tester-oidc-client",
            ["redirect_uri"] = "https://example-app.local/callback",
            ["scope"] = "openid profile",
            ["nonce"] = "fixed-nonce-value"
        });

        var first = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, authorizeUri));
        var second = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, authorizeUri));

        var findings = new List<string>
        {
            $"First request: {FormatStatus(first)}",
            $"Replay request: {FormatStatus(second)}",
            first is not null && second is not null && first.StatusCode == second.StatusCode
            ? "Potential risk: nonce replay resistance not obvious from flow behavior."
            : "No obvious nonce replay indicator."
        };

        return FormatSection("OIDC Nonce Replay", authorizeUri, findings);
    }

}

