namespace API_Tester;

public partial class MainPage
{
    /*
    OIDC Token Substitution Test

    Purpose:
    Checks whether the application properly validates the relationship
    between ID tokens, access tokens, and the authenticated user during
    OpenID Connect (OIDC) authentication flows.

    Threat Model:
    In OpenID Connect, an ID token represents the authenticated user and
    contains claims such as "sub" (subject) that identify the user. If an
    application fails to correctly bind the ID token to the authenticated
    session or associated access token, attackers may attempt token
    substitution.

    Token substitution occurs when an attacker replaces one token in the
    authentication flow with another valid token issued for a different
    user or client.

    Attack scenarios include:

        - replacing a victim's ID token with one belonging to the attacker
        - mixing tokens issued for different users
        - using tokens issued to a different client application
        - exploiting weak token binding between authentication steps

    Example scenario:

        1. Victim authenticates and receives a valid session.
        2. Attacker injects an ID token that identifies the attacker.
        3. If the application fails to verify token consistency, the
        session may become associated with the attacker's identity.

    Test Strategy:
    The scanner attempts to supply tokens with inconsistent user or client
    claims and observes whether the application properly validates token
    relationships and rejects mismatched tokens.

    Potential Impact:
    If token substitution is possible, attackers may be able to:

        - impersonate other users
        - hijack authenticated sessions
        - bypass authentication integrity checks
        - gain unauthorized access to protected resources

    Expected Behavior:
    Applications should verify that tokens are correctly bound to the
    authentication session, ensure that user identifiers (such as "sub")
    remain consistent across tokens, and validate issuer, audience, and
    client bindings for all tokens used in the authentication process.
    */

    private async Task<string> RunOidcTokenSubstitutionTestsAsync(Uri baseUri)
    {
        var idTokenLike = BuildUnsignedJwt(new Dictionary<string, object>
        {
            ["iss"] = "https://issuer.example",
            ["aud"] = "api-tester-oidc-client",
            ["sub"] = "apitester",
            ["nonce"] = "apitester",
            ["typ"] = "id_token",
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(20).ToUnixTimeSeconds()
        });

        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
            req.Headers.TryAddWithoutValidation("Authorization", $"Bearer {idTokenLike}");
            return req;
        });

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.OK
            ? "Potential risk: ID-token-like artifact may be accepted as API access token."
            : "No obvious token-substitution acceptance."
        };

        return FormatSection("OIDC Token Substitution", baseUri, findings);
    }

}

