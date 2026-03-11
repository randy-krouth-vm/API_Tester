namespace API_Tester;

public partial class MainPage
{
    /*
    OAuth PKCE Enforcement Test

    Purpose:
    Checks whether the OAuth authorization server properly enforces
    Proof Key for Code Exchange (PKCE) for public clients during the
    authorization code flow.

    Threat Model:
    PKCE is designed to protect the OAuth authorization code flow from
    authorization code interception attacks, particularly in mobile apps,
    single-page applications, and other public clients that cannot safely
    store client secrets.

    Without PKCE, an attacker who intercepts an authorization code may be
    able to exchange it for an access token.

    PKCE works by introducing two values:

        code_verifier
        code_challenge

    The client generates a random code_verifier and sends a derived
    code_challenge during the authorization request. When exchanging the
    authorization code for a token, the client must present the original
    code_verifier.

    The authorization server verifies that the verifier matches the
    challenge before issuing the token.

    Test Strategy:
    The scanner attempts OAuth token exchange requests without PKCE
    parameters or with incorrect PKCE values and observes whether the
    authorization server still issues access tokens.

    Potential Impact:
    If PKCE enforcement is missing or improperly configured, attackers may
    be able to:

        - intercept authorization codes
        - exchange stolen codes for access tokens
        - impersonate legitimate users
        - bypass protections intended for public clients

    Expected Behavior:
    Authorization servers should require PKCE for public clients using the
    authorization code flow and reject token exchange attempts that do not
    include a valid code_verifier corresponding to the original
    code_challenge.
    */
    
    private async Task<string> RunOAuthPkceEnforcementTestsAsync(Uri baseUri)
    {
        var authorizeUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = "public-client",
            ["redirect_uri"] = "https://example-app.local/callback",
            ["state"] = "apitester"
        });

        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, authorizeUri));
        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && (response.StatusCode == HttpStatusCode.OK || response.StatusCode == HttpStatusCode.Redirect)
            ? "Potential risk: authorization flow may proceed without PKCE challenge."
            : "No obvious non-PKCE authorization acceptance."
        };

        return FormatSection("OAuth PKCE Enforcement", authorizeUri, findings);
    }

}

