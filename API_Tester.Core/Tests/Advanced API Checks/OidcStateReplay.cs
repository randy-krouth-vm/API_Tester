namespace API_Tester;

public partial class MainPage
{
    /*
    OIDC State Replay Test

    Purpose:
    Checks whether the application properly validates and enforces the
    "state" parameter in OpenID Connect (OIDC) authorization flows.

    Threat Model:
    The "state" parameter is used by OIDC and OAuth clients to bind an
    authorization request to the resulting authorization response. It
    helps prevent cross-site request forgery (CSRF) and replay attacks
    during the login process.

    If the application does not properly validate the state value, or
    allows previously used state values to be reused, attackers may be
    able to manipulate the authentication flow.

    Attack scenarios include:

        - replaying a previously captured authorization response
        - injecting a malicious authorization response into another user's session
        - bypassing CSRF protections in the login flow
        - forcing a victim to authenticate using an attacker-controlled request

    Example flow:

        Client → /authorize?state=RANDOM_VALUE
        Identity Provider → redirect back with state=RANDOM_VALUE

    The client must verify that the returned state matches the original
    request and that the value has not been reused.

    Test Strategy:
    The scanner attempts to submit authorization responses or parameters
    with reused, missing, or altered state values and observes whether
    the application accepts them.

    Potential Impact:
    If state validation is weak or missing, attackers may be able to:

        - perform login CSRF attacks
        - hijack authentication sessions
        - inject authorization responses
        - bypass protections designed to bind requests and responses

    Expected Behavior:
    Applications should generate strong, unpredictable state values,
    store them for the duration of the authentication flow, and verify
    that the returned state exactly matches the original request and
    cannot be reused.
    */
    
    private async Task<string> RunOidcStateReplayTestsAsync(Uri baseUri)
    {
        var authorizeUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = "api-tester-oidc-client",
            ["redirect_uri"] = "https://example-app.local/callback",
            ["scope"] = "openid profile",
            ["state"] = "fixed-state-value"
        });

        var first = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, authorizeUri));
        var second = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, authorizeUri));

        var findings = new List<string>
        {
            $"First request: {FormatStatus(first)}",
            $"Replay request: {FormatStatus(second)}",
            first is not null && second is not null && first.StatusCode == HttpStatusCode.Redirect && second.StatusCode == HttpStatusCode.Redirect
            ? "Potential risk: repeated fixed state is accepted without visible anti-replay signal."
            : "No obvious state replay acceptance indicator."
        };

        return FormatSection("OIDC State Replay", authorizeUri, findings);
    }

}

