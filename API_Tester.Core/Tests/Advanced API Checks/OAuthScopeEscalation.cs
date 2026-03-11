namespace API_Tester;

public partial class MainPage
{
    /*
    OAuth Refresh Token Handling Test

    Purpose:
    Checks whether the OAuth authorization server securely handles
    refresh tokens and enforces proper validation during token renewal.

    Threat Model:
    Refresh tokens allow clients to obtain new access tokens without
    requiring the user to re-authenticate. Because refresh tokens often
    have long lifetimes and high privilege, they must be carefully
    protected and validated.

    Improper refresh token handling may allow attackers to reuse,
    replay, or abuse refresh tokens to continuously obtain new
    access tokens.

    Attack scenarios include:

        - reusing a refresh token multiple times without rotation
        - exchanging expired or revoked refresh tokens
        - refreshing tokens without proper client authentication
        - abusing refresh tokens issued to other clients

    Test Strategy:
    The scanner submits refresh token requests to the token endpoint
    using various conditions such as repeated use, missing parameters,
    or altered tokens. The responses are analyzed to determine whether
    the authorization server enforces proper refresh token validation
    and rotation policies.

    Potential Impact:
    If refresh token protections are weak, attackers may be able to:

        - maintain long-term unauthorized access
        - bypass session expiration controls
        - continuously generate new access tokens
        - hijack user sessions

    Expected Behavior:
    Authorization servers should validate refresh tokens strictly,
    enforce expiration and revocation checks, bind tokens to the
    original client, and ideally implement refresh token rotation
    to prevent replay attacks.
    */
    
    private async Task<string> RunOAuthScopeEscalationTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "client_credentials",
                ["client_id"] = "api-tester-client",
                ["client_secret"] = "invalid-secret",
                ["scope"] = "admin superuser root"
            });
            return req;
        });

        var body = await ReadBodyAsync(response);
        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.OK
            ? "Potential risk: privileged scopes may be granted."
            : "No obvious privileged scope grant acceptance.",
            body.Contains("scope", StringComparison.OrdinalIgnoreCase) || body.Contains("admin", StringComparison.OrdinalIgnoreCase)
            ? "Scope-related response content detected (review required)."
            : "No explicit scope echo detected in response."
        };

        return FormatSection("OAuth Scope Escalation", baseUri, findings);
    }

}

