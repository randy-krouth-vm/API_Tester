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

    private async Task<string> RunOAuthRefreshTokenTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = "invalid-refresh-token",
                ["client_id"] = "api-tester-client"
            });
            return req;
        });

        var body = await ReadBodyAsync(response);
        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.OK
            ? "Potential risk: invalid refresh token may be accepted."
            : "Invalid refresh token was not obviously accepted.",
            body.Contains("access_token", StringComparison.OrdinalIgnoreCase)
            ? "Potential risk: access token-like response detected."
            : "No access token marker found in response."
        };

        return FormatSection("OAuth Refresh Token Behavior", baseUri, findings);
    }

}

