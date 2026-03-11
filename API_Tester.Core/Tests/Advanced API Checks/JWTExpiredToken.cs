namespace API_Tester;

public partial class MainPage
{
    /*
    JWT Expired Token Test

    Purpose:
    Checks whether the API properly rejects JSON Web Tokens (JWTs) whose
    expiration time has passed.

    Threat Model:
    JWTs typically include an "exp" (expiration) claim that defines how long
    the token is valid. If the server fails to enforce this claim or ignores
    expiration during validation, attackers may reuse old tokens indefinitely.

    Expired tokens may originate from:

        - previously captured network traffic
        - leaked tokens stored in logs
        - compromised client devices
        - long-lived tokens that were never revoked

    Test Strategy:
    The scanner submits requests using JWTs that contain expiration times
    in the past and observes whether the API accepts or rejects them.

    Potential Impact:
    If expired tokens are still accepted, attackers may be able to:

        - replay old authentication tokens
        - maintain unauthorized access after logout
        - bypass session expiration controls

    Expected Behavior:
    The server should validate the "exp" claim during token verification and
    reject tokens whose expiration time has already passed, typically
    returning a 401 Unauthorized response.
    */

    private async Task<string> RunJwtExpiredTokenTestsAsync(Uri baseUri)
    {
        var payload = new Dictionary<string, object>
        {
            ["sub"] = "apitester",
            ["exp"] = DateTimeOffset.UtcNow.AddHours(-2).ToUnixTimeSeconds()
        };
        var token = BuildUnsignedJwt(payload);

        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
            req.Headers.TryAddWithoutValidation("Authorization", $"Bearer {token}");
            return req;
        });

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.OK
            ? "Potential risk: expired token appears accepted."
            : "No obvious expired-token acceptance."
        };

        return FormatSection("JWT Expired Token", baseUri, findings);
    }

}

