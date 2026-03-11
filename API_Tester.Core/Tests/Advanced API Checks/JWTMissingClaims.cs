namespace API_Tester;

public partial class MainPage
{
    /*
    JWT Missing Claims Validation Test

    Purpose:
    Checks whether the API properly validates required JWT claims and
    rejects tokens that are missing critical fields.

    Threat Model:
    JWTs typically contain standard claims that help the server determine
    whether the token is valid and intended for the current application.
    If the server fails to enforce the presence of these claims, attackers
    may be able to construct incomplete tokens that bypass important
    validation checks.

    Common required claims include:

        iss   (issuer)
        aud   (audience)
        exp   (expiration time)
        iat   (issued at)
        sub   (subject / user identity)

    Test Strategy:
    The scanner sends JWT-like tokens that intentionally omit one or more
    expected claims and observes how the server responds. It checks whether
    the API still accepts the token or correctly rejects it.

    Potential Impact:
    If required claims are not enforced, attackers may be able to:

        - bypass token expiration controls
        - use tokens issued for other services
        - impersonate users without proper identity fields
        - weaken overall authentication validation

    Expected Behavior:
    The server should require all mandatory claims and reject any token
    that is missing them, returning an authentication failure response
    such as HTTP 401 Unauthorized.
    */

    private async Task<string> RunJwtMissingClaimsTestsAsync(Uri baseUri)
    {
        var payload = new Dictionary<string, object>
        {
            ["sub"] = "apitester",
            ["scope"] = "admin"
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
            ? "Potential risk: token without expected claims appears accepted."
            : "No obvious missing-claims acceptance."
        };

        return FormatSection("JWT Missing Claims", baseUri, findings);
    }

}

