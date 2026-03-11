namespace API_Tester;

public partial class MainPage
{
    /*
    JWT RS256 ↔ HS256 Algorithm Confusion Test

    Purpose:
    Checks whether the API is vulnerable to JWT algorithm confusion between
    asymmetric (RS256) and symmetric (HS256) signing algorithms.

    Threat Model:
    JWT tokens can be signed using different algorithms. RS256 uses an
    asymmetric key pair (private key to sign, public key to verify),
    while HS256 uses a shared secret.

    A vulnerable implementation may accept the algorithm specified in the
    token header and verify the signature using the wrong method.

    Attack scenario:

    1. The server expects RS256-signed tokens.
    2. The attacker changes the JWT header to:

            { "alg": "HS256" }

    3. The attacker signs the token using the server’s public key as the
    HMAC secret.
    4. If the server incorrectly uses that public key as the HS256 secret,
    the forged token may be accepted.

    Test Strategy:
    The scanner sends JWT-like tokens that attempt to change the signing
    algorithm from RS256 to HS256 and observes whether the server still
    accepts the token.

    Potential Impact:
    If algorithm confusion is possible, attackers may be able to:

        - forge valid authentication tokens
        - impersonate arbitrary users
        - escalate privileges
        - bypass authentication controls

    Expected Behavior:
    The server should enforce a fixed signing algorithm and ignore the
    algorithm specified by the client-supplied JWT header. Tokens signed
    with unexpected algorithms must be rejected.
    */

    private async Task<string> RunJwtRsHsConfusionTestsAsync(Uri baseUri)
    {
        var payload = new Dictionary<string, object>
        {
            ["sub"] = "apitester",
            ["role"] = "admin",
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(30).ToUnixTimeSeconds()
        };
        var token = BuildUnsignedJwtWithCustomHeader(payload, new Dictionary<string, object>
        {
            ["alg"] = "HS256",
            ["typ"] = "JWT",
            ["kid"] = "rsa-public-key"
        });

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
            ? "Potential risk: possible RS256/HS256 algorithm confusion acceptance."
            : "No obvious algorithm-confusion acceptance."
        };

        return FormatSection("JWT RS256-HS256 Confusion", baseUri, findings);
    }

}

