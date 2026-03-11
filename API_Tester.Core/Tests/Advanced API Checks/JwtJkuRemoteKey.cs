namespace API_Tester;

public partial class MainPage
{
    /*
    JWT JKU Remote Key Injection Test

    Purpose:
    Checks whether the application improperly trusts the "jku" (JSON Web Key URL)
    header parameter in a JWT to dynamically retrieve verification keys.

    Threat Model:
    Some JWT implementations support a "jku" header that tells the server
    where to fetch a JSON Web Key Set (JWKS) containing the public key used
    to verify the token signature.

    If the application allows the client to supply this URL without strict
    validation, an attacker may be able to point the server to a malicious
    JWKS endpoint they control. The attacker can then sign tokens with their
    own private key and have them accepted as valid by the server.

    Test Strategy:
    The scanner attempts to submit JWT-like requests containing a "jku"
    header that references an external or attacker-controlled JWKS endpoint.
    It observes whether the server attempts to fetch the key or accepts
    tokens signed with the injected key.

    Potential Impact:
    If the server trusts arbitrary JKU values, attackers may be able to:

        - forge valid authentication tokens
        - impersonate other users
        - escalate privileges
        - bypass authentication entirely

    Expected Behavior:
    JWT verification should only use trusted key sources defined by the
    server configuration. Any "jku" header supplied by clients should be
    ignored or strictly validated against an allowlist of approved JWKS
    endpoints.
    */

    private async Task<string> RunJwtJkuRemoteKeyTestsAsync(Uri baseUri)
    {
        var payload = new Dictionary<string, object>
        {
            ["sub"] = "apitester",
            ["scope"] = "admin",
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(30).ToUnixTimeSeconds()
        };
        var token = BuildUnsignedJwtWithCustomHeader(payload, new Dictionary<string, object>
        {
            ["alg"] = "RS256",
            ["typ"] = "JWT",
            ["jku"] = "https://example.invalid/jwks.json",
            ["kid"] = "example-key"
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
            ? "Potential risk: token with untrusted jku key source may be accepted."
            : "No obvious untrusted jku acceptance."
        };

        return FormatSection("JWT jku Remote Key", baseUri, findings);
    }

}

