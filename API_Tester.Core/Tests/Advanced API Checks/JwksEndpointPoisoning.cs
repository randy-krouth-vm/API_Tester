namespace API_Tester;

public partial class MainPage
{
    /*
    JWKS Endpoint Poisoning Test

    Purpose:
    Checks whether the application improperly trusts or dynamically retrieves
    JSON Web Key Sets (JWKS) from untrusted or attacker-controlled sources.

    Threat Model:
    JWT validation often relies on a JWKS endpoint that provides the public
    keys used to verify token signatures. If an application dynamically
    fetches keys based on user-controlled input (such as the "jku", "kid",
    or "x5u" fields in a JWT header), an attacker may be able to redirect
    the key lookup to a malicious JWKS endpoint.

    Test Strategy:
    The scanner sends JWT-like requests containing manipulated header
    parameters that reference external or unexpected JWKS locations.
    It observes whether the server attempts to retrieve keys from these
    locations or accepts tokens signed with attacker-controlled keys.

    Potential Impact:
    If JWKS poisoning is possible, attackers may be able to:

        - forge valid JWT tokens
        - impersonate arbitrary users
        - bypass authentication controls
        - escalate privileges within the application

    Expected Behavior:
    Applications should only trust JWKS endpoints from a predefined
    allowlist and should ignore any key references supplied by the client.
    JWT validation should use fixed, trusted key sources configured on
    the server.
    */

    private async Task<string> RunJwksEndpointPoisoningTestsAsync(Uri baseUri)
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
            ["kid"] = "attacker-key",
            ["jku"] = "https://example.invalid/.well-known/jwks.json"
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
            ? "Potential risk: externally supplied JWKS endpoint may be trusted."
            : "No obvious externally supplied JWKS trust indicator."
        };

        return FormatSection("JWKS Endpoint Poisoning", baseUri, findings);
    }

}

