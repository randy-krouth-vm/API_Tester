namespace API_Tester;

public partial class MainPage
{
    /*
    JWT KID Header Injection Test

    Purpose:
    Checks whether the application safely handles the "kid" (Key ID) field
    in the JWT header when selecting a verification key.

    Threat Model:
    The "kid" header is commonly used by servers to determine which signing
    key should be used to verify a JWT. If the value is used directly in
    file paths, database queries, or key lookups without validation,
    attackers may inject malicious values that manipulate how the key
    is retrieved.

    Attack patterns may include:

        - path traversal attempts
        - SQL or lookup injection
        - selecting unintended verification keys
        - forcing fallback verification behavior

    Test Strategy:
    The scanner sends JWT-like tokens containing crafted "kid" values and
    observes whether the server handles them safely or produces unusual
    responses indicating unsafe key selection logic.

    Potential Impact:
    If the server uses the "kid" value unsafely, attackers may be able to:

        - force the server to use an attacker-controlled key
        - bypass signature validation
        - read local files used as keys
        - escalate privileges or impersonate other users

    Expected Behavior:
    Applications should treat the "kid" value strictly as an identifier and
    resolve it only against a predefined set of trusted keys. User-supplied
    values must never be used directly in file paths, queries, or external
    lookups.
    */
    
    private async Task<string> RunJwtKidHeaderInjectionTestsAsync(Uri baseUri)
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
            ["kid"] = "../../../../etc/passwd"
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
            ? "Potential risk: suspicious kid header token may be accepted."
            : "No obvious acceptance of malicious kid header."
        };

        return FormatSection("JWT kid Header Injection", baseUri, findings);
    }

}

