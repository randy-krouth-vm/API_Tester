namespace API_Tester;

public partial class MainPage
{
    /*
    JWT x5u Header Injection Test

    Purpose:
    Checks whether the API improperly trusts the "x5u" (X.509 URL) header
    parameter in a JWT to dynamically retrieve signing certificates.

    Threat Model:
    JWT headers can include an "x5u" field that specifies a URL where the
    server can fetch an X.509 certificate used to verify the token signature.
    If the server allows the client to supply this URL without strict
    validation, an attacker may point the server to a certificate they
    control.

    Attack scenario:

    1. The attacker crafts a JWT with a header like:

            { "alg": "RS256", "x5u": "https://attacker.com/cert.pem" }

    2. The attacker signs the token using the private key corresponding to
    that certificate.

    3. If the server fetches the certificate from the supplied URL and uses
    it for verification, the forged token may be accepted.

    Test Strategy:
    The scanner submits JWT-like requests containing manipulated "x5u"
    headers pointing to external or unexpected certificate URLs. It observes
    whether the server attempts to fetch certificates from those locations
    or accepts tokens signed with attacker-controlled keys.

    Potential Impact:
    If x5u header injection is possible, attackers may be able to:

        - forge valid authentication tokens
        - impersonate arbitrary users
        - escalate privileges
        - bypass authentication entirely

    Expected Behavior:
    JWT verification should only use certificates or key sources that are
    preconfigured and trusted by the server. Any "x5u" header supplied by
    clients should be ignored or strictly validated against an allowlist
    of approved certificate locations.
    */

    private async Task<string> RunJwtX5uHeaderInjectionTestsAsync(Uri baseUri)
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
            ["x5u"] = "https://example.invalid/cert.pem",
            ["kid"] = "example-cert"
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
            ? "Potential risk: token with untrusted x5u certificate URL may be accepted."
            : "No obvious untrusted x5u acceptance."
        };

        return FormatSection("JWT x5u Header Injection", baseUri, findings);
    }

}

