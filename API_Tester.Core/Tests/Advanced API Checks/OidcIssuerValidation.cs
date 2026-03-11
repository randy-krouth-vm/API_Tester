namespace API_Tester;

public partial class MainPage
{
    /*
    OIDC Issuer Validation Test

    Purpose:
    Checks whether the API properly validates the "iss" (issuer) claim in
    OpenID Connect (OIDC) or JWT tokens used for authentication.

    Threat Model:
    The "iss" claim identifies the identity provider that issued the token.
    APIs must ensure that tokens are issued by a trusted authorization
    server or identity provider.

    If issuer validation is missing or weak, an attacker may present tokens
    issued by a different or malicious identity provider that the API
    should not trust.

    Attack scenarios include:

        - submitting tokens issued by a different identity provider
        - forging tokens using attacker-controlled authentication services
        - abusing test or development identity providers
        - bypassing authentication trust boundaries

    Example token payload:

        {
            "iss": "https://auth.example.com",
            "sub": "user123",
            "aud": "orders-api",
            "exp": 1710000000
        }

    If the API accepts tokens with an unexpected issuer, it may trust
    tokens that were never intended for the system.

    Test Strategy:
    The scanner submits tokens with modified or incorrect issuer claims
    and observes whether the API accepts or rejects the request.

    Potential Impact:
    If issuer validation is missing or misconfigured, attackers may be able to:

        - authenticate using tokens from untrusted providers
        - bypass identity provider restrictions
        - impersonate users
        - escalate privileges across authentication domains

    Expected Behavior:
    The API should strictly validate that the "iss" claim matches the
    expected identity provider and reject tokens issued by unknown
    or untrusted issuers.
    */
    
    private async Task<string> RunOidcIssuerValidationTestsAsync(Uri baseUri)
    {
        var fakeToken = BuildUnsignedJwt(new Dictionary<string, object>
        {
            ["iss"] = "https://example.invalid",
            ["aud"] = "api-tester-oidc-client",
            ["sub"] = "apitester",
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(20).ToUnixTimeSeconds()
        });

        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
            req.Headers.TryAddWithoutValidation("Authorization", $"Bearer {fakeToken}");
            return req;
        });

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.OK
            ? "Potential risk: token with untrusted issuer appears accepted."
            : "No obvious untrusted-issuer acceptance."
        };

        return FormatSection("OIDC Issuer Validation", baseUri, findings);
    }

}

