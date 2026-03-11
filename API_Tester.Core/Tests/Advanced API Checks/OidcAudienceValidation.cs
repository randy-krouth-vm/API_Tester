namespace API_Tester;

public partial class MainPage
{
    /*
    OIDC Audience Validation Test

    Purpose:
    Checks whether the API properly validates the "aud" (audience) claim
    in OpenID Connect (OIDC) or JWT access tokens.

    Threat Model:
    The "aud" claim identifies the intended recipient of the token.
    APIs must ensure that tokens presented to them were actually issued
    for that specific service. If audience validation is missing or weak,
    a token issued for one service may be accepted by another service.

    Attack scenarios include:

        - using a token issued for a different API
        - replaying tokens across multiple services
        - abusing tokens issued for client applications
        - bypassing service-specific authorization checks

    Example token payload:

        {
            "sub": "user123",
            "aud": "payments-api",
            "iss": "https://auth.example.com",
            "scope": "payments:read"
        }

    If another API (for example "orders-api") accepts this token without
    checking the audience, the token can be reused across services.

    Test Strategy:
    The scanner submits tokens with incorrect or modified audience claims
    to the API and observes whether the request is accepted or rejected.
    Responses are analyzed to determine whether the server enforces
    proper audience validation.

    Potential Impact:
    If audience validation is missing or misconfigured, attackers may be
    able to:

        - reuse tokens across multiple services
        - access unintended APIs
        - bypass service boundaries
        - escalate privileges within distributed systems

    Expected Behavior:
    APIs should strictly validate that the "aud" claim matches the
    expected service identifier and reject tokens issued for other
    audiences.
    */

    private async Task<string> RunOidcAudienceValidationTestsAsync(Uri baseUri)
    {
        var wrongAudienceToken = BuildUnsignedJwt(new Dictionary<string, object>
        {
            ["iss"] = "https://issuer.example",
            ["aud"] = "another-client",
            ["sub"] = "apitester",
            ["exp"] = DateTimeOffset.UtcNow.AddMinutes(20).ToUnixTimeSeconds()
        });

        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
            req.Headers.TryAddWithoutValidation("Authorization", $"Bearer {wrongAudienceToken}");
            return req;
        });

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.OK
            ? "Potential risk: token with wrong audience appears accepted."
            : "No obvious wrong-audience acceptance."
        };

        return FormatSection("OIDC Audience Validation", baseUri, findings);
    }

}

