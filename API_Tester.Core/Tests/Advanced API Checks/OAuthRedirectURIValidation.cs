namespace API_Tester;

public partial class MainPage
{
    /*
    OAuth Redirect URI Validation Test

    Purpose:
    Checks whether the OAuth authorization server properly validates the
    redirect_uri parameter during the authorization flow.

    Threat Model:
    In OAuth authorization code flows, the authorization server redirects
    the user back to the client application using a redirect_uri supplied
    in the authorization request. If the server does not strictly validate
    this URI against a pre-registered list of allowed redirect endpoints,
    attackers may be able to manipulate it.

    Improper validation can allow attackers to supply a malicious redirect
    URI and capture authorization codes or tokens intended for legitimate
    applications.

    Attack scenarios include:

        - substituting an attacker-controlled redirect URI
        - using partial or prefix matches to bypass validation
        - abusing open redirects on trusted domains
        - exploiting wildcard redirect URI configurations

    Example attack pattern:

        https://auth.example.com/authorize?
            client_id=CLIENT_ID
            &redirect_uri=https://attacker.com/callback
            &response_type=code

    If accepted, the authorization code may be sent directly to the attacker.

    Test Strategy:
    The scanner attempts authorization requests using modified redirect_uri
    values that differ from expected client registrations. It observes whether
    the authorization server accepts or rejects these values.

    Potential Impact:
    If redirect URI validation is weak, attackers may be able to:

        - intercept OAuth authorization codes
        - obtain access tokens
        - hijack user authentication flows
        - impersonate legitimate applications

    Expected Behavior:
    The authorization server should only allow redirect URIs that exactly
    match pre-registered client redirect endpoints. Requests with unknown
    or mismatched redirect URIs should be rejected.
    */
    
    private async Task<string> RunOAuthRedirectUriValidationTestsAsync(Uri baseUri)
    {
        var authorizeUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["response_type"] = "code",
            ["client_id"] = "api-tester-client",
            ["redirect_uri"] = "https://example.invalid/callback",
            ["state"] = "apitester"
        });

        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, authorizeUri));
        var body = await ReadBodyAsync(response);
        var location = response is null ? string.Empty : TryGetHeader(response, "Location");

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            (!string.IsNullOrWhiteSpace(location) && location.Contains("example.invalid", StringComparison.OrdinalIgnoreCase)) ||
            body.Contains("example.invalid", StringComparison.OrdinalIgnoreCase)
            ? "Potential risk: untrusted redirect URI appears accepted or reflected."
            : "No obvious untrusted redirect URI acceptance."
        };

        return FormatSection("OAuth Redirect URI Validation", authorizeUri, findings);
    }

}

