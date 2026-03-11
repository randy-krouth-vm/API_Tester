namespace API_Tester;

public partial class MainPage
{
    /*
    OAuth Grant Type Misuse Test

    Purpose:
    Checks whether an API's OAuth authorization server improperly accepts
    or processes unsupported, deprecated, or misused OAuth grant types.

    Threat Model:
    OAuth uses specific grant types to define how clients obtain access
    tokens. Common secure grant types include:

        authorization_code
        client_credentials
        refresh_token

    If the server incorrectly accepts unsupported or deprecated grant types
    (such as password or implicit) or allows grant types that should be
    restricted to specific clients, attackers may be able to obtain access
    tokens illegitimately.

    Attack scenarios include:

        - using the password grant where it should be disabled
        - requesting tokens using unexpected or undocumented grant types
        - bypassing client authentication requirements
        - abusing refresh token flows to obtain new tokens improperly

    Test Strategy:
    The scanner submits token requests using various OAuth grant types and
    observes whether the authorization server accepts or rejects them.
    Responses are analyzed to determine whether the server enforces proper
    grant type restrictions.

    Potential Impact:
    If grant type validation is weak or misconfigured, attackers may be able
    to:

        - obtain access tokens without proper authorization
        - bypass intended authentication flows
        - impersonate legitimate users or clients
        - escalate privileges within the system

    Expected Behavior:
    The OAuth server should strictly enforce allowed grant types, require
    proper client authentication, and reject unsupported or deprecated
    grant types with a clear error response.
    */
    
    private async Task<string> RunOAuthGrantTypeMisuseTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "password",
                ["username"] = "testuser",
                ["password"] = "testpass",
                ["client_id"] = "api-tester-client"
            });
            return req;
        });

        var body = await ReadBodyAsync(response);
        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.OK
            ? "Potential risk: resource owner password grant may be enabled."
            : "No obvious password grant acceptance.",
            body.Contains("access_token", StringComparison.OrdinalIgnoreCase)
            ? "Potential risk: token-like response returned."
            : "No token marker found in response."
        };

        return FormatSection("OAuth Grant-Type Misuse", baseUri, findings);
    }

}

