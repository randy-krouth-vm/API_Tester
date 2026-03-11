namespace API_Tester;

public partial class MainPage
{
    /*
    Token in Query Parameter Test

    Purpose:
    Checks whether authentication tokens, API keys, session identifiers,
    or other sensitive credentials are accepted or transmitted through
    URL query parameters.

    Threat Model:
    Sensitive tokens included in URL query strings can be exposed through
    multiple unintended channels. Unlike headers or request bodies, URLs
    are commonly logged and stored by browsers, proxies, and monitoring
    systems.

    If authentication tokens are passed in query parameters, they may
    leak through logs or other systems even when HTTPS is used.

    Attack scenarios include:

        - tokens recorded in web server access logs
        - tokens stored in browser history
        - tokens exposed through analytics or monitoring tools
        - tokens leaked via the HTTP Referer header when users
        navigate to other sites
        - tokens captured in shared links or screenshots

    Example risky pattern:

        https://api.example.com/data?token=ABC123XYZ

    If this URL is logged or shared, the token may be exposed to others.

    Test Strategy:
    The scanner sends requests containing authentication-style parameters
    in query strings and observes whether the API accepts them as valid
    credentials or processes them as authorization tokens.

    Potential Impact:
    If sensitive tokens are accepted through query parameters, attackers
    may be able to:

        - retrieve tokens from logs or monitoring systems
        - replay captured tokens to access protected resources
        - steal session credentials through referer leaks

    Expected Behavior:
    Authentication tokens should be transmitted using secure mechanisms
    such as HTTP Authorization headers or secure cookies rather than
    URL query parameters. Applications should reject credentials provided
    in query strings for security-sensitive operations.
    */
    
    private async Task<string> RunTokenInQueryTestsAsync(Uri baseUri)
    {
        var testUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["access_token"] = "ey.fake.test.token"
        });

        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, testUri));
        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.OK
            ? "Potential risk: token passed via query may be accepted."
            : "No obvious token-in-query acceptance."
        };

        return FormatSection("Token in Query String", testUri, findings);
    }

}

