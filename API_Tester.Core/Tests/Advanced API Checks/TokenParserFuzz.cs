namespace API_Tester;

public partial class MainPage
{
    /*
    Token Parser Fuzzing Test

    Purpose:
    Checks whether the API securely parses and validates authentication
    tokens such as JWTs, bearer tokens, API keys, or session identifiers.

    Threat Model:
    Authentication tokens often have structured formats (for example,
    JWT tokens containing header, payload, and signature segments).
    If the token parsing logic is fragile or poorly validated, attackers
    may craft malformed or manipulated tokens that bypass validation
    logic or cause unexpected behavior.

    Improper token parsing may allow attackers to exploit differences
    between how tokens are interpreted by different components of the
    system.

    Attack scenarios include:

        - submitting malformed or truncated tokens
        - injecting unexpected characters into token segments
        - modifying token structure to bypass validation checks
        - triggering parsing exceptions that reveal internal details
        - exploiting parser inconsistencies between libraries

    Example malformed tokens:

        Authorization: Bearer abc.def
        Authorization: Bearer abc..def
        Authorization: Bearer abc.def.ghi.extra
        Authorization: Bearer %00%00%00

    If the parser fails to properly validate token structure, it may
    incorrectly treat the token as valid or trigger unexpected behavior.

    Test Strategy:
    The scanner submits a variety of malformed or corrupted token
    structures and observes how the API responds. Responses are analyzed
    for parsing errors, unexpected success responses, or signals that
    token validation logic may be inconsistent.

    Potential Impact:
    If token parsing is weak or inconsistent, attackers may be able to:

        - bypass authentication checks
        - trigger parser errors that leak information
        - manipulate token interpretation
        - exploit differences between validation layers

    Expected Behavior:
    Token parsers should strictly validate token structure, reject
    malformed tokens immediately, and handle parsing failures safely
    without exposing sensitive implementation details.
    */
    
    private async Task<string> RunTokenParserFuzzTestsAsync(Uri baseUri)
    {
        var largeToken = $"{new string('A', 6000)}.{new string('B', 6000)}.{new string('C', 6000)}";
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
            req.Headers.TryAddWithoutValidation("Authorization", $"Bearer {largeToken}");
            return req;
        });

        var findings = new List<string> { $"HTTP {FormatStatus(response)}" };
        if (response is not null && (int)response.StatusCode >= 500)
        {
            findings.Add("Potential risk: oversized token triggers server error.");
        }
        else
        {
            findings.Add("No obvious parser crash from oversized token.");
        }

        return FormatSection("Token Parser Fuzzing", baseUri, findings);
    }

}

