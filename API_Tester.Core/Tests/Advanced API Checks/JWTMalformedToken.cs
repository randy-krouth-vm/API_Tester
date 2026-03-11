namespace API_Tester;

public partial class MainPage
{
    /*
    JWT Malformed Token Handling Test

    Purpose:
    Checks whether the API safely handles malformed or structurally invalid
    JSON Web Tokens (JWTs).

    Threat Model:
    Applications that process JWTs must correctly parse and validate the
    token structure before attempting verification. A valid JWT should
    consist of three Base64URL-encoded segments separated by periods:

        header.payload.signature

    Malformed tokens may include:

        - missing segments
        - corrupted Base64 encoding
        - invalid JSON in header or payload
        - extra or truncated sections

    If the server fails to properly validate the token structure before
    processing it, attackers may be able to trigger parsing errors or
    unexpected behavior.

    Test Strategy:
    The scanner sends malformed JWT values in the Authorization header and
    observes how the server responds. It checks whether the server safely
    rejects invalid tokens or produces unusual responses or internal errors.

    Potential Impact:
    Improper handling of malformed tokens may allow attackers to:

        - trigger application errors
        - cause denial-of-service conditions
        - expose internal error messages
        - reveal implementation details about authentication logic

    Expected Behavior:
    The server should strictly validate JWT structure and reject malformed
    tokens with a controlled authentication failure response, typically
    returning HTTP 401 Unauthorized without exposing internal errors.
    */

    private async Task<string> RunJwtMalformedTokenTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
            req.Headers.TryAddWithoutValidation("Authorization", "Bearer malformed.token");
            return req;
        });

        var findings = new List<string> { $"HTTP {FormatStatus(response)}" };
        if (response is not null && response.StatusCode == HttpStatusCode.OK)
        {
            findings.Add("Potential risk: malformed token appears accepted.");
        }
        else if (response is not null && (int)response.StatusCode >= 500)
        {
            findings.Add("Potential risk: malformed token caused server error.");
        }
        else
        {
            findings.Add("Malformed token was rejected or handled safely.");
        }

        return FormatSection("JWT Malformed Token", baseUri, findings);
    }

}

