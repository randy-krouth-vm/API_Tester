namespace API_Tester;

public partial class MainPage
{
    /*
    JWT "none" Algorithm Acceptance Test

    Purpose:
    Checks whether the API improperly accepts JSON Web Tokens that specify
    the "none" algorithm, which indicates that the token is unsigned.

    Threat Model:
    JWT headers include an "alg" field specifying the signing algorithm
    used to generate the token signature. In properly configured systems,
    this value must match a trusted signing algorithm such as:

        HS256
        RS256
        ES256

    If the server accepts "alg": "none", the token contains no signature
    and can be freely modified by an attacker.

    Test Strategy:
    The scanner submits a JWT-like token where the header specifies:

        { "alg": "none" }

    and the token contains a payload but no valid signature. It observes
    whether the API rejects the token or incorrectly accepts it.

    Potential Impact:
    If the server accepts tokens using the "none" algorithm, attackers may:

        - forge arbitrary authentication tokens
        - impersonate any user
        - escalate privileges
        - bypass authentication entirely

    Expected Behavior:
    The server must reject any JWT specifying the "none" algorithm and
    should only accept tokens signed using explicitly configured
    cryptographic algorithms.
    */

    private async Task<string> RunJwtNoneAlgorithmTestsAsync(Uri baseUri)
    {
        const string token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ0ZXN0Iiwicm9sZSI6ImFkbWluIn0.";
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
            ? "Potential risk: unsigned JWT may be accepted."
            : "No obvious unsigned JWT acceptance."
        };

        return FormatSection("JWT none-algorithm Probe", baseUri, findings);
    }

}

