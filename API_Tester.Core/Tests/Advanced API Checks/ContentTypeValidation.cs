namespace API_Tester;

public partial class MainPage
{
    /*
    Content-Type Validation Test

    Purpose:
    Verifies whether the API properly validates the Content-Type header
    and rejects unexpected or unsupported media types.

    Threat Model:
    Some applications rely on the Content-Type header to determine how
    request bodies should be parsed. If validation is weak or absent,
    attackers may send requests with misleading or incorrect content types
    to bypass validation logic or trigger unintended parsing behavior.

    For example, an endpoint expecting JSON may incorrectly process data
    sent as:

        text/plain
        application/xml
        multipart/form-data

    Improper handling may allow attackers to manipulate input processing
    or exploit inconsistencies between parsers.

    Test Strategy:
    The scanner sends requests using various Content-Type headers and
    observes how the server responds. It checks whether endpoints accept
    unexpected media types or fail to enforce strict content validation.

    Potential Impact:
    If Content-Type validation is not enforced, attackers may exploit
    parsing discrepancies to:

        - bypass input validation
        - inject malformed data
        - exploit deserialization or parser vulnerabilities
        - trigger unexpected server behavior

    Expected Behavior:
    The server should strictly validate Content-Type headers and return
    an error (such as HTTP 415 Unsupported Media Type) when receiving
    unexpected or unsupported formats.
    */
    
    private async Task<string> RunContentTypeValidationTestsAsync(Uri baseUri)
    {
        const string jsonBody = "{\"test\":\"value\"}";
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Content = new StringContent(jsonBody, Encoding.UTF8, "text/plain");
            return req;
        });
        var body = await ReadBodyAsync(response);

        var enforced = response is not null &&
                       (response.StatusCode == HttpStatusCode.UnsupportedMediaType ||
                        response.StatusCode == HttpStatusCode.BadRequest);
        var serverError = response is not null && (int)response.StatusCode >= 500;
        var exceptionLeak = ContainsAny(body, "exception", "stack trace", "invalidoperationexception", "developerexceptionpage");

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            enforced
                ? "Content-type validation appears enforced."
                : serverError || exceptionLeak
                    ? "Potential risk: invalid content-type handling triggered unhandled server error details."
                    : "Potential risk: invalid content-type may be accepted."
        };

        return FormatSection("Content-Type Validation", baseUri, findings);
    }

}

