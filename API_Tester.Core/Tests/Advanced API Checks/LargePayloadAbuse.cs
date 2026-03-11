namespace API_Tester;

public partial class MainPage
{
    /*
    Large Payload Abuse Test

    Purpose:
    Checks whether the API properly enforces limits on request body size
    to prevent excessive resource consumption.

    Threat Model:
    APIs that accept large request bodies without enforcing size limits
    may be vulnerable to resource exhaustion attacks. Attackers can send
    very large payloads to consume server memory, CPU, or bandwidth.

    Examples include:

        - oversized JSON bodies
        - extremely large multipart/form-data uploads
        - repeated nested structures

    If the server attempts to fully parse or buffer the payload before
    validation, it may cause excessive memory allocation or processing time.

    Test Strategy:
    The scanner sends requests containing abnormally large payloads and
    observes how the server responds. It checks whether the API accepts
    the payload, rejects it with an error, or becomes slow or unstable.

    Potential Impact:
    If request size limits are not enforced, attackers may be able to:

        - trigger denial-of-service conditions
        - exhaust memory or CPU resources
        - degrade performance for other users
        - cause application crashes

    Expected Behavior:
    The server should enforce strict maximum request size limits and reject
    requests that exceed acceptable thresholds, typically returning HTTP
    413 Payload Too Large.
    */

    private async Task<string> RunLargePayloadAbuseTestsAsync(Uri baseUri)
    {
        var payload = new string('A', 256 * 1024);
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Content = new StringContent(payload, Encoding.UTF8, "text/plain");
            return req;
        });

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && (int)response.StatusCode == 413
            ? "Payload size limits enforced (413 detected)."
            : "No explicit payload-size rejection detected."
        };

        return FormatSection("Large Payload Abuse", baseUri, findings);
    }

}

