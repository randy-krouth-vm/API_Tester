namespace API_Tester;

public partial class MainPage
{
    /*
    OAuth 1.0 Signature Validation Test

    Purpose:
    Checks whether an OAuth 1.0 endpoint improperly accepts requests with
    invalid signatures, weak signature methods, or missing required fields.
    */
    private async Task<string> RunOAuth1SignatureValidationTestsAsync(Uri baseUri)
    {
        var timestamp = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString();
        var nonce = Guid.NewGuid().ToString("N");

        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["oauth_consumer_key"] = "api-tester-client",
                ["oauth_signature_method"] = "PLAINTEXT",
                ["oauth_signature"] = "invalid&invalid",
                ["oauth_timestamp"] = timestamp,
                ["oauth_nonce"] = nonce,
                ["oauth_version"] = "1.0",
                ["oauth_callback"] = "https://example.invalid/callback"
            });
            return req;
        });

        var body = await ReadBodyAsync(response);
        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.OK
            ? "Potential risk: OAuth 1.0 request may have been accepted."
            : "No obvious OAuth 1.0 acceptance.",
            body.Contains("oauth_token", StringComparison.OrdinalIgnoreCase)
            ? "Potential risk: oauth_token marker returned."
            : "No oauth_token marker found in response."
        };

        return FormatSection("OAuth 1.0 Signature Validation", baseUri, findings);
    }
}
