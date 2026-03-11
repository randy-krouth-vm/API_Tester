namespace API_Tester;

public partial class MainPage
{
    /*
    Deep JSON Nesting Test

    Purpose:
    Checks whether the API properly handles extremely deep or complex JSON
    structures in request bodies.

    Threat Model:
    Some JSON parsers or deserialization frameworks can become unstable
    or consume excessive resources when processing deeply nested objects
    or arrays. Attackers may intentionally craft requests with excessive
    nesting depth to trigger parsing failures or resource exhaustion.

    Test Strategy:
    The scanner sends JSON payloads with deeply nested structures and
    observes how the server processes them. It checks whether the API
    accepts the payload, rejects it with validation errors, or becomes
    slow or unstable while parsing it.

    Potential Impact:
    If nesting limits are not enforced, attackers may be able to cause:

        - excessive CPU usage
        - memory exhaustion
        - stack overflows in recursive parsers
        - denial-of-service (DoS) conditions

    This type of input can also expose weaknesses in JSON deserialization
    logic or input validation routines.

    Expected Behavior:
    Applications should enforce limits on JSON nesting depth, payload size,
    and parser complexity, and should reject excessively nested input with
    appropriate validation errors.
    */
    
    private async Task<string> RunDeepJsonNestingTestsAsync(Uri baseUri)
    {
        const int depth = 80;
        var sb = new StringBuilder();
        for (var i = 0; i < depth; i++)
        {
            sb.Append("{\"a\":");
        }

        sb.Append("\"x\"");
        for (var i = 0; i < depth; i++)
        {
            sb.Append('}');
        }

        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Content = new StringContent(sb.ToString(), Encoding.UTF8, "application/json");
            return req;
        });

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.InternalServerError
            ? "Potential risk: deep JSON nesting triggered server error."
            : "No obvious deep-nesting parser failure."
        };

        return FormatSection("Deep JSON Nesting", baseUri, findings);
    }

}

