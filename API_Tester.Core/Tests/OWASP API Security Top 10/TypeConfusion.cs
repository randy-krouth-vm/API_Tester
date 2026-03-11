namespace API_Tester;

public partial class MainPage
{
    /*
    Type Confusion Testing Payloads

    Purpose:
    Provides payloads used to test whether the application properly
    validates input types and handles unexpected data structures.
    These payloads simulate type confusion scenarios where inputs are
    interpreted differently than intended by the application.

    Threat Model:
    Type confusion vulnerabilities occur when an application expects a
    specific data type (e.g., string, integer, object) but processes
    attacker-controlled input as another type. Attackers may attempt to:

        - bypass validation logic
        - manipulate application behavior
        - trigger unexpected code paths
        - escalate privileges or access restricted resources

    These issues are especially common in APIs that process JSON input.

    Common vulnerabilities include:

        - accepting objects where scalar values are expected
        - improper deserialization of user-supplied data
        - failure to enforce strict schema validation
        - inconsistent type handling between validation and processing
        - reliance on loosely typed data structures

    Test Strategy:
    The payloads returned by this method simulate inputs that alter
    expected data types. These are used to determine whether the
    application incorrectly processes structured or conflicting types
    in request parameters.

    Potential Impact:
    If type confusion vulnerabilities exist, attackers may:

        - bypass authentication or authorization checks
        - manipulate application logic
        - trigger deserialization vulnerabilities
        - access or modify restricted data

    Expected Behavior:
    Applications should:

        - enforce strict schema validation for inputs
        - validate both structure and data types of request parameters
        - reject unexpected object or array inputs
        - use strongly typed request models
        - monitor and log suspicious input patterns
    */
    
    private static string[] GetTypeConfusionPayloads() =>
    [
        "{\"amount\":\"999999999999\",\"isAdmin\":\"true\",\"role\":1}",
        "{\"amount\":true,\"count\":\"-1\",\"active\":\"yes\"}",
        "{\"limit\":\"1000000\",\"offset\":\"NaN\",\"flags\":[\"admin\"]}",
        "{\"price\":{\"value\":\"999\"},\"quantity\":\"1e309\",\"enabled\":\"false\"}"
    ];

    private HttpRequestMessage FormatTypeConfusionRequest(Uri baseUri, string payload, TypeConfusionVector vector)
    {
        return vector switch
        {
            TypeConfusionVector.Json => BuildTypeConfusionJsonRequest(baseUri, payload),
            TypeConfusionVector.Query => BuildTypeConfusionQueryRequest(baseUri),
            _ => new HttpRequestMessage(HttpMethod.Get, baseUri)
        };
    }

    private static HttpRequestMessage BuildTypeConfusionJsonRequest(Uri baseUri, string payload)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
        req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
        return req;
    }

    private HttpRequestMessage BuildTypeConfusionQueryRequest(Uri baseUri)
    {
        var queryUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["amount"] = "999999999999",
            ["isAdmin"] = "true",
            ["limit"] = "NaN"
        });
        return new HttpRequestMessage(HttpMethod.Get, queryUri);
    }

    private enum TypeConfusionVector
    {
        Json,
        Query
    }

    private async Task<string> RunTypeConfusionTestsAsync(Uri baseUri)
    {
        var payloads = GetTypeConfusionPayloads();

        var findings = new List<string>();
        var accepted = 0;
        var attempts = 0;

        foreach (var payload in payloads)
        {
            var response = await SafeSendAsync(() => FormatTypeConfusionRequest(baseUri, payload, TypeConfusionVector.Json));
            attempts++;
            findings.Add($"JSON payload {attempts}: {FormatStatus(response)}");
            if (response is not null && (int)response.StatusCode is >= 200 and < 300)
            {
                accepted++;
            }
        }

        var queryResponse = await SafeSendAsync(() => FormatTypeConfusionRequest(baseUri, string.Empty, TypeConfusionVector.Query));
        attempts++;
        findings.Add($"Query type-confusion probe: {FormatStatus(queryResponse)}");
        if (queryResponse is not null && (int)queryResponse.StatusCode is >= 200 and < 300)
        {
            accepted++;
        }

        findings.Insert(0, $"Vectors tested: JSON body + query | Payload variants: {payloads.Length + 1}");
        findings.Add(accepted > 1
            ? $"Potential risk: type-coercion payloads accepted on {accepted}/{attempts} probes."
            : "No obvious type-confusion acceptance across tested vectors.");

        return FormatSection("Type Confusion", baseUri, findings);
    }
}
