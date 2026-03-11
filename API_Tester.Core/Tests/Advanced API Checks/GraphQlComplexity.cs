namespace API_Tester;

public partial class MainPage
{
    /*
    GraphQL Query Complexity Test

    Purpose:
    Evaluates whether a GraphQL endpoint enforces limits on query depth,
    field nesting, and overall query complexity.

    Threat Model:
    GraphQL allows clients to request deeply nested objects and multiple
    related fields in a single query. If the server does not enforce limits
    on query depth or complexity, attackers can craft expensive queries
    that cause excessive database calls or heavy computation.

    Attackers may abuse GraphQL queries by:

        - requesting deeply nested fields
        - requesting large numbers of related objects
        - repeating fragments or aliases
        - expanding recursive relationships

    Test Strategy:
    The scanner submits GraphQL queries with excessive nesting, repeated
    fields, or large object requests and observes whether the server
    accepts or rejects them.

    Potential Impact:
    If complexity limits are not enforced, attackers may be able to cause:

        - high CPU usage
        - database overload
        - memory exhaustion
        - denial-of-service (DoS)

    Expected Behavior:
    GraphQL servers should enforce limits such as:

        - maximum query depth
        - maximum query complexity score
        - rate limiting for expensive queries
        - query cost analysis before execution
    */

    private async Task<string> RunGraphQlComplexityTestsAsync(Uri baseUri)
    {
        var aliases = string.Join(" ", Enumerable.Range(1, 80).Select(i => $"a{i}:__typename"));
        var query = $"{{\"query\":\"query{{{aliases}}}\"}}";

        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Content = new StringContent(query, Encoding.UTF8, "application/json");
            return req;
        });

        var body = await ReadBodyAsync(response);
        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            ContainsAny(body, "complexity", "cost", "too many", "limit")
            ? "Complexity guardrail indicators observed."
            : "No explicit complexity-limit marker found."
        };

        return FormatSection("GraphQL Complexity", baseUri, findings);
    }

}

