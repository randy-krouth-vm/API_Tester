namespace API_Tester;

public partial class MainPage
{
    /*
    GraphQL Introspection Test

    Purpose:
    Determines whether the GraphQL endpoint allows schema introspection queries.

    Threat Model:
    GraphQL supports built-in introspection that lets clients query the schema
    to discover all types, queries, mutations, and fields. While useful for
    development tools, leaving introspection enabled in production can reveal
    the entire API structure to unauthorized users.

    Test Strategy:
    The scanner sends standard GraphQL introspection queries (for example
    queries referencing "__schema" or "__type") and observes whether the
    server returns schema metadata.

    Potential Impact:
    If introspection is enabled for unauthenticated users, attackers may be
    able to:

        - enumerate all queries and mutations
        - discover hidden or undocumented endpoints
        - identify internal object types and fields
        - map relationships between resources

    This information can significantly reduce the effort required to find
    other vulnerabilities in the API.

    Expected Behavior:
    Production GraphQL endpoints should restrict introspection queries to
    authorized users or disable them entirely outside of development
    environments.
    */

    private async Task<string> RunGraphQlIntrospectionTestsAsync(Uri baseUri)
    {
        var payload = "{\"query\":\"{__schema{types{name}}}\"}";
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            return req;
        });

        var body = await ReadBodyAsync(response);
        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            body.Contains("__schema", StringComparison.OrdinalIgnoreCase)
            ? "Potential risk: GraphQL introspection appears enabled."
            : "No GraphQL introspection indicator found."
        };

        return FormatSection("GraphQL Introspection", baseUri, findings);
    }

}

