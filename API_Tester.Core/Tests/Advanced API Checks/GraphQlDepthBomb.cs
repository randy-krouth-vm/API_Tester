namespace API_Tester;

public partial class MainPage
{
    /*
    GraphQL Depth Bomb Test

    Purpose:
    Checks whether a GraphQL endpoint properly limits the depth of nested
    queries to prevent excessive recursion or resource consumption.

    Threat Model:
    GraphQL allows clients to request nested fields within a single query.
    If no depth limits are enforced, attackers can construct extremely deep
    queries (often called "depth bombs") that recursively request nested
    objects many levels deep.

    Example pattern:

        query {
            user {
                friends {
                    friends {
                        friends {
                            ...
                        }
                    }
                }
            }
        }

    Each level may trigger additional database queries or expensive
    resolver functions.

    Test Strategy:
    The scanner generates queries with progressively deeper nesting levels
    and observes whether the server accepts them or rejects them due to
    depth restrictions.

    Potential Impact:
    If depth limits are not enforced, attackers may be able to trigger:

        - excessive database queries
        - high CPU utilization
        - memory exhaustion
        - denial-of-service conditions

    Expected Behavior:
    GraphQL servers should enforce a maximum query depth and reject queries
    that exceed acceptable limits. Many frameworks provide depth limiting
    or query complexity analysis to prevent recursive abuse.
    */

    private async Task<string> RunGraphQlDepthBombTestsAsync(Uri baseUri)
    {
        const string query = "{\"query\":\"query { a { a { a { a { a { a { a { a { a { id } } } } } } } } } }\"}";
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
            ContainsAny(body, "depth", "complexity", "too deep", "validation")
            ? "Depth/complexity guardrail indicators observed."
            : "No explicit depth-limit indicator in response."
        };

        return FormatSection("GraphQL Depth Bomb", baseUri, findings);
    }

}

