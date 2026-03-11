namespace API_Tester;

public partial class MainPage
{
    /*
    gRPC Metadata Abuse Test

    Purpose:
    Checks whether a gRPC service improperly trusts client-supplied metadata
    (headers) that may influence authentication, routing, or internal logic.

    Threat Model:
    gRPC uses HTTP/2 headers called "metadata" to pass contextual information
    along with requests. These metadata fields are often used for purposes
    such as authentication tokens, user identity, tenant identifiers, or
    internal routing.

    If a service trusts metadata supplied directly by clients without proper
    validation, attackers may be able to spoof values such as:

        - user identity
        - authorization tokens
        - tenant or account identifiers
        - internal service flags

    Test Strategy:
    The scanner sends requests containing crafted or duplicate metadata
    fields to determine whether the service accepts or trusts these values.

    Potential Impact:
    Improper handling of metadata may allow attackers to:

        - bypass authentication or authorization checks
        - impersonate other users or tenants
        - manipulate internal request routing
        - trigger unintended service behavior

    Expected Behavior:
    gRPC services should strictly validate metadata values and ensure that
    sensitive metadata fields are generated only by trusted infrastructure
    components rather than client-controlled input.
    */

    private async Task<string> RunGrpcMetadataAbuseTestsAsync(Uri baseUri)
    {
        var uri = new Uri(baseUri, "/grpc.health.v1.Health/Check");
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, uri);
            req.Content = new ByteArrayContent(new byte[] { 0, 0, 0, 0, 0 });
            req.Content.Headers.TryAddWithoutValidation("Content-Type", "application/grpc");
            req.Headers.TryAddWithoutValidation("TE", "trailers");
            req.Headers.TryAddWithoutValidation("x-user-role", "admin");
            req.Headers.TryAddWithoutValidation("x-forwarded-for", "127.0.0.1");
            return req;
        });

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.OK
            ? "Potential risk: gRPC metadata override may influence authorization path."
            : "No obvious gRPC metadata abuse acceptance."
        };

        return FormatSection("gRPC Metadata Abuse", uri, findings);
    }

}

