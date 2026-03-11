namespace API_Tester;

public partial class MainPage
{
    /*
    gRPC Reflection Test

    Purpose:
    Checks whether the gRPC service exposes the reflection API that allows
    clients to query service definitions and protobuf schemas at runtime.

    Threat Model:
    gRPC reflection enables tools to dynamically discover available
    services, methods, message types, and protobuf schemas without
    having the original .proto files. While useful for development and
    debugging, leaving reflection enabled in production may expose
    internal service details to unauthorized users.

    Test Strategy:
    The scanner attempts to interact with the gRPC reflection service to
    determine whether it is enabled and accessible.

    Potential Impact:
    If reflection is exposed publicly, attackers may be able to:

        - enumerate all gRPC services and methods
        - discover request and response message structures
        - identify internal or undocumented RPC endpoints
        - map service dependencies and data models

    This information can significantly reduce the effort required to
    craft targeted requests or identify additional vulnerabilities.

    Expected Behavior:
    gRPC reflection should be disabled in production environments or
    restricted to authenticated and trusted clients only.
    */

    private async Task<string> RunGrpcReflectionTestsAsync(Uri baseUri)
    {
        var reflectionUri = new Uri(baseUri, "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo");
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, reflectionUri);
            req.Content = new ByteArrayContent(new byte[] { 0, 0, 0, 0, 0 });
            req.Content.Headers.TryAddWithoutValidation("Content-Type", "application/grpc");
            req.Headers.TryAddWithoutValidation("TE", "trailers");
            return req;
        });
        var body = await ReadBodyAsync(response);

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            ContainsAny(body, "service", "reflection", "grpc")
            ? "Service/reflection markers detected (review exposure)."
            : "No obvious reflection disclosure marker."
        };

        return FormatSection("gRPC Reflection", reflectionUri, findings);
    }

}

