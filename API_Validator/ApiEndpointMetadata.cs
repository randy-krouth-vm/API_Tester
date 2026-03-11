using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace ApiValidator;

public sealed record ApiEndpointMetadata(
    string? RouteTemplate,
    IReadOnlyList<string> HttpMethods,
    IReadOnlyList<string> RouteParameterNames,
    IReadOnlyList<string> MetadataTypes)
{
    public static ApiEndpointMetadata FromEndpoint(Endpoint? endpoint)
    {
        if (endpoint is not RouteEndpoint routeEndpoint)
        {
            return new ApiEndpointMetadata(
                null,
                Array.Empty<string>(),
                Array.Empty<string>(),
                endpoint?.Metadata.Select(m => m.GetType().Name).Distinct().ToArray() ?? Array.Empty<string>());
        }

        var methodMetadata = endpoint.Metadata.GetMetadata<HttpMethodMetadata>();
        var methods = methodMetadata?.HttpMethods?.ToArray() ?? Array.Empty<string>();
        var paramNames = routeEndpoint.RoutePattern.Parameters
            .Select(p => p.Name)
            .Where(n => !string.IsNullOrWhiteSpace(n))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        var metadataTypes = endpoint.Metadata.Select(m => m.GetType().Name).Distinct().ToArray();

        return new ApiEndpointMetadata(
            routeEndpoint.RoutePattern.RawText,
            methods,
            paramNames,
            metadataTypes);
    }
}
