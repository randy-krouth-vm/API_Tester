namespace ApiValidator;

public sealed record ApiTestAttachment(
    string? TestKey,
    string? Payload,
    bool PayloadExpected,
    string PayloadSource,
    string? RouteTemplate,
    IReadOnlyDictionary<string, string> RouteValues,
    ApiEndpointMetadata? EndpointMetadata,
    string Method,
    string Path,
    string QueryString,
    IReadOnlyDictionary<string, string[]> RequestHeaders,
    string? RequestBody,
    int? ResponseStatusCode,
    IReadOnlyDictionary<string, string[]> ResponseHeaders,
    string? ResponseBody,
    DateTime TimestampUtc);
