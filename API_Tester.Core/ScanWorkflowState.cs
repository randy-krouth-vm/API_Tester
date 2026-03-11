using System.Net.Http;

namespace ApiTester.Core;

public sealed class ScanWorkflowState
{
    public const int PrettyResultFormattingMaxChars = 220_000;

    public HttpClient HttpClient { get; set; } = null!;
    public bool StartupInitialized { get; set; }
    public AsyncLocal<string?> ActiveStandardTestKey { get; } = new();
    public AsyncLocal<AuthProfile?> ActiveAuthProfile { get; } = new();
    public AsyncLocal<bool> StrictSingleTargetMode { get; } = new();
    public AsyncLocal<Uri?> StrictSingleBaseUri { get; } = new();
    public string? ResultsFindQuery { get; set; }
    public int ResultsFindIndex { get; set; } = -1;
    public bool ResultsFindCaseSensitive { get; set; }
    public bool SuppressFindPromptOnNextInvoke { get; set; }
    public AsyncLocal<AuditCaptureContext?> AuditCaptureContext { get; } = new();
    public Dictionary<string, string> BaselineArtifactMap { get; } = new(StringComparer.OrdinalIgnoreCase);
    public Dictionary<string, OpenApiProbeContext> OpenApiProbeContextCache { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string LastOpenApiInputRaw { get; set; } = string.Empty;
    public string RawResultsText { get; set; } = string.Empty;
    public string InMemoryRunLog { get; set; } = string.Empty;
    public bool CaptureRunProgressInMemory { get; set; }
    public string RenderedResultsText { get; set; } = string.Empty;
    public bool HeadlessAutoRunStarted { get; set; }
}

public sealed record AuthProfile(
    string Name,
    string BearerToken,
    string ApiKey,
    string ApiKeyHeader,
    string Cookie,
    Dictionary<string, string> ExtraHeaders);

public sealed record HttpExchangeEvidence(
    string RequestMethod,
    string RequestUri,
    string RequestHeaders,
    string RequestBody,
    int? ResponseStatusCode,
    string ResponseReasonPhrase,
    string ResponseHeaders,
    string ResponseBodySnippet,
    string ErrorMessage,
    string TimestampUtc);

public sealed record AuditCaptureContext(List<HttpExchangeEvidence> Exchanges);

public sealed record OpenApiOperationProfile(
    Uri Endpoint,
    List<string> AllowedMethods,
    List<string> QueryParameterNames,
    List<string> BodyPropertyNames,
    List<string> PathParameterNames,
    Dictionary<string, string> QueryParameterTypeHints,
    Dictionary<string, string> BodyPropertyTypeHints,
    Dictionary<string, string> PathParameterTypeHints);

public sealed record OpenApiProbeContext(
    List<Uri> TargetEndpoints,
    List<string> QueryParameterNames,
    List<string> BodyPropertyNames,
    List<string> NonStringQueryParameterNames,
    List<string> NonStringBodyPropertyNames,
    List<string> PathParameterNames,
    List<OpenApiOperationProfile> OperationProfiles);
