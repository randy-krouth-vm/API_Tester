using ApiTester.Core;
using ApiTester.Shared;

namespace API_Tester;

public partial class MainPage
{
    private readonly ScanWorkflowCoordinator _logic = new();

    private HttpClient _httpClient
    {
        get => _logic.State.HttpClient;
        set => _logic.State.HttpClient = value;
    }

    private AsyncLocal<AuthProfile?> _activeAuthProfile => _logic.State.ActiveAuthProfile;
    private AsyncLocal<string?> _activeStandardTestKey => _logic.State.ActiveStandardTestKey;
    private AsyncLocal<bool> _strictSingleTargetMode => _logic.State.StrictSingleTargetMode;
    private AsyncLocal<Uri?> _strictSingleBaseUri => _logic.State.StrictSingleBaseUri;
    private AsyncLocal<AuditCaptureContext?> _auditCaptureContext => _logic.State.AuditCaptureContext;
    private Dictionary<string, OpenApiProbeContext> _openApiProbeContextCache => _logic.State.OpenApiProbeContextCache;

    private string _lastOpenApiInputRaw
    {
        get => _logic.State.LastOpenApiInputRaw;
        set => _logic.State.LastOpenApiInputRaw = value;
    }

    public MainPage()
    {
        _logic.State.HttpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(20) };
    }

    public async Task<string> ExecuteWithStandardContextAsync(string testKey, Uri target, Func<Uri, Task<string>> test)
    {
        var previous = _activeStandardTestKey.Value;
        _activeStandardTestKey.Value = testKey;
        try
        {
            return await test(target);
        }
        finally
        {
            _activeStandardTestKey.Value = previous;
        }
    }

    private RunScopeMode GetRunScopeMode()
    {
        return ScanOptionUtilities.GetRunScopeMode(
            Environment.GetEnvironmentVariable("API_TESTER_RUN_SCOPE"),
            0,
            null);
    }

    private bool IsOpenApiRouteScopeSelected() => GetRunScopeMode() == RunScopeMode.OpenApiRoutes;

    private bool IsSpiderRouteScopeSelected() => GetRunScopeMode() == RunScopeMode.SpiderRoutes;

    private bool IsTypeAwareModeEnabled()
    {
        return ScanOptionUtilities.IsTypeAwareModeEnabled(
            Environment.GetEnvironmentVariable("API_TESTER_TYPE_HANDLING"),
            Environment.GetEnvironmentVariable("API_TESTER_TYPE_AWARE"),
            null);
    }

    private int GetEffectiveRequestDelayMs()
    {
        return ScanOptionUtilities.GetEffectiveRequestDelayMs(
            null,
            Environment.GetEnvironmentVariable("API_TESTER_REQUEST_DELAY_MS"),
            true,
            Environment.GetEnvironmentVariable("API_TESTER_HEADLESS_REQUEST_DELAY_MS"));
    }

    private bool IsManualPayloadModeEnabled()
    {
        return ScanOptionUtilities.IsManualPayloadModeEnabled(
            false,
            RunReportUtilities.IsTruthyEnvironment("API_TESTER_MANUAL_PAYLOAD_MODE"));
    }

    private string GetScanDepthProfile() => LegacyTestHarnessUtilities.GetScanDepthProfile();

    private T[] LimitByScanDepth<T>(T[] items, int fastCount, int balancedCount)
    {
        return LegacyTestHarnessUtilities.LimitByScanDepth(items, GetScanDepthProfile(), fastCount, balancedCount);
    }

    private void AddVerbosePayloadDetails(List<string> findings, IEnumerable<string> payloads, IEnumerable<string> queryFields, IEnumerable<string>? bodyFields = null)
    {
        // Intentionally disabled for headless host.
    }

    private string[] GetManualPayloadsOrDefault(IEnumerable<string> defaults)
        => GetManualPayloadsOrDefault(defaults, ManualPayloadCategory.Generic);

    private string[] GetManualPayloadsOrDefault(IEnumerable<string> defaults, ManualPayloadCategory category)
    {
        var manual = ManualPayloadUtilities.ParseManualPayloads(
            IsManualPayloadModeEnabled(),
            null,
            Environment.GetEnvironmentVariable("API_TESTER_MANUAL_PAYLOADS"));
        var filtered = ManualPayloadUtilities.FilterManualPayloads(manual, category);
        return ManualPayloadUtilities.MergePayloads(defaults, filtered, GetSchemeVariantPreference());
    }

    private string[] GetManualPayloadDirectRequestUrls()
    {
        var manual = ManualPayloadUtilities.ParseManualPayloads(
            IsManualPayloadModeEnabled(),
            null,
            Environment.GetEnvironmentVariable("API_TESTER_MANUAL_PAYLOADS"));
        return ManualPayloadUtilities.ExtractDirectRequestUrls(manual, GetSchemeVariantPreference());
    }

    private string GetSchemeVariantPreference()
    {
        var target = Environment.GetEnvironmentVariable("API_TESTER_TARGET_URL")
                     ?? Environment.GetEnvironmentVariable("API_TESTER_URL");
        if (Uri.TryCreate(target, UriKind.Absolute, out var parsedTarget))
        {
            return parsedTarget.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                ? "HTTPS"
                : parsedTarget.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                    ? "HTTP"
                    : "Both";
        }

        var openApiInput = GetOpenApiInputRaw();
        if (Uri.TryCreate(openApiInput, UriKind.Absolute, out var openApiUri))
        {
            return openApiUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase)
                ? "HTTPS"
                : openApiUri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase)
                    ? "HTTP"
                    : "Both";
        }

        return Environment.GetEnvironmentVariable("API_TESTER_SCHEME_VARIANTS") ?? "Both";
    }

    private string GetOpenApiInputRaw()
    {
        return LegacyTestHarnessUtilities.ResolveOpenApiInputRaw(
            null,
            Environment.GetEnvironmentVariable("API_TESTER_OPENAPI_INPUT"));
    }

    private async Task<OpenApiSnapshot?> TryFetchOpenApiSnapshotAsync(Uri baseUri) =>
        await OpenApiSnapshotUtilities.TryFetchOpenApiSnapshotAsync(baseUri, GetOpenApiInputRaw(), SafeMetadataSendAsync);

    private async Task<IReadOnlyList<ApiEndpointDescriptor>?> TryFetchEndpointMetadataAsync(Uri baseUri)
    {
        var endpointUri = new Uri(baseUri, "/_apitester/endpoints");
        var response = await SafeMetadataSendAsync(() => new HttpRequestMessage(HttpMethod.Get, endpointUri));
        if (response is null || !response.IsSuccessStatusCode)
        {
            return null;
        }

        var raw = await ReadBodyAsync(response);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        try
        {
            var parsed = System.Text.Json.JsonSerializer.Deserialize<List<ApiEndpointDescriptor>>(
                raw,
                new System.Text.Json.JsonSerializerOptions { PropertyNameCaseInsensitive = true });
            return parsed;
        }
        catch
        {
            return null;
        }
    }

    private async Task<OpenApiProbeContext> GetOpenApiProbeContextAsync(Uri baseUri)
    {
        var overrideRaw = GetOpenApiInputRaw();
        var resolution = await OpenApiProbeContextUtilities.ResolveAsync(
            baseUri,
            overrideRaw,
            IsOpenApiRouteScopeSelected(),
            IsSpiderRouteScopeSelected(),
            IsTypeAwareModeEnabled(),
            _openApiProbeContextCache,
            _lastOpenApiInputRaw,
            TryFetchOpenApiSnapshotAsync,
            TryFetchEndpointMetadataAsync);

        _lastOpenApiInputRaw = resolution.LastOpenApiInputRaw;
        return resolution.Context;
    }

    private async Task<HttpResponseMessage?> SafeSendAsync(Func<HttpRequestMessage> requestFactory)
    {
        return await RequestSendWorkflowUtilities.SafeSendAsync(
            requestFactory,
            GetEffectiveRequestDelayMs(),
            ApplySingleTargetRequestOverridesAsync,
            requestUri =>
            {
                var violation = IsStrictSingleScopeViolation(requestUri, out var message);
                return (violation, message);
            },
            _activeAuthProfile.Value,
            request => _httpClient.SendAsync(request),
            () => _auditCaptureContext.Value,
            () => _activeStandardTestKey.Value,
            GetManualPayloadHint);
    }

    private async Task<HttpResponseMessage?> SafeMetadataSendAsync(Func<HttpRequestMessage> requestFactory)
    {
        return await RequestSendWorkflowUtilities.SafeSendAsync(
            requestFactory,
            GetEffectiveRequestDelayMs(),
            _ => Task.CompletedTask,
            _ => (false, string.Empty),
            _activeAuthProfile.Value,
            request => _httpClient.SendAsync(request),
            () => _auditCaptureContext.Value,
            () => _activeStandardTestKey.Value,
            null);
    }

    private string? GetManualPayloadHint()
    {
        if (!RunReportUtilities.IsTruthyEnvironment("API_TESTER_MANUAL_PAYLOAD_OVERRIDE"))
        {
            return null;
        }

        if (!IsManualPayloadModeEnabled())
        {
            return null;
        }

        var raw = Environment.GetEnvironmentVariable("API_TESTER_MANUAL_PAYLOADS");
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        var lines = raw.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var line in lines)
        {
            if (line.StartsWith("override:", StringComparison.OrdinalIgnoreCase) ||
                line.StartsWith("route:", StringComparison.OrdinalIgnoreCase))
            {
                var value = line[(line.IndexOf(':') + 1)..].Trim();
                return string.IsNullOrWhiteSpace(value) ? null : value;
            }
        }

        return null;
    }

    private Task ApplySingleTargetRequestOverridesAsync(HttpRequestMessage request)
        => RequestOverrideWorkflowUtilities.ApplySingleTargetRequestOverridesAsync(
            request,
            GetRunScopeMode(),
            () => TryGetConfiguredTargetUriForOverrides(out var configured) ? configured : null,
            TryGetAutomaticSingleTargetOperationProfileAsync,
            GetSelectedPayloadLocation(),
            GetSelectedOperationOverride(),
            ShouldApplyManualSingleTargetPayloadOverrides(),
            IsSameOrigin,
            RequestContractPipeline.PathsMatchForScope);

    private Task<OpenApiOperationProfile?> TryGetAutomaticSingleTargetOperationProfileAsync(Uri configuredTarget)
        => RequestOverrideWorkflowUtilities.TryGetAutomaticSingleTargetOperationProfileAsync(
            configuredTarget,
            IsTypeAwareModeEnabled(),
            GetOpenApiInputRaw(),
            IsOpenApiRouteScopeSelected(),
            IsSpiderRouteScopeSelected(),
            GetOpenApiProbeContextAsync,
            IsSameOrigin,
            RequestContractPipeline.PathsMatchForScope);

    private bool ShouldApplyManualSingleTargetPayloadOverrides()
        => ScanOptionUtilities.ShouldApplyManualSingleTargetPayloadOverrides(
            IsTypeAwareModeEnabled(),
            GetOpenApiInputRaw(),
            IsOpenApiRouteScopeSelected());

    private bool TryGetConfiguredTargetUriForOverrides(out Uri uri)
        => ScanOptionUtilities.TryResolveConfiguredTargetUriForOverrides(
            null,
            Environment.GetEnvironmentVariable("API_TESTER_TARGET_URL"),
            Environment.GetEnvironmentVariable("API_TESTER_URL"),
            out uri);

    private HttpMethod? GetSelectedOperationOverride()
        => ScanOptionUtilities.ResolveOperationOverride(Environment.GetEnvironmentVariable("API_TESTER_METHOD"));

    private PayloadLocation GetSelectedPayloadLocation() =>
        ScanOptionUtilities.ResolvePayloadLocation(Environment.GetEnvironmentVariable("API_TESTER_PAYLOAD_LOCATION"));

    private bool IsStrictSingleScopeViolation(Uri? requestUri, out string message)
        => RequestExecutionUtilities.IsStrictSingleScopeViolation(
            _strictSingleTargetMode.Value,
            _strictSingleBaseUri.Value,
            requestUri,
            RequestContractPipeline.PathsMatchForScope,
            out message);

    private ScanOptions BuildCoreScanOptions(Uri target)
    {
        var selectedMethod = GetSelectedOperationOverride();
        return new ScanOptions(
            target,
            "single",
            "txt",
            "all",
            "(all)",
            GetOpenApiInputRaw(),
            StreamLogs: false,
            MethodOverride: selectedMethod?.Method ?? "auto",
            PayloadLocation: GetSelectedPayloadLocation().ToString().ToLowerInvariant(),
            HttpTrace: false);
    }

    private Task<string> RunSharedSecurityHeadersSectionAsync(Uri baseUri) => _logic.RunSecurityHeadersSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedCorsSectionAsync(Uri baseUri) => _logic.RunCorsSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedHttpMethodsSectionAsync(Uri baseUri) => _logic.RunHttpMethodsSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedSqlInjectionSectionAsync(Uri baseUri) => _logic.RunSqlInjectionSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedXssSectionAsync(Uri baseUri) => _logic.RunXssSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedSsrfSectionAsync(Uri baseUri) => _logic.RunSsrfSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedRateLimitSectionAsync(Uri baseUri) => _logic.RunRateLimitSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedInformationDisclosureSectionAsync(Uri baseUri) => _logic.RunInformationDisclosureSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedTransportSecuritySectionAsync(Uri baseUri) => _logic.RunTransportSecuritySectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedErrorHandlingLeakageSectionAsync(Uri baseUri) => _logic.RunErrorHandlingLeakageSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedAuthAndAccessControlSectionAsync(Uri baseUri, string? _ = null) => _logic.RunAuthAndAccessControlSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedBrokenAuthenticationSectionAsync(Uri baseUri) => _logic.RunBrokenAuthenticationSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedBrokenFunctionLevelAuthorizationSectionAsync(Uri baseUri) => _logic.RunBrokenFunctionLevelAuthorizationSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedBrokenObjectPropertyLevelAuthorizationSectionAsync(Uri baseUri) => _logic.RunBrokenObjectPropertyLevelAuthorizationSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedCrossTenantDataLeakageSectionAsync(Uri baseUri) => _logic.RunCrossTenantDataLeakageSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedBolaSectionAsync(Uri baseUri) => _logic.RunBolaSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedCookieSecurityFlagsSectionAsync(Uri baseUri) => _logic.RunCookieSecurityFlagsSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedContentTypeValidationSectionAsync(Uri baseUri) => _logic.RunContentTypeValidationSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedImproperInventoryManagementSectionAsync(Uri baseUri) => _logic.RunImproperInventoryManagementSectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private Task<string> RunSharedIdempotencyReplaySectionAsync(Uri baseUri) => _logic.RunIdempotencyReplaySectionAsync(baseUri, BuildCoreScanOptions, ResultPresentation.FormatSharedCoreSection);

    private static Task<string> ReadBodyAsync(HttpResponseMessage? response) => HttpEvidenceUtilities.ReadBodyAsync(response);

    private static bool ContainsAny(string input, params string[] markers) => TestResultUtilities.ContainsAny(input, markers);

    private static string TryGetHeader(HttpResponseMessage response, string headerName) => TestResultUtilities.TryGetHeader(response, headerName);

    private static bool HasHeader(HttpResponseMessage response, string headerName) => TestResultUtilities.HasHeader(response, headerName);

    private static Uri AppendQuery(Uri baseUri, IDictionary<string, string> additions) => TestResultUtilities.AppendQuery(baseUri, additions);

    private static Uri AppendPathSegment(Uri baseUri, string segment) => UriMutationUtilities.AppendPathSegment(baseUri, segment);

    private static bool IsRoutePlaceholderSegment(string segment) => UriMutationUtilities.IsRoutePlaceholderSegment(segment);

    private static Dictionary<string, string> ParseQuery(string query) => UriMutationUtilities.ParseQuery(query);

    private static string BuildQuery(Dictionary<string, string> values) => UriMutationUtilities.BuildQuery(values);

    private static string FormatSection(string sectionName, Uri uri, IEnumerable<string> findings) => TestResultUtilities.FormatSection(sectionName, uri, findings);

    private static bool IsSameOrigin(Uri baseUri, Uri candidate) => DiscoveryUtilities.IsSameOrigin(baseUri, candidate);

    private static string FormatStatus(HttpResponseMessage? response) => DiscoveryUtilities.FormatStatus(response);

    private static string BuildUnsignedJwt(Dictionary<string, object> payload) => DiscoveryUtilities.BuildUnsignedJwt(payload);

    private static string BuildUnsignedJwtWithCustomHeader(Dictionary<string, object> payload, Dictionary<string, object> header) =>
        DiscoveryUtilities.BuildUnsignedJwtWithCustomHeader(payload, header);

    private static string Base64UrlEncode(string value) => DiscoveryUtilities.Base64UrlEncode(value);
}
