using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ApiTester.Core;

public static class DiscoveryUtilities
{
    public static string BuildRunDisplaySummary(string title, string timestampUtc, string body)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"=== {title} ===");
        sb.AppendLine($"Timestamp (UTC): {timestampUtc}");
        sb.AppendLine();

        var lines = (body ?? string.Empty).Replace("\r\n", "\n").Split('\n');
        var suppressExecutionBlock = false;
        foreach (var rawLine in lines)
        {
            var line = rawLine ?? string.Empty;
            var trimmed = line.TrimStart();

            if (trimmed.StartsWith("[Execution]", StringComparison.Ordinal))
            {
                suppressExecutionBlock = true;
                continue;
            }

            if (suppressExecutionBlock)
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    suppressExecutionBlock = false;
                }

                continue;
            }

            if (trimmed.StartsWith("- Payload '", StringComparison.Ordinal) ||
                trimmed.StartsWith("Payload '", StringComparison.Ordinal))
            {
                continue;
            }

            sb.AppendLine(line);
        }

        return sb.ToString().TrimEnd();
    }

    public static void AddEndpointCandidates(IEnumerable<Uri> baseUris, string normalizedPath, HashSet<string> endpoints)
    {
        foreach (var baseCandidate in baseUris)
        {
            try
            {
                endpoints.Add(new Uri(baseCandidate, normalizedPath).ToString());
            }
            catch
            {
                // Ignore malformed endpoint candidates.
            }
        }
    }

    public static List<Uri> ResolveOpenApiServerBases(JsonElement node, Uri fallbackBaseUri, Uri sourceUri)
    {
        var bases = new List<Uri>();
        if (!node.TryGetProperty("servers", out var servers) || servers.ValueKind != JsonValueKind.Array)
        {
            bases.Add(fallbackBaseUri);
            return bases;
        }

        foreach (var server in servers.EnumerateArray())
        {
            if (server.ValueKind != JsonValueKind.Object ||
                !server.TryGetProperty("url", out var urlEl) ||
                urlEl.ValueKind != JsonValueKind.String)
            {
                continue;
            }

            var rawUrl = urlEl.GetString();
            if (string.IsNullOrWhiteSpace(rawUrl))
            {
                continue;
            }

            var expanded = ExpandOpenApiServerUrl(rawUrl, server);
            if (Uri.TryCreate(expanded, UriKind.Absolute, out var absolute) && absolute is not null)
            {
                bases.Add(absolute);
                continue;
            }

            if (Uri.TryCreate(sourceUri, expanded, out var relativeToDoc) && relativeToDoc is not null)
            {
                bases.Add(relativeToDoc);
                continue;
            }

            if (Uri.TryCreate(fallbackBaseUri, expanded, out var relativeToBase) && relativeToBase is not null)
            {
                bases.Add(relativeToBase);
            }
        }

        if (bases.Count == 0)
        {
            bases.Add(fallbackBaseUri);
        }

        return bases
            .DistinctBy(u => u.ToString())
            .ToList();
    }

    public static string ExpandOpenApiServerUrl(string template, JsonElement server)
    {
        if (!server.TryGetProperty("variables", out var variables) || variables.ValueKind != JsonValueKind.Object)
        {
            return template;
        }

        return Regex.Replace(template, "\\{(?<name>[^}]+)\\}", match =>
        {
            var name = match.Groups["name"].Value;
            if (!variables.TryGetProperty(name, out var variableDef) || variableDef.ValueKind != JsonValueKind.Object)
            {
                return match.Value;
            }

            if (variableDef.TryGetProperty("default", out var def) && def.ValueKind == JsonValueKind.String)
            {
                return def.GetString() ?? match.Value;
            }

            return match.Value;
        });
    }

    public static bool IsHttpVerb(string name) =>
        name.Equals("get", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("post", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("put", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("patch", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("delete", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("options", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("head", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("trace", StringComparison.OrdinalIgnoreCase);

    public static bool TryResolveSameOriginUri(Uri current, string raw, out Uri resolved)
    {
        resolved = null!;
        if (string.IsNullOrWhiteSpace(raw) ||
            raw.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase) ||
            raw.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase) ||
            raw.StartsWith("tel:", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (!Uri.TryCreate(current, raw, out var parsed) || parsed is null)
        {
            return false;
        }

        if (!IsSameOrigin(current, parsed))
        {
            return false;
        }

        if (parsed.Scheme != Uri.UriSchemeHttp && parsed.Scheme != Uri.UriSchemeHttps)
        {
            return false;
        }

        resolved = parsed;
        return true;
    }

    public static bool IsSameOrigin(Uri baseUri, Uri candidate) =>
        string.Equals(baseUri.Scheme, candidate.Scheme, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(baseUri.Host, candidate.Host, StringComparison.OrdinalIgnoreCase) &&
        baseUri.Port == candidate.Port;

    public static string NormalizeEndpointKey(Uri uri)
    {
        var builder = new UriBuilder(uri)
        {
            Fragment = string.Empty
        };

        return builder.Uri.ToString();
    }

    public static string FormatStatus(HttpResponseMessage? response)
    {
        if (response is null)
        {
            return "Error: No response";
        }

        var code = (int)response.StatusCode;
        return code >= 400 ? $"Error: {code} {response.StatusCode}" : $"{code} {response.StatusCode}";
    }

    public static List<string> BuildSpiderCoverageHints(IEnumerable<string> endpoints)
    {
        var endpointList = endpoints.Select(e => e.ToLowerInvariant()).ToList();
        var hints = new List<string>();

        void AddHintIf(string marker, string description, params string[] tests)
        {
            if (endpointList.Any(e => e.Contains(marker, StringComparison.Ordinal)))
            {
                hints.Add($"{description}: {string.Join(", ", tests)}");
            }
        }

        AddHintIf("graphql", "GraphQL surface detected", "RunGraphQlIntrospectionTestsAsync", "RunGraphQlDepthBombTestsAsync", "RunGraphQlComplexityTestsAsync");
        AddHintIf("grpc", "gRPC-like route detected", "RunGrpcReflectionTestsAsync", "RunGrpcMetadataAbuseTestsAsync", "RunGrpcProtobufFuzzingTestsAsync");
        AddHintIf("swagger", "Swagger/OpenAPI docs detected", "RunOpenApiSchemaMismatchTestsAsync", "RunApiInventoryManagementTestsAsync");
        AddHintIf("openapi", "OpenAPI endpoint detected", "RunOpenApiSchemaMismatchTestsAsync", "RunApiVersionDiscoveryTestsAsync");
        AddHintIf("oauth", "OAuth route detected", "RunOAuthRedirectUriValidationTestsAsync", "RunOAuthPkceEnforcementTestsAsync", "RunOAuthScopeEscalationTestsAsync");
        AddHintIf("openid", "OIDC discovery/auth route detected", "RunOidcDiscoveryHijackingTestsAsync", "RunOidcIssuerValidationTestsAsync", "RunOidcAudienceValidationTestsAsync");
        AddHintIf("token", "Token endpoint hint detected", "RunJwtMalformedTokenTestsAsync", "RunTokenParserFuzzTestsAsync", "RunTokenInQueryTestsAsync");
        AddHintIf("upload", "Upload route hint detected", "RunFileUploadValidationTestsAsync");
        AddHintIf("admin", "Admin route hint detected", "RunPrivilegeEscalationTestsAsync", "RunAuthAndAccessControlTestsAsync", "RunHeaderOverrideTestsAsync");
        AddHintIf("internal", "Internal route hint detected", "RunMITREATTampCKFrameworkSsrfTestsAsync", "RunAdvancedSsrfEncodingTestsAsync", "RunEgressFilteringTestsAsync");
        AddHintIf("ws", "WebSocket route hint detected", "RunWebSocketAuthTestsAsync", "RunWebSocketMessageInjectionTestsAsync", "RunWebSocketFragmentationTestsAsync");
        AddHintIf("docker", "Container API route hint detected", "RunDockerContainerExposureTestsAsync", "RunApiInventoryManagementTestsAsync");
        AddHintIf("containers", "Container endpoint hint detected", "RunDockerContainerExposureTestsAsync");

        return hints;
    }

    public static string BuildUnsignedJwt(Dictionary<string, object> payload)
    {
        var headerJson = "{\"alg\":\"none\",\"typ\":\"JWT\"}";
        var payloadJson = JsonSerializer.Serialize(payload ?? new Dictionary<string, object>());
        return $"{Base64UrlEncode(headerJson)}.{Base64UrlEncode(payloadJson)}.";
    }

    public static string BuildUnsignedJwtWithCustomHeader(Dictionary<string, object> payload, Dictionary<string, object> header)
    {
        var headerJson = JsonSerializer.Serialize(header ?? new Dictionary<string, object>());
        var payloadJson = JsonSerializer.Serialize(payload ?? new Dictionary<string, object>());
        return $"{Base64UrlEncode(headerJson)}.{Base64UrlEncode(payloadJson)}.";
    }

    public static string Base64UrlEncode(string value)
    {
        var bytes = Encoding.UTF8.GetBytes(value ?? string.Empty);
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }
}
