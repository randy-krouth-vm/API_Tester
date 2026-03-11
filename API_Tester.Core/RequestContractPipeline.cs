using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ApiTester.Shared;

public enum PayloadLocation
{
    Query,
    Path,
    Body,
    Header,
    Cookie
}

public sealed record OperationContract(
    Uri Endpoint,
    IReadOnlyCollection<string> AllowedMethods,
    IReadOnlyCollection<string> QueryParameterNames,
    IReadOnlyCollection<string> BodyPropertyNames,
    IReadOnlyCollection<string> PathParameterNames,
    IReadOnlyDictionary<string, string>? QueryParameterTypeHints = null,
    IReadOnlyDictionary<string, string>? BodyPropertyTypeHints = null,
    IReadOnlyDictionary<string, string>? PathParameterTypeHints = null,
    PayloadLocation? PreferredPayloadLocation = null,
    string? BodyTemplateJson = null);

public sealed record RequestPipelineOptions(
    Uri ConfiguredTarget,
    PayloadLocation PayloadLocation,
    HttpMethod? MethodOverride,
    bool EnablePayloadRelocation,
    bool UseAutomaticContract,
    OperationContract? AutomaticContract);

public static class RequestContractPipeline
{
    public static void NormalizeRoutePlaceholders(HttpRequestMessage request)
    {
        if (request?.RequestUri is null)
        {
            return;
        }

        var payloadHint = TryGetPayloadHeaderValue(request);
        if (TryApplyFullRoutePayload(request, payloadHint))
        {
            return;
        }

        if (TryApplyQueryPayload(request, payloadHint))
        {
            return;
        }

        if (ContainsRoutePlaceholders(request.RequestUri))
        {
            request.RequestUri = ReplaceRoutePlaceholders(request.RequestUri, payloadHint);
        }
    }

    public static void Apply(HttpRequestMessage request, RequestPipelineOptions options)
    {
        if (request.RequestUri is null ||
            !IsSameOrigin(options.ConfiguredTarget, request.RequestUri) ||
            !PathsMatchForScope(request.RequestUri, options.ConfiguredTarget))
        {
            return;
        }

        if (options.MethodOverride is not null)
        {
            request.Method = options.MethodOverride;
        }

        if (options.UseAutomaticContract &&
            options.MethodOverride is null &&
            options.AutomaticContract is not null)
        {
            ApplyAutomaticContract(request, options.ConfiguredTarget, options.AutomaticContract);
            return;
        }

        if (!options.EnablePayloadRelocation)
        {
            return;
        }

        var payload = CapturePayload(request, options.ConfiguredTarget);
        if (payload is null)
        {
            return;
        }

        switch (options.PayloadLocation)
        {
            case PayloadLocation.Query:
                request.RequestUri = ApplyQueryOverride(options.ConfiguredTarget, payload.Name, payload.Value);
                request.Content = null;
                RemoveNonAuthPayloadHeaders(request);
                break;
            case PayloadLocation.Path:
                request.RequestUri = ApplyPathOverride(options.ConfiguredTarget, payload.Value);
                request.Content = null;
                RemoveNonAuthPayloadHeaders(request);
                break;
            case PayloadLocation.Body:
                if (SupportsRequestBody(request.Method))
                {
                    request.RequestUri = StripQuery(options.ConfiguredTarget);
                    request.Content = BuildBodyOverrideContent(BuildPayloadBody(payload));
                    RemoveNonAuthPayloadHeaders(request);
                }
                break;
            case PayloadLocation.Header:
                request.RequestUri = StripQuery(options.ConfiguredTarget);
                request.Content = null;
                RemoveNonAuthPayloadHeaders(request);
                ApplyHeaderOverride(request, payload.Name, payload.Value);
                break;
            case PayloadLocation.Cookie:
                request.RequestUri = StripQuery(options.ConfiguredTarget);
                request.Content = null;
                RemoveNonAuthPayloadHeaders(request);
                ApplyCookieOverride(request, payload.Name, payload.Value);
                break;
        }
    }

    public static bool PathsMatchForScope(Uri requestUri, Uri configuredUri)
    {
        var requestPath = NormalizeComparablePath(requestUri);
        var configuredPath = NormalizeComparablePath(configuredUri);
        if (requestPath.Equals(configuredPath, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        var template = Uri.UnescapeDataString(configuredPath);
        if (!template.Contains('{') || !template.Contains('}'))
        {
            return false;
        }

        var pattern = "^" + Regex.Escape(template).Replace("\\{", "{").Replace("\\}", "}") + "$";
        pattern = Regex.Replace(pattern, "\\{[^}]+\\}", "[^/]+");
        return Regex.IsMatch(Uri.UnescapeDataString(requestPath), pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    }

    public static bool IsRoutePlaceholderSegment(string segment)
    {
        return TryGetRoutePlaceholderName(segment, out _);
    }

    public static string NormalizeComparablePath(Uri uri)
    {
        var path = uri.AbsolutePath.Trim();
        if (string.IsNullOrEmpty(path))
        {
            return "/";
        }

        path = path.TrimEnd('/');
        return string.IsNullOrEmpty(path) ? "/" : path;
    }

    private static bool ContainsRoutePlaceholders(Uri uri)
    {
        var path = uri.AbsolutePath;
        if (path.Contains('{') && path.Contains('}'))
        {
            return true;
        }

        var decoded = Uri.UnescapeDataString(path);
        return decoded.Contains('{') && decoded.Contains('}');
    }

    private static Uri ReplaceRoutePlaceholders(Uri uri, string? payloadHint)
    {
        var decodedPath = Uri.UnescapeDataString(uri.AbsolutePath);
        var routePayload = ResolveRoutePayloadHint(uri, payloadHint);
        var updated = Regex.Replace(decodedPath, "\\{(?<name>[^}/]+)\\}", match =>
        {
            var rawToken = match.Groups["name"].Value;
            var name = NormalizeRoutePlaceholderName(rawToken);
            if (!string.IsNullOrWhiteSpace(routePayload))
            {
                return BuildRoutePayloadSegment(CoerceRoutePayloadValue(routePayload, rawToken, name, null));
            }
            return name switch
            {
                "id" or "userid" or "orderid" or "productid" => "1",
                "username" or "user" => "apitester",
                "runaat" or "runat" or "date" or "time" => "2026-03-01T00-00-00Z",
                "a" => "1",
                "b" => "2",
                "path" or "filepath" => "sample.txt",
                _ when name.Contains("id", StringComparison.Ordinal) => "1",
                _ when name.Contains("user", StringComparison.Ordinal) => "apitester",
                _ => "test"
            };
        });

        var builder = new UriBuilder(uri) { Path = updated };
        return builder.Uri;
    }

    private static string? ResolveRoutePayloadHint(Uri uri, string? payloadHint)
    {
        if (!string.IsNullOrWhiteSpace(payloadHint))
        {
            var trimmed = payloadHint.Trim();
            if (trimmed.StartsWith("?", StringComparison.Ordinal) || trimmed.Contains('='))
            {
                var parsed = ParseQuery(trimmed.StartsWith("?", StringComparison.Ordinal) ? trimmed : "?" + trimmed);
                var first = parsed.FirstOrDefault(kvp => !string.IsNullOrWhiteSpace(kvp.Value));
                if (!string.IsNullOrWhiteSpace(first.Value))
                {
                    return first.Value;
                }
            }

            return trimmed;
        }

        if (!string.IsNullOrWhiteSpace(uri.Query))
        {
            var parsed = ParseQuery(uri.Query);
            var first = parsed.FirstOrDefault(kvp => !string.IsNullOrWhiteSpace(kvp.Value));
            if (!string.IsNullOrWhiteSpace(first.Value))
            {
                return first.Value;
            }
        }

        return null;
    }

    private static string BuildRoutePayloadSegment(string payload)
    {
        var trimmed = payload.Trim();
        if (trimmed.Length == 0)
        {
            return "test";
        }

        return Uri.EscapeDataString(trimmed);
    }

    private static string? TryGetPayloadHeaderValue(HttpRequestMessage request)
    {
        if (request.Headers.TryGetValues("X-ApiTester-Payload", out var values))
        {
            var value = values.FirstOrDefault();
            return string.IsNullOrWhiteSpace(value) ? null : value;
        }

        return null;
    }

    private static bool TryApplyFullRoutePayload(HttpRequestMessage request, string? payloadHint)
    {
        if (string.IsNullOrWhiteSpace(payloadHint) || request.RequestUri is null)
        {
            return false;
        }

        var trimmed = payloadHint.Trim();
        if (Uri.TryCreate(trimmed, UriKind.Absolute, out var absolute))
        {
            request.RequestUri = absolute;
            return true;
        }

        if (trimmed.StartsWith("/", StringComparison.Ordinal))
        {
            request.RequestUri = new Uri(request.RequestUri, trimmed);
            return true;
        }

        return false;
    }

    private static bool TryApplyQueryPayload(HttpRequestMessage request, string? payloadHint)
    {
        if (string.IsNullOrWhiteSpace(payloadHint) || request.RequestUri is null)
        {
            return false;
        }

        var trimmed = payloadHint.Trim();
        if (trimmed.StartsWith("?", StringComparison.Ordinal))
        {
            request.RequestUri = ApplyQueryOverride(request.RequestUri, trimmed, null);
            return true;
        }

        if (IsLikelyKeyValueQuery(trimmed))
        {
            request.RequestUri = ApplyQueryOverride(request.RequestUri, trimmed, null);
            return true;
        }

        if (ContainsQueryLikePayload(trimmed))
        {
            request.RequestUri = ApplyQueryOverride(request.RequestUri, "q", trimmed);
            return true;
        }

        return false;
    }

    private static bool IsLikelyKeyValueQuery(string value)
    {
        var idx = value.IndexOf('=');
        if (idx <= 0)
        {
            return false;
        }

        var key = value[..idx].Trim();
        if (string.IsNullOrWhiteSpace(key) || key.Any(char.IsWhiteSpace))
        {
            return false;
        }

        return key.All(c => char.IsLetterOrDigit(c) || c is '_' or '-' or '.');
    }

    private static bool ContainsQueryLikePayload(string value)
    {
        if (value.Contains('='))
        {
            return true;
        }

        if (value.IndexOf(" or ", StringComparison.OrdinalIgnoreCase) >= 0 ||
            value.Contains("'", StringComparison.Ordinal) ||
            value.Contains("\"", StringComparison.Ordinal))
        {
            return true;
        }

        return false;
    }

    private static bool IsSimpleRouteValue(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        if (trimmed.Length > 64 || trimmed.Contains('/') || trimmed.Contains('?') || trimmed.Contains('&'))
        {
            return false;
        }

        return Regex.IsMatch(trimmed, "^[A-Za-z0-9._-]+$");
    }

    public static Dictionary<string, string> ParseQuery(string query)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(query))
        {
            return values;
        }

        var trimmed = query.TrimStart('?');
        foreach (var pair in trimmed.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            var key = Uri.UnescapeDataString(parts[0]);
            var value = parts.Length > 1 ? Uri.UnescapeDataString(parts[1]) : string.Empty;
            values[key] = value;
        }

        return values;
    }

    public static string BuildQuery(IDictionary<string, string> values)
    {
        return string.Join("&", values
            .Where(kvp => !string.IsNullOrWhiteSpace(kvp.Key))
            .Select(kvp => $"{Uri.EscapeDataString(kvp.Key)}={Uri.EscapeDataString(kvp.Value ?? string.Empty)}"));
    }

    private static void ApplyAutomaticContract(HttpRequestMessage request, Uri configuredTarget, OperationContract contract)
    {
        if (request.Method == HttpMethod.Trace)
        {
            return;
        }

        var allowedMethods = contract.AllowedMethods.Count == 0
            ? new HashSet<string>(StringComparer.OrdinalIgnoreCase) { request.Method.Method }
            : new HashSet<string>(contract.AllowedMethods, StringComparer.OrdinalIgnoreCase);
        var preferredMethod = ResolvePreferredMethod(allowedMethods);
        var preferredLocation = ResolveAutomaticPayloadLocation(contract, preferredMethod);
        var payload = CaptureAutomaticPayload(request, configuredTarget);

        var currentAllowed = allowedMethods.Contains(request.Method.Method);
        var pathMatchesConfigured = NormalizeComparablePath(request.RequestUri!).Equals(NormalizeComparablePath(configuredTarget), StringComparison.OrdinalIgnoreCase);
        var hasBody = request.Content is not null;
        var payloadAlreadyMatches = PayloadAlreadyMatchesPreferredLocation(request, preferredLocation);
        var bodyTypeMatches = preferredLocation != PayloadLocation.Body || HasJsonContentType(request.Content);
        if (currentAllowed &&
            pathMatchesConfigured &&
            (!hasBody || SupportsRequestBody(request.Method)) &&
            payloadAlreadyMatches &&
            bodyTypeMatches)
        {
            return;
        }

        request.Method = preferredMethod;

        if (preferredLocation == PayloadLocation.Body && SupportsRequestBody(preferredMethod))
        {
            request.RequestUri = StripQuery(configuredTarget);
            request.Content = BuildBodyOverrideContent(BuildAutomaticPayloadBody(contract, payload), forceJson: true);
            RemoveNonAuthPayloadHeaders(request);
            return;
        }

        if (payload is null)
        {
            request.RequestUri = StripQuery(configuredTarget);
            request.Content = null;
            RemoveNonAuthPayloadHeaders(request);
            return;
        }

        if (preferredLocation == PayloadLocation.Path)
        {
            request.RequestUri = ApplyPathOverride(configuredTarget, payload.Value, contract.PathParameterTypeHints);
            request.Content = null;
            RemoveNonAuthPayloadHeaders(request);
            return;
        }

        if (preferredLocation == PayloadLocation.Header)
        {
            request.RequestUri = StripQuery(configuredTarget);
            request.Content = null;
            RemoveNonAuthPayloadHeaders(request);
            ApplyHeaderOverride(request, payload.Name, payload.Value);
            return;
        }

        if (preferredLocation == PayloadLocation.Cookie)
        {
            request.RequestUri = StripQuery(configuredTarget);
            request.Content = null;
            RemoveNonAuthPayloadHeaders(request);
            ApplyCookieOverride(request, payload.Name, payload.Value);
            return;
        }

        var queryField = contract.QueryParameterNames.FirstOrDefault();
        if (string.IsNullOrWhiteSpace(queryField))
        {
            queryField = !string.IsNullOrWhiteSpace(payload.Name) ? payload.Name : "id";
        }

        var queryValue = CoerceFieldPayloadValue(
            payload.Value,
            queryField,
            contract.QueryParameterTypeHints);
        request.RequestUri = ApplyQueryOverride(configuredTarget, queryField, queryValue);
        request.Content = null;
        RemoveNonAuthPayloadHeaders(request);
    }

    private static HttpMethod ResolvePreferredMethod(HashSet<string> allowedMethods)
    {
        if (allowedMethods.Contains("GET")) return HttpMethod.Get;
        if (allowedMethods.Contains("POST")) return HttpMethod.Post;
        if (allowedMethods.Contains("PUT")) return HttpMethod.Put;
        if (allowedMethods.Contains("PATCH")) return HttpMethod.Patch;
        if (allowedMethods.Contains("DELETE")) return HttpMethod.Delete;
        if (allowedMethods.Contains("HEAD")) return HttpMethod.Head;
        if (allowedMethods.Contains("OPTIONS")) return HttpMethod.Options;
        return HttpMethod.Get;
    }

    private static PayloadLocation ResolveAutomaticPayloadLocation(OperationContract contract, HttpMethod preferredMethod)
    {
        if (contract.PreferredPayloadLocation is not null)
        {
            return contract.PreferredPayloadLocation.Value;
        }

        if (contract.BodyPropertyNames.Count > 0 && SupportsRequestBody(preferredMethod))
        {
            return PayloadLocation.Body;
        }

        if (contract.QueryParameterNames.Count > 0)
        {
            return PayloadLocation.Query;
        }

        if (contract.PathParameterNames.Count > 0)
        {
            return PayloadLocation.Path;
        }

        return PayloadLocation.Query;
    }

    private static bool PayloadAlreadyMatchesPreferredLocation(HttpRequestMessage request, PayloadLocation preferredLocation)
    {
        var requestUri = request.RequestUri;
        if (requestUri is null)
        {
            return false;
        }

        return preferredLocation switch
        {
            PayloadLocation.Query => !string.IsNullOrWhiteSpace(requestUri.Query),
            PayloadLocation.Path => string.IsNullOrWhiteSpace(requestUri.Query) && request.Content is null,
            PayloadLocation.Body => request.Content is not null,
            PayloadLocation.Header => request.Headers.Any(h =>
                !h.Key.Equals("Authorization", StringComparison.OrdinalIgnoreCase) &&
                !h.Key.Equals("Cookie", StringComparison.OrdinalIgnoreCase)),
            PayloadLocation.Cookie => request.Headers.Contains("Cookie"),
            _ => false
        };
    }

    private static string BuildAutomaticPayloadBody(OperationContract contract, SingleTargetPayload? payload)
    {
        if (payload is null)
        {
            return contract.BodyTemplateJson ?? "{}";
        }

        if (payload.IsStructuredBody)
        {
            return payload.Value;
        }

        var field = contract.BodyPropertyNames.FirstOrDefault();
        if (string.IsNullOrWhiteSpace(field))
        {
            field = !string.IsNullOrWhiteSpace(payload.Name) ? payload.Name : "value";
        }

        var escapedValue = JsonSerializer.Serialize(
            ConvertPayloadForTypedField(payload.Value, field, contract.BodyPropertyTypeHints));
        var escapedName = JsonSerializer.Serialize(field);
        return $"{{{escapedName}:{escapedValue}}}";
    }

    private static SingleTargetPayload? CapturePayload(HttpRequestMessage request, Uri configuredTarget)
    {
        var requestUri = request.RequestUri;
        if (requestUri is null)
        {
            return null;
        }

        var query = ParseQuery(requestUri.Query);
        var firstQuery = query.FirstOrDefault(kvp => !string.IsNullOrWhiteSpace(kvp.Value));
        if (!string.IsNullOrWhiteSpace(firstQuery.Key))
        {
            return new SingleTargetPayload(firstQuery.Key, firstQuery.Value, false);
        }

        var requestPath = Uri.UnescapeDataString(NormalizeComparablePath(requestUri));
        var configuredPath = Uri.UnescapeDataString(NormalizeComparablePath(configuredTarget));
        if (!requestPath.Equals(configuredPath, StringComparison.OrdinalIgnoreCase))
        {
            var requestSegments = requestPath.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
            var configuredSegments = configuredPath.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
            for (var i = 0; i < Math.Min(requestSegments.Length, configuredSegments.Length); i++)
            {
                var configuredSegment = configuredSegments[i];
            if (IsRoutePlaceholderSegment(configuredSegment) &&
                !string.Equals(requestSegments[i], configuredSegment, StringComparison.OrdinalIgnoreCase))
            {
                var name = GetRoutePlaceholderName(configuredSegment);
                return new SingleTargetPayload(name, Uri.UnescapeDataString(requestSegments[i]), false);
            }
            }

            if (requestSegments.Length > 0)
            {
                return new SingleTargetPayload("id", Uri.UnescapeDataString(requestSegments[^1]), false);
            }
        }

        if (request.Content is not null)
        {
            var rawBody = request.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            if (!string.IsNullOrWhiteSpace(rawBody))
            {
                return new SingleTargetPayload("body", rawBody, LooksStructuredBody(rawBody));
            }
        }

        foreach (var header in request.Headers)
        {
            if (header.Key.Equals("Authorization", StringComparison.OrdinalIgnoreCase) ||
                header.Key.Equals("Cookie", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var value = string.Join(",", header.Value);
            if (!string.IsNullOrWhiteSpace(value))
            {
                return new SingleTargetPayload(header.Key, value, false);
            }
        }

        if (request.Headers.TryGetValues("Cookie", out var cookieValues))
        {
            var cookie = cookieValues.FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(cookie))
            {
                var firstCookie = cookie.Split(';', StringSplitOptions.RemoveEmptyEntries)
                    .Select(part => part.Split('=', 2))
                    .FirstOrDefault(parts => parts.Length == 2);
                if (firstCookie is not null)
                {
                    return new SingleTargetPayload(firstCookie[0].Trim(), firstCookie[1].Trim(), false);
                }
            }
        }

        return null;
    }

    private static SingleTargetPayload? CaptureAutomaticPayload(HttpRequestMessage request, Uri configuredTarget)
    {
        var requestUri = request.RequestUri;
        if (requestUri is null)
        {
            return null;
        }

        var query = ParseQuery(requestUri.Query);
        var firstQuery = query.FirstOrDefault(kvp => !string.IsNullOrWhiteSpace(kvp.Value));
        if (!string.IsNullOrWhiteSpace(firstQuery.Key))
        {
            return new SingleTargetPayload(firstQuery.Key, firstQuery.Value, false);
        }

        var requestPath = Uri.UnescapeDataString(NormalizeComparablePath(requestUri));
        var configuredPath = Uri.UnescapeDataString(NormalizeComparablePath(configuredTarget));
        if (!requestPath.Equals(configuredPath, StringComparison.OrdinalIgnoreCase))
        {
            var requestSegments = requestPath.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
            var configuredSegments = configuredPath.Trim('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
            for (var i = 0; i < Math.Min(requestSegments.Length, configuredSegments.Length); i++)
            {
                var configuredSegment = configuredSegments[i];
            if (IsRoutePlaceholderSegment(configuredSegment) &&
                !string.Equals(requestSegments[i], configuredSegment, StringComparison.OrdinalIgnoreCase))
            {
                var name = GetRoutePlaceholderName(configuredSegment);
                return new SingleTargetPayload(name, Uri.UnescapeDataString(requestSegments[i]), false);
            }
            }

            if (requestSegments.Length > 0)
            {
                return new SingleTargetPayload("id", Uri.UnescapeDataString(requestSegments[^1]), false);
            }
        }

        if (request.Content is not null)
        {
            var rawBody = request.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            if (!string.IsNullOrWhiteSpace(rawBody))
            {
                return new SingleTargetPayload("body", rawBody, LooksStructuredBody(rawBody));
            }
        }

        return null;
    }

    private static bool SupportsRequestBody(HttpMethod method) =>
        method == HttpMethod.Post || method == HttpMethod.Put || method == HttpMethod.Patch;

    private static Uri ApplyPathOverride(Uri requestUri, string payload, IReadOnlyDictionary<string, string>? pathParameterTypeHints = null)
    {
        var builder = new UriBuilder(requestUri);
        var path = builder.Path ?? "/";
        var trimmedPath = path.TrimEnd('/');
        var parts = trimmedPath.Split('/', StringSplitOptions.RemoveEmptyEntries).ToList();

        if (parts.Count == 0)
        {
            builder.Path = "/" + Uri.EscapeDataString(payload ?? string.Empty);
            return builder.Uri;
        }

        if (TryReplacePlaceholderSegments(parts, payload, pathParameterTypeHints, out var placeholderPath))
        {
            builder.Path = placeholderPath;
            return builder.Uri;
        }

        if (ShouldReplaceTerminalPathSegment(parts))
        {
            parts[^1] = Uri.EscapeDataString(payload ?? string.Empty);
            builder.Path = "/" + string.Join('/', parts);
            return builder.Uri;
        }

        builder.Path = $"{trimmedPath}/{Uri.EscapeDataString(payload ?? string.Empty)}";
        return builder.Uri;
    }

    private static bool TryReplacePlaceholderSegments(
        IReadOnlyList<string> parts,
        string payload,
        IReadOnlyDictionary<string, string>? pathParameterTypeHints,
        out string path)
    {
        path = string.Empty;
        var replaced = false;
        var updated = new List<string>(parts.Count);

        foreach (var part in parts)
        {
            if (TryGetRoutePlaceholderName(part, out var placeholderName))
            {
                var typeHint = ResolvePathTypeHint(part, placeholderName, pathParameterTypeHints);
                var value = CoerceRoutePayloadValue(payload, part, placeholderName, typeHint);
                updated.Add(Uri.EscapeDataString(value));
                replaced = true;
            }
            else
            {
                updated.Add(part);
            }
        }

        if (!replaced)
        {
            return false;
        }

        path = "/" + string.Join('/', updated);
        return true;
    }

    private static bool TryGetRoutePlaceholderName(string segment, out string name)
    {
        name = string.Empty;
        if (string.IsNullOrWhiteSpace(segment))
        {
            return false;
        }

        var decoded = Uri.UnescapeDataString(segment).Trim();
        if (decoded.Length < 3 || decoded[0] != '{' || decoded[^1] != '}')
        {
            return false;
        }

        var inner = decoded[1..^1].Trim();
        if (inner.Length == 0)
        {
            return false;
        }

        inner = NormalizeRoutePlaceholderName(inner);
        if (string.IsNullOrWhiteSpace(inner))
        {
            return false;
        }

        name = inner;
        return true;
    }

    private static string GetRoutePlaceholderName(string segment)
    {
        return TryGetRoutePlaceholderName(segment, out var name) ? name : string.Empty;
    }

    private static string NormalizeRoutePlaceholderName(string raw)
    {
        var trimmed = raw.Trim();
        if (trimmed.StartsWith("**", StringComparison.Ordinal))
        {
            trimmed = trimmed[2..];
        }
        else if (trimmed.StartsWith("*", StringComparison.Ordinal))
        {
            trimmed = trimmed[1..];
        }

        var split = trimmed.Split([':', '?', '='], 2);
        var name = split[0].Trim();
        if (string.IsNullOrWhiteSpace(name))
        {
            return string.Empty;
        }

        return name.ToLowerInvariant();
    }

    private static string ResolvePathTypeHint(
        string rawPlaceholder,
        string placeholderName,
        IReadOnlyDictionary<string, string>? pathParameterTypeHints)
    {
        if (pathParameterTypeHints is not null &&
            pathParameterTypeHints.TryGetValue(placeholderName, out var mapped) &&
            !string.IsNullOrWhiteSpace(mapped))
        {
            return mapped;
        }

        var raw = rawPlaceholder.Trim();
        var colonIndex = raw.IndexOf(':');
        if (colonIndex >= 0 && colonIndex < raw.Length - 1)
        {
            return raw[(colonIndex + 1)..];
        }

        return string.Empty;
    }

    private static string CoerceRoutePayloadValue(
        string payload,
        string rawPlaceholder,
        string placeholderName,
        string? typeHint)
    {
        var normalizedType = (typeHint ?? string.Empty).Trim().ToLowerInvariant();
        var normalizedPlaceholder = rawPlaceholder.Trim().ToLowerInvariant();

        if (IsGuidTypeHint(normalizedType) ||
            normalizedPlaceholder.Contains(":guid", StringComparison.Ordinal))
        {
            return Guid.Empty.ToString("D");
        }

        if (IsIntegerTypeHint(normalizedType) ||
            normalizedPlaceholder.Contains(":int", StringComparison.Ordinal) ||
            normalizedPlaceholder.Contains(":long", StringComparison.Ordinal))
        {
            return ExtractFirstIntegerLikeToken(payload) ?? "1";
        }

        if (IsFloatingPointTypeHint(normalizedType) ||
            normalizedPlaceholder.Contains(":double", StringComparison.Ordinal) ||
            normalizedPlaceholder.Contains(":float", StringComparison.Ordinal) ||
            normalizedPlaceholder.Contains(":decimal", StringComparison.Ordinal))
        {
            return ExtractFirstFloatingPointToken(payload) ?? "1.5";
        }

        if (IsBooleanTypeHint(normalizedType) ||
            normalizedPlaceholder.Contains(":bool", StringComparison.Ordinal))
        {
            return "true";
        }

        if (IsCharTypeHint(normalizedType))
        {
            return ExtractFirstCharacterToken(payload) ?? "a";
        }

        if (IsDateLikeTypeHint(normalizedType) ||
            normalizedPlaceholder.Contains(":datetime", StringComparison.Ordinal))
        {
            return normalizedType.Contains("timeonly", StringComparison.Ordinal)
                ? "12:00:00"
                : normalizedType.Contains("dateonly", StringComparison.Ordinal)
                    ? "2026-03-01"
                    : "2026-03-01T00:00:00Z";
        }

        return string.IsNullOrWhiteSpace(payload)
            ? ResolveFallbackRouteValue(placeholderName)
            : payload.Trim();
    }

    private static string? ExtractFirstIntegerLikeToken(string payload)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            return null;
        }

        var match = Regex.Match(payload, "-?\\d+");
        return match.Success ? match.Value : null;
    }

    private static string? ExtractFirstFloatingPointToken(string payload)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            return null;
        }

        var match = Regex.Match(payload, "-?\\d+(?:\\.\\d+)?");
        return match.Success ? match.Value : null;
    }

    private static string? ExtractFirstCharacterToken(string payload)
    {
        if (string.IsNullOrWhiteSpace(payload))
        {
            return null;
        }

        foreach (var character in payload.Trim())
        {
            if (!char.IsWhiteSpace(character))
            {
                return character.ToString();
            }
        }

        return null;
    }

    private static string ResolveFallbackRouteValue(string placeholderName)
    {
        return placeholderName switch
        {
            "id" or "userid" or "orderid" or "productid" => "1",
            "username" or "user" => "apitester",
            _ when placeholderName.Contains("id", StringComparison.Ordinal) => "1",
            _ => "test"
        };
    }

    private static string CoerceFieldPayloadValue(
        string payload,
        string fieldName,
        IReadOnlyDictionary<string, string>? fieldTypeHints)
    {
        var typedValue = ConvertPayloadForTypedField(payload, fieldName, fieldTypeHints);
        return typedValue switch
        {
            null => string.Empty,
            bool b => b ? "true" : "false",
            string s => s,
            _ => Convert.ToString(typedValue, System.Globalization.CultureInfo.InvariantCulture) ?? string.Empty
        };
    }

    private static object? ConvertPayloadForTypedField(
        string payload,
        string fieldName,
        IReadOnlyDictionary<string, string>? fieldTypeHints)
    {
        if (fieldTypeHints is null || !fieldTypeHints.TryGetValue(fieldName, out var typeHint))
        {
            return payload;
        }

        var normalized = typeHint.Trim().ToLowerInvariant();
        if (normalized.Contains("nonstring", StringComparison.Ordinal))
        {
            return 1;
        }

        if (normalized.Contains("sbyte", StringComparison.Ordinal))
        {
            return (sbyte)1;
        }

        if (normalized.Contains("byte", StringComparison.Ordinal) && !normalized.Contains("[]", StringComparison.Ordinal))
        {
            return (byte)1;
        }

        if (normalized.Contains("ushort", StringComparison.Ordinal))
        {
            return (ushort)1;
        }

        if (normalized.Contains("uint", StringComparison.Ordinal))
        {
            return (uint)1;
        }

        if (normalized.Contains("ulong", StringComparison.Ordinal))
        {
            return (ulong)1;
        }

        if (normalized.Contains("short", StringComparison.Ordinal))
        {
            return (short)1;
        }

        if (normalized.Contains("int", StringComparison.Ordinal))
        {
            return 1;
        }

        if (normalized.Contains("long", StringComparison.Ordinal))
        {
            return 1L;
        }

        if (normalized.Contains("decimal", StringComparison.Ordinal))
        {
            return 1.5m;
        }

        if (normalized.Contains("float", StringComparison.Ordinal))
        {
            return 1.5f;
        }

        if (normalized.Contains("double", StringComparison.Ordinal) ||
            normalized.Contains("number", StringComparison.Ordinal))
        {
            return 1.5d;
        }

        if (IsBooleanTypeHint(normalized))
        {
            return true;
        }

        if (IsCharTypeHint(normalized))
        {
            return ExtractFirstCharacterToken(payload) ?? "a";
        }

        if (normalized.Contains("dateonly", StringComparison.Ordinal))
        {
            return DateOnly.Parse("2026-03-01", System.Globalization.CultureInfo.InvariantCulture);
        }

        if (normalized.Contains("timeonly", StringComparison.Ordinal))
        {
            return TimeOnly.Parse("12:00:00", System.Globalization.CultureInfo.InvariantCulture);
        }

        if (normalized.Contains("datetimeoffset", StringComparison.Ordinal))
        {
            return DateTimeOffset.Parse("2026-03-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture);
        }

        if (normalized.Contains("date", StringComparison.Ordinal) ||
            normalized.Contains("time", StringComparison.Ordinal))
        {
            return DateTime.Parse("2026-03-01T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.RoundtripKind);
        }

        if (IsGuidTypeHint(normalized))
        {
            return Guid.Empty;
        }

        return payload;
    }

    private static bool IsIntegerTypeHint(string normalizedType)
    {
        return normalizedType.Contains("sbyte", StringComparison.Ordinal) ||
               normalizedType.Contains("byte", StringComparison.Ordinal) ||
               normalizedType.Contains("short", StringComparison.Ordinal) ||
               normalizedType.Contains("ushort", StringComparison.Ordinal) ||
               normalizedType.Contains("int", StringComparison.Ordinal) ||
               normalizedType.Contains("uint", StringComparison.Ordinal) ||
               normalizedType.Contains("long", StringComparison.Ordinal) ||
               normalizedType.Contains("ulong", StringComparison.Ordinal);
    }

    private static bool IsFloatingPointTypeHint(string normalizedType)
    {
        return normalizedType.Contains("decimal", StringComparison.Ordinal) ||
               normalizedType.Contains("double", StringComparison.Ordinal) ||
               normalizedType.Contains("float", StringComparison.Ordinal) ||
               normalizedType.Contains("number", StringComparison.Ordinal);
    }

    private static bool IsBooleanTypeHint(string normalizedType)
    {
        return normalizedType.Contains("bool", StringComparison.Ordinal);
    }

    private static bool IsCharTypeHint(string normalizedType)
    {
        return normalizedType.Contains("char", StringComparison.Ordinal);
    }

    private static bool IsGuidTypeHint(string normalizedType)
    {
        return normalizedType.Contains("guid", StringComparison.Ordinal) ||
               normalizedType.Contains("uuid", StringComparison.Ordinal);
    }

    private static bool IsDateLikeTypeHint(string normalizedType)
    {
        return normalizedType.Contains("dateonly", StringComparison.Ordinal) ||
               normalizedType.Contains("timeonly", StringComparison.Ordinal) ||
               normalizedType.Contains("datetimeoffset", StringComparison.Ordinal) ||
               normalizedType.Contains("date", StringComparison.Ordinal) ||
               normalizedType.Contains("time", StringComparison.Ordinal);
    }

    private static bool ShouldReplaceTerminalPathSegment(IReadOnlyList<string> parts)
    {
        if (parts.Count < 2)
        {
            return false;
        }

        var last = parts[^1];
        if (string.IsNullOrWhiteSpace(last))
        {
            return false;
        }

        return int.TryParse(last, out _) ||
               Guid.TryParse(last, out _) ||
               Regex.IsMatch(last, "^[0-9a-f]{8,}$", RegexOptions.IgnoreCase) ||
               Regex.IsMatch(last, "^[A-Za-z0-9_-]{6,}$", RegexOptions.CultureInvariant);
    }

    private static Uri StripQuery(Uri uri)
    {
        var builder = new UriBuilder(uri) { Query = string.Empty };
        return builder.Uri;
    }

    private static Uri ApplyQueryOverride(Uri baseUri, string? keyOrRawQuery, string? value)
    {
        var builder = new UriBuilder(baseUri);
        var merged = ParseQuery(builder.Query);
        Dictionary<string, string> overrideValues;

        if (!string.IsNullOrWhiteSpace(keyOrRawQuery) && keyOrRawQuery.Contains('='))
        {
            var rawQuery = keyOrRawQuery.StartsWith("?", StringComparison.Ordinal) ? keyOrRawQuery : "?" + keyOrRawQuery;
            overrideValues = ParseQuery(rawQuery);
        }
        else if (!string.IsNullOrWhiteSpace(keyOrRawQuery))
        {
            overrideValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [keyOrRawQuery] = value ?? string.Empty
            };
        }
        else
        {
            var rawValue = value ?? string.Empty;
            overrideValues = ParseQuery(rawValue.StartsWith("?", StringComparison.Ordinal) ? rawValue : "?" + rawValue);
        }

        foreach (var kvp in overrideValues)
        {
            merged[kvp.Key] = kvp.Value;
        }

        builder.Query = BuildQuery(merged);
        return builder.Uri;
    }

    private static void RemoveNonAuthPayloadHeaders(HttpRequestMessage request)
    {
        var removable = request.Headers
            .Select(h => h.Key)
            .Where(key =>
                !key.Equals("Authorization", StringComparison.OrdinalIgnoreCase) &&
                !key.Equals("Cookie", StringComparison.OrdinalIgnoreCase) &&
                !key.StartsWith("X-Api-Key", StringComparison.OrdinalIgnoreCase))
            .ToList();

        foreach (var key in removable)
        {
            request.Headers.Remove(key);
        }
    }

    private static string BuildPayloadBody(SingleTargetPayload payload)
    {
        if (payload.IsStructuredBody)
        {
            return payload.Value;
        }

        var escapedValue = JsonSerializer.Serialize(payload.Value);
        var escapedName = JsonSerializer.Serialize(payload.Name);
        return $"{{{escapedName}:{escapedValue}}}";
    }

    private static HttpContent BuildBodyOverrideContent(string rawBody, bool forceJson = false)
    {
        var trimmed = rawBody.Trim();
        var contentType = forceJson ||
                          (trimmed.StartsWith("{", StringComparison.Ordinal) && trimmed.EndsWith("}", StringComparison.Ordinal)) ||
                          (trimmed.StartsWith("[", StringComparison.Ordinal) && trimmed.EndsWith("]", StringComparison.Ordinal))
            ? "application/json"
            : "text/plain";

        return new StringContent(rawBody, Encoding.UTF8, contentType);
    }

    private static bool HasJsonContentType(HttpContent? content)
    {
        var mediaType = content?.Headers?.ContentType?.MediaType;
        return !string.IsNullOrWhiteSpace(mediaType) &&
               mediaType.Contains("json", StringComparison.OrdinalIgnoreCase);
    }

    private static void ApplyHeaderOverride(HttpRequestMessage request, string? headerName, string value)
    {
        var effectiveHeaderName = string.IsNullOrWhiteSpace(headerName) ? "X-Api-Tester" : headerName;
        request.Headers.Remove(effectiveHeaderName);
        if (!request.Headers.TryAddWithoutValidation(effectiveHeaderName, value))
        {
            request.Content ??= new StringContent(string.Empty);
            request.Content.Headers.Remove(effectiveHeaderName);
            request.Content.Headers.TryAddWithoutValidation(effectiveHeaderName, value);
        }
    }

    private static void ApplyCookieOverride(HttpRequestMessage request, string? cookieName, string value)
    {
        var effectiveCookieName = string.IsNullOrWhiteSpace(cookieName) ? "api_tester" : cookieName;
        request.Headers.Remove("Cookie");
        request.Headers.TryAddWithoutValidation("Cookie", $"{effectiveCookieName}={value}");
    }

    private static bool LooksStructuredBody(string rawBody)
    {
        var trimmed = rawBody.Trim();
        return (trimmed.StartsWith("{", StringComparison.Ordinal) && trimmed.EndsWith("}", StringComparison.Ordinal)) ||
               (trimmed.StartsWith("[", StringComparison.Ordinal) && trimmed.EndsWith("]", StringComparison.Ordinal));
    }

    private static bool IsSameOrigin(Uri baseUri, Uri candidate) =>
        string.Equals(baseUri.Scheme, candidate.Scheme, StringComparison.OrdinalIgnoreCase) &&
        string.Equals(baseUri.Host, candidate.Host, StringComparison.OrdinalIgnoreCase) &&
        baseUri.Port == candidate.Port;

    private sealed record SingleTargetPayload(string Name, string Value, bool IsStructuredBody);
}
