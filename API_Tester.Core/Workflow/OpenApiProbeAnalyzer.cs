using System.Text.Json;

namespace ApiTester.Core;

public sealed record OpenApiDocumentSummary(
    int PathCount,
    int OperationCount,
    int SecuredOperationCount,
    int UnsecuredOperationCount,
    int SchemaCount);

public static class OpenApiProbeAnalyzer
{
    public static OpenApiDocumentSummary AnalyzeDocumentSummary(JsonDocument document)
    {
        var pathCount = 0;
        var operationCount = 0;
        var securedOps = 0;
        var unsecuredOps = 0;
        var schemaCount = 0;

        var root = document.RootElement;
        if (root.TryGetProperty("components", out var components) &&
            components.ValueKind == JsonValueKind.Object &&
            components.TryGetProperty("schemas", out var schemas) &&
            schemas.ValueKind == JsonValueKind.Object)
        {
            schemaCount = schemas.EnumerateObject().Count();
        }

        if (!root.TryGetProperty("paths", out var paths) || paths.ValueKind != JsonValueKind.Object)
        {
            return new OpenApiDocumentSummary(pathCount, operationCount, securedOps, unsecuredOps, schemaCount);
        }

        foreach (var path in paths.EnumerateObject())
        {
            pathCount++;
            if (path.Value.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            foreach (var op in path.Value.EnumerateObject())
            {
                if (!DiscoveryUtilities.IsHttpVerb(op.Name))
                {
                    continue;
                }

                operationCount++;
                if (op.Value.ValueKind == JsonValueKind.Object &&
                    op.Value.TryGetProperty("security", out var sec) &&
                    sec.ValueKind == JsonValueKind.Array &&
                    sec.GetArrayLength() > 0)
                {
                    securedOps++;
                }
                else
                {
                    unsecuredOps++;
                }
            }
        }

        return new OpenApiDocumentSummary(pathCount, operationCount, securedOps, unsecuredOps, schemaCount);
    }

    public static OpenApiProbeContext AnalyzeProbeContext(JsonDocument document, Uri baseUri, Uri sourceUri)
    {
        var endpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var queryNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var bodyNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var pathNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var nonStringQueryNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var nonStringBodyNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var operationProfiles = new Dictionary<string, MutableOperationProfile>(StringComparer.OrdinalIgnoreCase);

        var root = document.RootElement;
        if (root.TryGetProperty("paths", out var paths) && paths.ValueKind == JsonValueKind.Object)
        {
            var globalServerBases = DiscoveryUtilities.ResolveOpenApiServerBases(root, baseUri, sourceUri);
            foreach (var pathEntry in paths.EnumerateObject())
            {
                var rawPath = pathEntry.Name;
                var normalizedPath = System.Text.RegularExpressions.Regex.Replace(rawPath, "{[^}]+}", "1");
                if (!normalizedPath.StartsWith('/'))
                {
                    normalizedPath = "/" + normalizedPath;
                }

                DiscoveryUtilities.AddEndpointCandidates(globalServerBases, normalizedPath, endpoints);

                if (pathEntry.Value.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                var pathServerBases = DiscoveryUtilities.ResolveOpenApiServerBases(pathEntry.Value, baseUri, sourceUri);
                DiscoveryUtilities.AddEndpointCandidates(pathServerBases, normalizedPath, endpoints);
                TrackOperationProfiles(globalServerBases, normalizedPath, operationProfiles);
                TrackOperationProfiles(pathServerBases, normalizedPath, operationProfiles);

                if (pathEntry.Value.TryGetProperty("parameters", out var pathParams))
                {
                    CollectQueryParameterNames(root, pathParams, queryNames, nonStringQueryNames);
                    CollectPathParameterNames(root, pathParams, pathNames);
                }

                foreach (var op in pathEntry.Value.EnumerateObject())
                {
                    if (!DiscoveryUtilities.IsHttpVerb(op.Name) || op.Value.ValueKind != JsonValueKind.Object)
                    {
                        continue;
                    }

                    var opServerBases = DiscoveryUtilities.ResolveOpenApiServerBases(op.Value, baseUri, sourceUri);
                    DiscoveryUtilities.AddEndpointCandidates(opServerBases, normalizedPath, endpoints);
                    TrackOperationProfiles(opServerBases, normalizedPath, operationProfiles, op.Name);

                    if (op.Value.TryGetProperty("parameters", out var opParams))
                    {
                        CollectQueryParameterNames(root, opParams, queryNames, nonStringQueryNames);
                        CollectPathParameterNames(root, opParams, pathNames);
                        CollectQueryParameterNames(root, opParams, operationProfiles, opServerBases, normalizedPath);
                        CollectPathParameterNames(root, opParams, operationProfiles, opServerBases, normalizedPath);
                    }

                    if (op.Value.TryGetProperty("requestBody", out var requestBody))
                    {
                        CollectBodyPropertyNames(root, requestBody, bodyNames, nonStringBodyNames);
                        CollectBodyPropertyNames(root, requestBody, operationProfiles, opServerBases, normalizedPath);
                    }

                    if (pathEntry.Value.TryGetProperty("parameters", out var inheritedPathParams))
                    {
                        CollectQueryParameterNames(root, inheritedPathParams, operationProfiles, opServerBases, normalizedPath);
                        CollectPathParameterNames(root, inheritedPathParams, operationProfiles, opServerBases, normalizedPath);
                    }
                }
            }
        }

        if (endpoints.Count == 0)
        {
            endpoints.Add(baseUri.ToString());
        }

        return new OpenApiProbeContext(
            endpoints.Select(u => new Uri(u)).ToList(),
            queryNames.ToList(),
            bodyNames.ToList(),
            nonStringQueryNames.ToList(),
            nonStringBodyNames.ToList(),
            pathNames.ToList(),
            operationProfiles.Values
                .Select(p => new OpenApiOperationProfile(
                    new Uri(p.Endpoint),
                    p.AllowedMethods.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
                    p.QueryParameterNames.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
                    p.BodyPropertyNames.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
                    p.PathParameterNames.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToList(),
                    new Dictionary<string, string>(p.QueryParameterTypeHints, StringComparer.OrdinalIgnoreCase),
                    new Dictionary<string, string>(p.BodyPropertyTypeHints, StringComparer.OrdinalIgnoreCase),
                    new Dictionary<string, string>(p.PathParameterTypeHints, StringComparer.OrdinalIgnoreCase)))
                .ToList());
    }

    private sealed class MutableOperationProfile
    {
        public required string Endpoint { get; init; }
        public HashSet<string> AllowedMethods { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> QueryParameterNames { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> BodyPropertyNames { get; } = new(StringComparer.OrdinalIgnoreCase);
        public HashSet<string> PathParameterNames { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> QueryParameterTypeHints { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> BodyPropertyTypeHints { get; } = new(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> PathParameterTypeHints { get; } = new(StringComparer.OrdinalIgnoreCase);
    }

    private static void TrackOperationProfiles(
        IEnumerable<Uri> baseUris,
        string normalizedPath,
        Dictionary<string, MutableOperationProfile> profiles,
        string? method = null)
    {
        foreach (var baseUri in baseUris)
        {
            Uri endpoint;
            try
            {
                endpoint = new Uri(baseUri, normalizedPath);
            }
            catch
            {
                continue;
            }

            var key = endpoint.ToString();
            if (!profiles.TryGetValue(key, out var profile))
            {
                profile = new MutableOperationProfile { Endpoint = key };
                profiles[key] = profile;
            }

            if (!string.IsNullOrWhiteSpace(method))
            {
                profile.AllowedMethods.Add(method.ToUpperInvariant());
            }
        }
    }

    private static void CollectQueryParameterNames(
        JsonElement root,
        JsonElement parameters,
        Dictionary<string, MutableOperationProfile> profiles,
        IEnumerable<Uri> baseUris,
        string normalizedPath)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var nonStrings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        CollectQueryParameterNames(root, parameters, names, nonStrings);
        if (names.Count == 0)
        {
            return;
        }

        foreach (var baseUri in baseUris)
        {
            Uri endpoint;
            try
            {
                endpoint = new Uri(baseUri, normalizedPath);
            }
            catch
            {
                continue;
            }

            if (!profiles.TryGetValue(endpoint.ToString(), out var profile))
            {
                continue;
            }

            foreach (var name in names)
            {
                profile.QueryParameterNames.Add(name);
                if (nonStrings.Contains(name))
                {
                    profile.QueryParameterTypeHints.TryAdd(name, "nonstring");
                }
            }
        }
    }

    private static void CollectPathParameterNames(
        JsonElement root,
        JsonElement parameters,
        HashSet<string> output)
    {
        CollectPathParameterNames(root, parameters, output, null);
    }

    private static void CollectPathParameterNames(
        JsonElement root,
        JsonElement parameters,
        HashSet<string> output,
        Dictionary<string, string>? typeHints)
    {
        if (parameters.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var p in parameters.EnumerateArray())
        {
            if (p.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var resolvedParameter = DereferenceOpenApiObject(root, p, 0);
            if (!resolvedParameter.HasValue)
            {
                continue;
            }

            var parameterObject = resolvedParameter.Value;
            if (parameterObject.TryGetProperty("in", out var inEl) &&
                inEl.ValueKind == JsonValueKind.String &&
                inEl.GetString()?.Equals("path", StringComparison.OrdinalIgnoreCase) == true &&
                parameterObject.TryGetProperty("name", out var nameEl) &&
                nameEl.ValueKind == JsonValueKind.String)
            {
                var value = nameEl.GetString();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    output.Add(value!);
                    if (typeHints is not null &&
                        parameterObject.TryGetProperty("schema", out var schema) &&
                        schema.ValueKind == JsonValueKind.Object)
                    {
                        var typeHint = ResolveSchemaTypeHint(root, schema, 0);
                        if (!string.IsNullOrWhiteSpace(typeHint))
                        {
                            typeHints[value!] = typeHint!;
                        }
                    }
                }
            }
        }
    }

    private static void CollectPathParameterNames(
        JsonElement root,
        JsonElement parameters,
        Dictionary<string, MutableOperationProfile> profiles,
        IEnumerable<Uri> baseUris,
        string normalizedPath)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var typeHints = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        CollectPathParameterNames(root, parameters, names, typeHints);
        if (names.Count == 0)
        {
            return;
        }

        foreach (var baseUri in baseUris)
        {
            Uri endpoint;
            try
            {
                endpoint = new Uri(baseUri, normalizedPath);
            }
            catch
            {
                continue;
            }

            if (!profiles.TryGetValue(endpoint.ToString(), out var profile))
            {
                continue;
            }

            foreach (var name in names)
            {
                profile.PathParameterNames.Add(name);
                if (typeHints.TryGetValue(name, out var typeHint) && !string.IsNullOrWhiteSpace(typeHint))
                {
                    profile.PathParameterTypeHints[name] = typeHint;
                }
            }
        }
    }

    private static void CollectBodyPropertyNames(
        JsonElement root,
        JsonElement requestBody,
        Dictionary<string, MutableOperationProfile> profiles,
        IEnumerable<Uri> baseUris,
        string normalizedPath)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var nonStrings = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        CollectBodyPropertyNames(root, requestBody, names, nonStrings);
        if (names.Count == 0)
        {
            return;
        }

        foreach (var baseUri in baseUris)
        {
            Uri endpoint;
            try
            {
                endpoint = new Uri(baseUri, normalizedPath);
            }
            catch
            {
                continue;
            }

            if (!profiles.TryGetValue(endpoint.ToString(), out var profile))
            {
                continue;
            }

            foreach (var name in names)
            {
                profile.BodyPropertyNames.Add(name);
                if (nonStrings.Contains(name))
                {
                    profile.BodyPropertyTypeHints.TryAdd(name, "nonstring");
                }
            }
        }
    }

    private static void CollectQueryParameterNames(
        JsonElement root,
        JsonElement parameters,
        HashSet<string> output,
        HashSet<string> nonStringOutput)
    {
        if (parameters.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var p in parameters.EnumerateArray())
        {
            if (p.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var resolvedParameter = DereferenceOpenApiObject(root, p, 0);
            if (!resolvedParameter.HasValue)
            {
                continue;
            }

            var parameterObject = resolvedParameter.Value;
            if (parameterObject.TryGetProperty("in", out var inEl) &&
                inEl.ValueKind == JsonValueKind.String &&
                inEl.GetString()?.Equals("query", StringComparison.OrdinalIgnoreCase) == true &&
                parameterObject.TryGetProperty("name", out var nameEl) &&
                nameEl.ValueKind == JsonValueKind.String)
            {
                var value = nameEl.GetString();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    output.Add(value!);
                    if (parameterObject.TryGetProperty("schema", out var schema) && schema.ValueKind == JsonValueKind.Object)
                    {
                        var compatibility = GetSchemaStringCompatibility(root, schema, 0);
                        if (compatibility == SchemaStringCompatibility.NonString)
                        {
                            nonStringOutput.Add(value!);
                        }
                    }
                }
            }
        }
    }

    private static void CollectBodyPropertyNames(
        JsonElement root,
        JsonElement requestBody,
        HashSet<string> output,
        HashSet<string> nonStringOutput)
    {
        if (requestBody.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        var resolvedRequestBody = DereferenceOpenApiObject(root, requestBody, 0);
        if (!resolvedRequestBody.HasValue ||
            !resolvedRequestBody.Value.TryGetProperty("content", out var content) ||
            content.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var mediaType in content.EnumerateObject())
        {
            if (!mediaType.Name.Contains("json", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!mediaType.Value.TryGetProperty("schema", out var schema) || schema.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            CollectSchemaPropertyNames(root, schema, output, nonStringOutput, 0);
        }
    }

    private static void CollectSchemaPropertyNames(
        JsonElement root,
        JsonElement schema,
        HashSet<string> output,
        HashSet<string> nonStringOutput,
        int depth)
    {
        if (depth > 3 || schema.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        if (schema.TryGetProperty("$ref", out var refEl) && refEl.ValueKind == JsonValueKind.String)
        {
            var reference = refEl.GetString();
            var resolved = ResolveSchemaRef(root, reference);
            if (resolved.HasValue)
            {
                CollectSchemaPropertyNames(root, resolved.Value, output, nonStringOutput, depth + 1);
            }
            return;
        }

        if (schema.TryGetProperty("properties", out var properties) && properties.ValueKind == JsonValueKind.Object)
        {
            foreach (var prop in properties.EnumerateObject())
            {
                output.Add(prop.Name);
                var compatibility = GetSchemaStringCompatibility(root, prop.Value, depth + 1);
                if (compatibility == SchemaStringCompatibility.NonString)
                {
                    nonStringOutput.Add(prop.Name);
                }

                CollectSchemaPropertyNames(root, prop.Value, output, nonStringOutput, depth + 1);
            }
        }

        if (schema.TryGetProperty("allOf", out var allOf) && allOf.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in allOf.EnumerateArray())
            {
                CollectSchemaPropertyNames(root, item, output, nonStringOutput, depth + 1);
            }
        }

        if (schema.TryGetProperty("oneOf", out var oneOf) && oneOf.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in oneOf.EnumerateArray())
            {
                CollectSchemaPropertyNames(root, item, output, nonStringOutput, depth + 1);
            }
        }

        if (schema.TryGetProperty("anyOf", out var anyOf) && anyOf.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in anyOf.EnumerateArray())
            {
                CollectSchemaPropertyNames(root, item, output, nonStringOutput, depth + 1);
            }
        }
    }

    private enum SchemaStringCompatibility
    {
        Unknown,
        StringCompatible,
        NonString
    }

    private static SchemaStringCompatibility GetSchemaStringCompatibility(JsonElement root, JsonElement schema, int depth)
    {
        if (depth > 6 || schema.ValueKind != JsonValueKind.Object)
        {
            return SchemaStringCompatibility.Unknown;
        }

        if (schema.TryGetProperty("$ref", out var refEl) && refEl.ValueKind == JsonValueKind.String)
        {
            var resolved = ResolveSchemaRef(root, refEl.GetString());
            return resolved.HasValue
                ? GetSchemaStringCompatibility(root, resolved.Value, depth + 1)
                : SchemaStringCompatibility.Unknown;
        }

        if (schema.TryGetProperty("type", out var typeEl) && typeEl.ValueKind == JsonValueKind.String)
        {
            var schemaType = typeEl.GetString()?.Trim().ToLowerInvariant();
            return schemaType switch
            {
                "string" => SchemaStringCompatibility.StringCompatible,
                "integer" or "number" or "boolean" or "object" or "array" => SchemaStringCompatibility.NonString,
                _ => SchemaStringCompatibility.Unknown
            };
        }

        if (schema.TryGetProperty("type", out typeEl) && typeEl.ValueKind == JsonValueKind.Array)
        {
            var hasString = false;
            var hasNonString = false;
            var hasUnknown = false;
            foreach (var t in typeEl.EnumerateArray())
            {
                if (t.ValueKind != JsonValueKind.String)
                {
                    hasUnknown = true;
                    continue;
                }

                var token = t.GetString()?.Trim().ToLowerInvariant();
                if (token == "string")
                {
                    hasString = true;
                }
                else if (token is "integer" or "number" or "boolean" or "object" or "array")
                {
                    hasNonString = true;
                }
                else if (token == "null")
                {
                    // nullable wrapper; keep evaluating remaining type tokens.
                }
                else
                {
                    hasUnknown = true;
                }
            }

            if (hasString)
            {
                return SchemaStringCompatibility.StringCompatible;
            }

            if (hasNonString && !hasUnknown)
            {
                return SchemaStringCompatibility.NonString;
            }
        }

        if (schema.TryGetProperty("enum", out var enumEl) && enumEl.ValueKind == JsonValueKind.Array)
        {
            var enumValues = enumEl.EnumerateArray().ToArray();
            if (enumValues.Length == 0)
            {
                return SchemaStringCompatibility.Unknown;
            }

            var allStrings = enumValues.All(v => v.ValueKind == JsonValueKind.String);
            var allNonStrings = enumValues.All(v => v.ValueKind is JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False);
            if (allStrings)
            {
                return SchemaStringCompatibility.StringCompatible;
            }

            if (allNonStrings)
            {
                return SchemaStringCompatibility.NonString;
            }
        }

        if (schema.TryGetProperty("oneOf", out var oneOf) && oneOf.ValueKind == JsonValueKind.Array)
        {
            return CombineCompositeCompatibility(root, oneOf, depth + 1);
        }

        if (schema.TryGetProperty("anyOf", out var anyOf) && anyOf.ValueKind == JsonValueKind.Array)
        {
            return CombineCompositeCompatibility(root, anyOf, depth + 1);
        }

        if (schema.TryGetProperty("allOf", out var allOf) && allOf.ValueKind == JsonValueKind.Array)
        {
            return CombineCompositeCompatibility(root, allOf, depth + 1);
        }

        return SchemaStringCompatibility.Unknown;
    }

    private static SchemaStringCompatibility CombineCompositeCompatibility(JsonElement root, JsonElement compositeArray, int depth)
    {
        var sawUnknown = false;
        foreach (var item in compositeArray.EnumerateArray())
        {
            var compatibility = GetSchemaStringCompatibility(root, item, depth + 1);
            if (compatibility == SchemaStringCompatibility.StringCompatible)
            {
                return SchemaStringCompatibility.StringCompatible;
            }

            if (compatibility == SchemaStringCompatibility.Unknown)
            {
                sawUnknown = true;
            }
        }

        return sawUnknown ? SchemaStringCompatibility.Unknown : SchemaStringCompatibility.NonString;
    }

    private static JsonElement? ResolveSchemaRef(JsonElement root, string? reference)
    {
        return ResolveOpenApiRef(root, reference);
    }

    private static string? ResolveSchemaTypeHint(JsonElement root, JsonElement schema, int depth)
    {
        if (depth > 6 || schema.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (schema.TryGetProperty("$ref", out var refEl) && refEl.ValueKind == JsonValueKind.String)
        {
            var resolved = ResolveSchemaRef(root, refEl.GetString());
            return resolved.HasValue
                ? ResolveSchemaTypeHint(root, resolved.Value, depth + 1)
                : null;
        }

        if (schema.TryGetProperty("format", out var formatEl) &&
            formatEl.ValueKind == JsonValueKind.String &&
            !string.IsNullOrWhiteSpace(formatEl.GetString()))
        {
            return formatEl.GetString();
        }

        if (schema.TryGetProperty("type", out var typeEl))
        {
            if (typeEl.ValueKind == JsonValueKind.String)
            {
                return typeEl.GetString();
            }

            if (typeEl.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in typeEl.EnumerateArray())
                {
                    if (item.ValueKind == JsonValueKind.String &&
                        !string.Equals(item.GetString(), "null", StringComparison.OrdinalIgnoreCase))
                    {
                        return item.GetString();
                    }
                }
            }
        }

        return null;
    }

    private static JsonElement? ResolveOpenApiRef(JsonElement root, string? reference)
    {
        if (string.IsNullOrWhiteSpace(reference) || !reference.StartsWith("#/", StringComparison.Ordinal))
        {
            return null;
        }

        var current = root;
        var parts = reference[2..].Split('/', StringSplitOptions.RemoveEmptyEntries);
        foreach (var part in parts)
        {
            var key = part.Replace("~1", "/").Replace("~0", "~");
            if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(key, out current))
            {
                return null;
            }
        }

        return current;
    }

    private static JsonElement? DereferenceOpenApiObject(JsonElement root, JsonElement element, int depth)
    {
        if (depth > 8 || element.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        if (!element.TryGetProperty("$ref", out var refEl) || refEl.ValueKind != JsonValueKind.String)
        {
            return element;
        }

        var resolved = ResolveOpenApiRef(root, refEl.GetString());
        if (!resolved.HasValue || resolved.Value.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        return DereferenceOpenApiObject(root, resolved.Value, depth + 1);
    }
}
