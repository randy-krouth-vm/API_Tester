namespace ApiTester.Core;

public sealed record OpenApiProbeContextResolution(
    OpenApiProbeContext Context,
    string LastOpenApiInputRaw);

public static class OpenApiProbeContextUtilities
{
    public static async Task<OpenApiProbeContextResolution> ResolveAsync(
        Uri baseUri,
        string overrideRaw,
        bool useOpenApiEndpoints,
        bool isSpiderRouteScopeSelected,
        bool typeAwareEnabled,
        IDictionary<string, OpenApiProbeContext> cache,
        string lastOpenApiInputRaw,
        Func<Uri, Task<OpenApiSnapshot?>> tryFetchOpenApiSnapshotAsync,
        Func<Uri, Task<IReadOnlyList<ApiEndpointDescriptor>?>> tryFetchEndpointMetadataAsync)
    {
        var hasExplicitOpenApiInput = !string.IsNullOrWhiteSpace(overrideRaw);
        var allowEndpointDiscovery = useOpenApiEndpoints || hasExplicitOpenApiInput || (isSpiderRouteScopeSelected && typeAwareEnabled);
        var allowTypeAwareMetadata = typeAwareEnabled && (useOpenApiEndpoints || isSpiderRouteScopeSelected || hasExplicitOpenApiInput);
        var updatedLastOpenApiInputRaw = lastOpenApiInputRaw;

        if (!overrideRaw.Equals(lastOpenApiInputRaw, StringComparison.Ordinal))
        {
            cache.Clear();
            updatedLastOpenApiInputRaw = overrideRaw;
        }

        if (!allowEndpointDiscovery)
        {
            return new OpenApiProbeContextResolution(CreateBaseContext(baseUri), updatedLastOpenApiInputRaw);
        }

        var cacheKey = $"{baseUri.Scheme}://{baseUri.Authority}|{overrideRaw}".ToLowerInvariant();
        if (cache.TryGetValue(cacheKey, out var cached))
        {
            if (useOpenApiEndpoints)
            {
                return new OpenApiProbeContextResolution(cached, updatedLastOpenApiInputRaw);
            }

            var shapedCached = allowTypeAwareMetadata
                ? CreateMetadataContext(baseUri, cached, isSpiderRouteScopeSelected)
                : CreateBaseContext(baseUri);
            return new OpenApiProbeContextResolution(shapedCached, updatedLastOpenApiInputRaw);
        }

        var snapshot = await tryFetchOpenApiSnapshotAsync(baseUri);
        if (snapshot is null)
        {
            var endpointMetadata = await tryFetchEndpointMetadataAsync(baseUri);
            if (endpointMetadata is null || endpointMetadata.Count == 0)
            {
                var empty = CreateBaseContext(baseUri);
                cache[cacheKey] = empty;
                return new OpenApiProbeContextResolution(empty, updatedLastOpenApiInputRaw);
            }

            var metadataContext = EndpointMetadataUtilities.BuildProbeContext(baseUri, endpointMetadata);
            cache[cacheKey] = metadataContext;
            if (useOpenApiEndpoints)
            {
                return new OpenApiProbeContextResolution(metadataContext, updatedLastOpenApiInputRaw);
            }

            var shapedMetadata = allowTypeAwareMetadata
                ? CreateMetadataContext(baseUri, metadataContext, isSpiderRouteScopeSelected)
                : CreateBaseContext(baseUri);
            return new OpenApiProbeContextResolution(shapedMetadata, updatedLastOpenApiInputRaw);
        }

        OpenApiProbeContext context;
        try
        {
            context = OpenApiProbeAnalyzer.AnalyzeProbeContext(snapshot.Document, baseUri, snapshot.SourceUri);
        }
        finally
        {
            snapshot.Document.Dispose();
        }

        if (allowTypeAwareMetadata)
        {
            var endpointMetadata = await tryFetchEndpointMetadataAsync(baseUri);
            if (endpointMetadata is { Count: > 0 })
            {
                var metadataContext = EndpointMetadataUtilities.BuildProbeContext(baseUri, endpointMetadata);
                context = PreferRuntimeMetadata(context, metadataContext);
            }
        }

        cache[cacheKey] = context;
        if (useOpenApiEndpoints)
        {
            return new OpenApiProbeContextResolution(context, updatedLastOpenApiInputRaw);
        }

        var shaped = allowTypeAwareMetadata
            ? CreateMetadataContext(baseUri, context, isSpiderRouteScopeSelected)
            : CreateBaseContext(baseUri);
        return new OpenApiProbeContextResolution(shaped, updatedLastOpenApiInputRaw);
    }

    private static OpenApiProbeContext CreateBaseContext(Uri baseUri)
    {
        return new OpenApiProbeContext(
            new List<Uri> { baseUri },
            new List<string>(),
            new List<string>(),
            new List<string>(),
            new List<string>(),
            new List<string>(),
            new List<OpenApiOperationProfile>());
    }

    private static OpenApiProbeContext CreateMetadataContext(
        Uri baseUri,
        OpenApiProbeContext source,
        bool includeEndpoints)
    {
        return new OpenApiProbeContext(
            includeEndpoints ? new List<Uri>(source.TargetEndpoints) : new List<Uri> { baseUri },
            new List<string>(source.QueryParameterNames),
            new List<string>(source.BodyPropertyNames),
            new List<string>(source.NonStringQueryParameterNames),
            new List<string>(source.NonStringBodyPropertyNames),
            new List<string>(source.PathParameterNames),
            source.OperationProfiles
                .Select(profile => new OpenApiOperationProfile(
                    profile.Endpoint,
                    new List<string>(profile.AllowedMethods),
                    new List<string>(profile.QueryParameterNames),
                    new List<string>(profile.BodyPropertyNames),
                    new List<string>(profile.PathParameterNames),
                    new Dictionary<string, string>(profile.QueryParameterTypeHints, StringComparer.OrdinalIgnoreCase),
                    new Dictionary<string, string>(profile.BodyPropertyTypeHints, StringComparer.OrdinalIgnoreCase),
                    new Dictionary<string, string>(profile.PathParameterTypeHints, StringComparer.OrdinalIgnoreCase)))
                .ToList());
    }

    private static OpenApiProbeContext PreferRuntimeMetadata(OpenApiProbeContext openApiContext, OpenApiProbeContext metadataContext)
    {
        var endpoints = openApiContext.TargetEndpoints
            .Concat(metadataContext.TargetEndpoints)
            .DistinctBy(uri => uri.ToString(), StringComparer.OrdinalIgnoreCase)
            .ToList();

        var queryNames = openApiContext.QueryParameterNames
            .Concat(metadataContext.QueryParameterNames)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var bodyNames = openApiContext.BodyPropertyNames
            .Concat(metadataContext.BodyPropertyNames)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var nonStringQueryNames = openApiContext.NonStringQueryParameterNames
            .Concat(metadataContext.NonStringQueryParameterNames)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var nonStringBodyNames = openApiContext.NonStringBodyPropertyNames
            .Concat(metadataContext.NonStringBodyPropertyNames)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var pathNames = openApiContext.PathParameterNames
            .Concat(metadataContext.PathParameterNames)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var operationProfiles = metadataContext.OperationProfiles.Count > 0
            ? metadataContext.OperationProfiles
            : openApiContext.OperationProfiles;

        return new OpenApiProbeContext(
            endpoints,
            queryNames,
            bodyNames,
            nonStringQueryNames,
            nonStringBodyNames,
            pathNames,
            operationProfiles);
    }
}
