using ApiTester.Shared;

namespace ApiTester.Core;

public static class RequestOverrideWorkflowUtilities
{
    public static async Task ApplySingleTargetRequestOverridesAsync(
        HttpRequestMessage request,
        RunScopeMode runScopeMode,
        Func<Uri?> resolveConfiguredTargetUri,
        Func<Uri, Task<OpenApiOperationProfile?>> tryGetAutomaticSingleTargetOperationProfileAsync,
        PayloadLocation selectedPayloadLocation,
        HttpMethod? selectedOperationOverride,
        bool shouldApplyManualSingleTargetPayloadOverrides,
        Func<Uri, Uri, bool> isSameOrigin,
        Func<Uri, Uri, bool> pathsMatchForScope)
    {
        if (request.RequestUri is null)
        {
            return;
        }

        if (runScopeMode != RunScopeMode.SingleTarget)
        {
            if (selectedOperationOverride is not null)
            {
                return;
            }

            var autoProfile = await tryGetAutomaticSingleTargetOperationProfileAsync(request.RequestUri);
            if (autoProfile is null)
            {
                return;
            }

            var contract = new OperationContract(
                autoProfile.Endpoint,
                autoProfile.AllowedMethods,
                autoProfile.QueryParameterNames,
                autoProfile.BodyPropertyNames,
                autoProfile.PathParameterNames,
                autoProfile.QueryParameterTypeHints,
                autoProfile.BodyPropertyTypeHints,
                autoProfile.PathParameterTypeHints,
                null);

            var autoOptions = new RequestPipelineOptions(
                autoProfile.Endpoint,
                selectedPayloadLocation,
                null,
                false,
                true,
                contract);
            RequestContractPipeline.Apply(request, autoOptions);
            return;
        }

        var configuredTarget = resolveConfiguredTargetUri();
        if (configuredTarget is null ||
            !isSameOrigin(configuredTarget, request.RequestUri) ||
            !pathsMatchForScope(request.RequestUri, configuredTarget))
        {
            return;
        }

        var automaticProfile = await tryGetAutomaticSingleTargetOperationProfileAsync(configuredTarget);
        var sharedProfile = automaticProfile is null
            ? null
            : new OperationContract(
                automaticProfile.Endpoint,
                automaticProfile.AllowedMethods,
                automaticProfile.QueryParameterNames,
                automaticProfile.BodyPropertyNames,
                automaticProfile.PathParameterNames,
                automaticProfile.QueryParameterTypeHints,
                automaticProfile.BodyPropertyTypeHints,
                automaticProfile.PathParameterTypeHints,
                null);

        var effectiveTarget = automaticProfile?.Endpoint ?? configuredTarget;

        var options = new RequestPipelineOptions(
            effectiveTarget,
            selectedPayloadLocation,
            selectedOperationOverride,
            shouldApplyManualSingleTargetPayloadOverrides,
            automaticProfile is not null && selectedOperationOverride is null,
            sharedProfile);
        RequestContractPipeline.Apply(request, options);
    }

    public static async Task<OpenApiOperationProfile?> TryGetAutomaticSingleTargetOperationProfileAsync(
        Uri configuredTarget,
        bool typeAwareModeEnabled,
        string openApiInputRaw,
        bool openApiRouteScopeSelected,
        bool isSpiderRouteScopeSelected,
        Func<Uri, Task<OpenApiProbeContext>> getOpenApiProbeContextAsync,
        Func<Uri, Uri, bool> isSameOrigin,
        Func<Uri, Uri, bool> pathsMatchForScope)
    {
        if (!typeAwareModeEnabled)
        {
            return null;
        }

        var authorityRoot = new Uri($"{configuredTarget.Scheme}://{configuredTarget.Authority}/");
        var context = await getOpenApiProbeContextAsync(authorityRoot);
        return context.OperationProfiles
            .Where(profile =>
                isSameOrigin(profile.Endpoint, configuredTarget) &&
                pathsMatchForScope(profile.Endpoint, configuredTarget))
            .OrderByDescending(profile => ScoreProfileMatch(profile.Endpoint, configuredTarget))
            .FirstOrDefault();
    }

    private static int ScoreProfileMatch(Uri endpoint, Uri configuredTarget)
    {
        var endpointPath = RequestContractPipeline.NormalizeComparablePath(endpoint);
        var targetPath = RequestContractPipeline.NormalizeComparablePath(configuredTarget);
        if (endpointPath.Equals(targetPath, StringComparison.OrdinalIgnoreCase))
        {
            return int.MaxValue;
        }

        var endpointSegments = endpointPath.Trim('/')
            .Split('/', StringSplitOptions.RemoveEmptyEntries);
        var targetSegments = targetPath.Trim('/')
            .Split('/', StringSplitOptions.RemoveEmptyEntries);

        var score = 0;
        if (endpointSegments.Length == targetSegments.Length)
        {
            score += 1000;
        }

        var shared = Math.Min(endpointSegments.Length, targetSegments.Length);
        for (var i = 0; i < shared; i++)
        {
            if (string.Equals(endpointSegments[i], targetSegments[i], StringComparison.OrdinalIgnoreCase))
            {
                score += 100;
            }
        }

        score -= Math.Abs(endpointSegments.Length - targetSegments.Length) * 10;
        return score;
    }
}
