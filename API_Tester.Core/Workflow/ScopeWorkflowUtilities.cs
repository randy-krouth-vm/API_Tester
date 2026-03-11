using System.Text;

namespace ApiTester.Core;

public static class ScopeWorkflowUtilities
{
    public static async Task<IReadOnlyList<Uri>> ResolveScopeTargetsAsync(
        Uri baseUri,
        bool openApiRouteScopeSelected,
        bool spiderRouteScopeSelected,
        Func<Uri, Task<OpenApiProbeContext>> getOpenApiProbeContextAsync,
        Func<Uri, Task<SpiderResult>> crawlSiteAsync)
    {
        if (openApiRouteScopeSelected)
        {
            var context = await getOpenApiProbeContextAsync(baseUri);
            var openApiTargets = context.TargetEndpoints
                .Where(u => DiscoveryUtilities.IsSameOrigin(baseUri, u))
                .DistinctBy(DiscoveryUtilities.NormalizeEndpointKey)
                .OrderBy(u => u.AbsolutePath, StringComparer.OrdinalIgnoreCase)
                .ThenBy(u => u.Query, StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (openApiTargets.Count == 0)
            {
                openApiTargets.Add(baseUri);
            }

            return openApiTargets;
        }

        if (!spiderRouteScopeSelected)
        {
            return new[] { baseUri };
        }

        var crawl = await crawlSiteAsync(baseUri);
        var openApiContext = await getOpenApiProbeContextAsync(baseUri);
        var targets = crawl.DiscoveredEndpoints
            .Select(e => Uri.TryCreate(e, UriKind.Absolute, out var parsed) ? parsed : null)
            .Where(u => u is not null)
            .Select(u => u!)
            .Where(u => DiscoveryUtilities.IsSameOrigin(baseUri, u))
            .DistinctBy(DiscoveryUtilities.NormalizeEndpointKey)
            .OrderBy(u => u.AbsolutePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(u => u.Query, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (openApiContext.TargetEndpoints.Count > 0)
        {
            targets.AddRange(openApiContext.TargetEndpoints
                .Where(u => DiscoveryUtilities.IsSameOrigin(baseUri, u)));
            targets = targets
                .DistinctBy(DiscoveryUtilities.NormalizeEndpointKey)
                .OrderBy(u => u.AbsolutePath, StringComparer.OrdinalIgnoreCase)
                .ThenBy(u => u.Query, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        if (targets.Count == 0)
        {
            targets.Add(baseUri);
        }

        return targets;
    }

    public static async Task<string> RunSpiderRouteHitPassAsync(
        Uri baseUri,
        IEnumerable<string> discoveredEndpoints,
        Func<Func<HttpRequestMessage>, Task<HttpResponseMessage?>> safeSendAsync,
        Func<HttpResponseMessage?, string> formatStatus,
        Func<Uri, string> tryGetRoutePathKey)
    {
        var endpointUris = discoveredEndpoints
            .Select(e => Uri.TryCreate(e, UriKind.Absolute, out var parsed) ? parsed : null)
            .Where(u => u is not null)
            .Select(u => u!)
            .Where(u => DiscoveryUtilities.IsSameOrigin(baseUri, u))
            .OrderBy(u => u.AbsolutePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(u => u.Query, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var uniquePaths = endpointUris
            .Select(tryGetRoutePathKey)
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        var hitLines = new List<string>();
        var ok = 0;
        var failed = 0;

        foreach (var endpoint in endpointUris)
        {
            var response = await safeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, endpoint));
            var status = formatStatus(response);
            hitLines.Add($"{endpoint}: {status}");

            if (response is not null && (int)response.StatusCode is >= 200 and < 500)
            {
                ok++;
            }
            else
            {
                failed++;
            }
        }

        var sb = new StringBuilder();
        sb.AppendLine("[Spider Route Hit Pass]");
        sb.AppendLine($"Routes targeted: {endpointUris.Count}");
        sb.AppendLine($"Unique route paths targeted: {uniquePaths}");
        sb.AppendLine($"Reachable responses (2xx-4xx): {ok}");
        sb.AppendLine($"Unreachable/timeouts/5xx: {failed}");
        sb.AppendLine("Route hit results:");
        foreach (var line in hitLines)
        {
            sb.AppendLine($"- {line}");
        }

        if (endpointUris.Count == 0)
        {
            sb.AppendLine("- No routes available to hit.");
        }

        return sb.ToString().TrimEnd();
    }
}
