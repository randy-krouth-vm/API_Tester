namespace ApiTester.Core;

public sealed record ResolvedNamedSuiteRun(string Name, Func<Uri, Task<string>>[] Tests);

public static class RunOrchestrationWorkflowUtilities
{
    public static async Task<string> BuildRunAllFrameworksReportAsync(
        Uri uri,
        IEnumerable<(string CategoryName, string[] Frameworks, Func<Uri, Task<string>>[] Tests)> standardFrameworkPacks,
        Func<string, IReadOnlyList<string>, Uri, IReadOnlyList<Func<Uri, Task<string>>>, Task<string>> buildControlDrivenFrameworkPackReportAsync,
        bool spiderRouteScopeSelected,
        Func<Uri, Task<SpiderResult>> crawlSiteAsync,
        Func<SpiderResult, string> buildRouteDiscoverySummary,
        Func<Uri, IEnumerable<string>, Task<string>> runSpiderRouteHitPassAsync,
        Func<Uri, IEnumerable<string>, Task<string>> runAdaptiveEndpointSweepAsync)
    {
        var reports = new List<string>();
        foreach (var pack in standardFrameworkPacks)
        {
            reports.Add(await buildControlDrivenFrameworkPackReportAsync(
                pack.CategoryName,
                pack.Frameworks,
                uri,
                pack.Tests));
        }

        if (spiderRouteScopeSelected)
        {
            var crawl = await crawlSiteAsync(uri);
            reports.Add(buildRouteDiscoverySummary(crawl));
            reports.Add(await runSpiderRouteHitPassAsync(uri, crawl.DiscoveredEndpoints));
            reports.Add(await runAdaptiveEndpointSweepAsync(uri, crawl.DiscoveredEndpoints));
        }
        else
        {
            reports.Add("[Route Scope]\n- Single target mode selected. Spider route sweep skipped.");
        }

        return string.Join($"{Environment.NewLine}{Environment.NewLine}", reports);
    }

    public static async Task<string> BuildRunEverythingReportAsync(
        Uri uri,
        IEnumerable<(string CategoryName, string[] Frameworks, Func<Uri, Task<string>>[] Tests)> standardFrameworkPacks,
        IEnumerable<string> namedSuiteKeys,
        Func<string, ResolvedNamedSuiteRun?> tryGetNamedSuite,
        Func<string, IReadOnlyList<string>, Uri, IReadOnlyList<Func<Uri, Task<string>>>, Task<string>> buildControlDrivenFrameworkPackReportAsync,
        Func<Uri, HashSet<string>, Task<string>> buildRemainingAdvancedProbeReportAsync,
        bool spiderRouteScopeSelected,
        Func<Uri, Task<SpiderResult>> crawlSiteAsync,
        Func<SpiderResult, string> buildRouteDiscoverySummary,
        Func<Uri, IEnumerable<string>, Task<string>> runSpiderRouteHitPassAsync,
        Func<Uri, IEnumerable<string>, Task<string>> runAdaptiveEndpointSweepAsync)
    {
        var reports = new List<string>();
        var executed = new HashSet<string>(StringComparer.Ordinal);

        foreach (var pack in standardFrameworkPacks)
        {
            foreach (var test in pack.Tests)
            {
                executed.Add(test.Method.Name);
            }

            reports.Add(await buildControlDrivenFrameworkPackReportAsync(
                pack.CategoryName,
                pack.Frameworks,
                uri,
                pack.Tests));
        }

        foreach (var suiteKey in namedSuiteKeys)
        {
            var suite = tryGetNamedSuite(suiteKey);
            if (suite is null)
            {
                continue;
            }

            foreach (var test in suite.Tests)
            {
                executed.Add(test.Method.Name);
            }

            reports.Add(await buildControlDrivenFrameworkPackReportAsync(
                "10) Domain Security Suites",
                new[] { suite.Name, $"Method count: {suite.Tests.Length}" },
                uri,
                suite.Tests));
        }

        reports.Add(await buildRemainingAdvancedProbeReportAsync(uri, executed));
        if (spiderRouteScopeSelected)
        {
            var crawl = await crawlSiteAsync(uri);
            reports.Add(buildRouteDiscoverySummary(crawl));
            reports.Add(await runSpiderRouteHitPassAsync(uri, crawl.DiscoveredEndpoints));
            reports.Add(await runAdaptiveEndpointSweepAsync(uri, crawl.DiscoveredEndpoints));
        }
        else
        {
            reports.Add("[Route Scope]\n- Single target mode selected. Spider route sweep skipped.");
        }

        return string.Join($"{Environment.NewLine}{Environment.NewLine}", reports);
    }
}
