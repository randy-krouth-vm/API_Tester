using System.Text;
using System.Text.RegularExpressions;
using API_Tester.SecurityCatalog;

namespace ApiTester.Core;

public static class CoverageWorkflowUtilities
{
    public static async Task<string> RunSiteSpiderAndCoverageAsync(
        Uri baseUri,
        Func<Uri, Task<SpiderResult>> crawlSiteAsync,
        Func<IEnumerable<string>, List<string>> buildSpiderCoverageHints)
    {
        var crawl = await crawlSiteAsync(baseUri);
        var hints = buildSpiderCoverageHints(crawl.DiscoveredEndpoints);
        var sb = new StringBuilder();
        sb.AppendLine("[Site Spider + Coverage]");
        sb.AppendLine($"Target: {baseUri}");
        sb.AppendLine($"Visited pages: {crawl.Visited.Count}");
        sb.AppendLine($"Discovered endpoints: {crawl.DiscoveredEndpoints.Count}");
        sb.AppendLine($"Failures: {crawl.Failures.Count}");
        sb.AppendLine();
        sb.AppendLine("Coverage hints from discovered routes:");
        foreach (var hint in hints)
        {
            sb.AppendLine($"- {hint}");
        }

        if (hints.Count == 0)
        {
            sb.AppendLine("- No technology-specific hints detected; run core suites for baseline coverage.");
        }

        sb.AppendLine();
        sb.AppendLine("Discovered endpoints:");
        foreach (var endpoint in crawl.DiscoveredEndpoints.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))
        {
            sb.AppendLine($"- {endpoint}");
        }

        if (crawl.DiscoveredEndpoints.Count == 0)
        {
            sb.AppendLine("- No endpoints discovered.");
        }

        return sb.ToString().TrimEnd();
    }

    public static async Task<string> RunMaximumCoverageAssessmentAsync(
        Uri baseUri,
        Func<Uri, Task<string>> buildStaticCoverageSectionAsync,
        Func<Uri, Task<SpiderResult>> crawlSiteAsync,
        Func<IEnumerable<string>, List<string>> buildSpiderCoverageHints,
        Func<IReadOnlyList<DynamicProbe>> getDynamicProbes,
        Func<Uri, IEnumerable<string>, IProgress<string>?, Task<string>> runAdaptiveEndpointSweepAsync,
        IProgress<string>? progress = null)
    {
        progress?.Report("Static analysis: loading catalog and probing OpenAPI...");
        var staticSection = await buildStaticCoverageSectionAsync(baseUri);

        progress?.Report("Dynamic discovery: spidering API surface...");
        var crawl = await crawlSiteAsync(baseUri);
        var hints = buildSpiderCoverageHints(crawl.DiscoveredEndpoints);

        var probes = getDynamicProbes();
        var reports = new List<string>(probes.Count);
        var executed = 0;

        foreach (var probe in probes)
        {
            executed++;
            progress?.Report($"Dynamic probes: {executed}/{probes.Count} - {probe.Name}");
            try
            {
                reports.Add(await probe.Execute(baseUri));
            }
            catch (Exception ex)
            {
                reports.Add($"[{probe.Name}]{Environment.NewLine}Target: {baseUri}{Environment.NewLine}- Execution error: {ex.Message}");
            }
        }

        if (!probes.Any(p => p.Name.Equals("RunManualPayloadDirectRequestsAsync", StringComparison.Ordinal)))
        {
            reports.Add("[Manual Payload Direct Requests]\n- Manual payload direct-request probe not available.");
        }

        progress?.Report("Adaptive sweep: running lightweight checks across discovered endpoints...");
        var adaptiveSweep = await runAdaptiveEndpointSweepAsync(baseUri, crawl.DiscoveredEndpoints, progress);

        var potentialRiskSignals = reports.Sum(r => Regex.Matches(r, "Potential risk:", RegexOptions.IgnoreCase).Count);
        var noResponseSignals = reports.Sum(r => Regex.Matches(r, "No response", RegexOptions.IgnoreCase).Count);

        var sb = new StringBuilder();
        sb.AppendLine("=== Maximum Static + Dynamic Coverage Assessment ===");
        sb.AppendLine($"Target: {baseUri}");
        sb.AppendLine($"Timestamp (UTC): {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine();
        sb.AppendLine(staticSection);
        sb.AppendLine();
        sb.AppendLine("[Dynamic Discovery]");
        sb.AppendLine($"Visited pages: {crawl.Visited.Count}");
        sb.AppendLine($"Discovered endpoints: {crawl.DiscoveredEndpoints.Count}");
        sb.AppendLine($"Discovery failures: {crawl.Failures.Count}");
        sb.AppendLine("Coverage hints:");
        foreach (var hint in hints)
        {
            sb.AppendLine($"- {hint}");
        }

        if (hints.Count == 0)
        {
            sb.AppendLine("- No technology-specific hints detected.");
        }

        sb.AppendLine();
        sb.AppendLine("[Dynamic Probe Execution]");
        sb.AppendLine($"Probes executed: {reports.Count}");
        sb.AppendLine($"Potential-risk signals found: {potentialRiskSignals}");
        sb.AppendLine($"No-response signals found: {noResponseSignals}");
        sb.AppendLine();
        sb.AppendLine(adaptiveSweep);
        sb.AppendLine();
        sb.Append(string.Join($"{Environment.NewLine}{Environment.NewLine}", reports));

        return sb.ToString().TrimEnd();
    }

    public static async Task<string> BuildStaticCoverageSectionAsync(
        Uri baseUri,
        Func<Uri, Task<OpenApiSnapshot?>> tryFetchOpenApiSnapshotAsync)
    {
        var sb = new StringBuilder();
        sb.AppendLine("[Static Coverage]");

        var catalog = await SecurityCatalogLoader.LoadAsync();
        if (catalog is null)
        {
            sb.AppendLine("- Dynamic catalog: unavailable.");
        }
        else
        {
            var categoryCount = catalog.Categories?.Count ?? 0;
            var testCount = catalog.Categories?.Sum(c => c.Tests?.Count ?? 0) ?? 0;
            sb.AppendLine($"- Dynamic catalog categories: {categoryCount}");
            sb.AppendLine($"- Dynamic catalog tests: {testCount}");
        }

        var openApi = await tryFetchOpenApiSnapshotAsync(baseUri);
        if (openApi is null)
        {
            sb.AppendLine("- OpenAPI static analysis: no OpenAPI document discovered.");
            return sb.ToString().TrimEnd();
        }

        sb.AppendLine($"- OpenAPI source: {openApi.SourceUri}");
        var summary = OpenApiProbeAnalyzer.AnalyzeDocumentSummary(openApi.Document);
        sb.AppendLine($"- OpenAPI paths: {summary.PathCount}");
        sb.AppendLine($"- OpenAPI operations: {summary.OperationCount}");
        sb.AppendLine($"- Operations with explicit security: {summary.SecuredOperationCount}");
        sb.AppendLine($"- Operations without explicit security: {summary.UnsecuredOperationCount}");
        sb.AppendLine($"- Schema objects: {summary.SchemaCount}");
        openApi.Document.Dispose();

        return sb.ToString().TrimEnd();
    }
}
