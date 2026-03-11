using API_Tester.SecurityCatalog;

namespace ApiTester.Core;

public enum HeadlessRunAction
{
    RunEverything,
    RunAllFrameworks,
    RunMaximumCoverage,
    SpiderSite,
    ValidationHarness,
    PagingSelfTest
}

public static class HeadlessWorkflowUtilities
{
    public static HeadlessRunAction ResolveHeadlessRunAction(string? requestedAction)
    {
        var action = string.IsNullOrWhiteSpace(requestedAction) ? "run-everything" : requestedAction.Trim();
        return action.ToLowerInvariant() switch
        {
            "run-all" or "all-frameworks" => HeadlessRunAction.RunAllFrameworks,
            "run-max" or "max-coverage" or "maximum-coverage" => HeadlessRunAction.RunMaximumCoverage,
            "spider" or "spider-site" => HeadlessRunAction.SpiderSite,
            "validation" or "validation-harness" or "validation-sequence" => HeadlessRunAction.ValidationHarness,
            "paging" or "paging-selftest" => HeadlessRunAction.PagingSelfTest,
            _ => HeadlessRunAction.RunEverything
        };
    }

    public static async Task<string?> EmitHeadlessReportAsync(bool headlessEnabled, string prefix, string report)
    {
        if (!headlessEnabled)
        {
            return null;
        }

        Console.WriteLine(report);

        try
        {
            var logsDir = Path.Combine(CveCorpusService.GetCacheDirectoryPath(), "logs");
            Directory.CreateDirectory(logsDir);
            var fileName = $"{prefix}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.txt";
            var path = Path.Combine(logsDir, fileName);
            await File.WriteAllTextAsync(path, report);
            Console.WriteLine($"[Headless] Report saved: {path}");
            return path;
        }
        catch
        {
            // Best effort logging only.
            return null;
        }
    }
}
