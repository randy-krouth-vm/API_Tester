using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using ApiTester.Core;
using ApiTester.Shared;
using API_Tester;

try
{
    var argsMap = ParseArgs(args);
    if (args.Length == 0 || HasFlag(argsMap, "help") || HasFlag(argsMap, "h"))
    {
        Console.WriteLine(BuildHelpText());
        return 0;
    }

    if (HasFlag(argsMap, "paging-selftest"))
    {
        var pageSize = TryGetValue(argsMap, "page-size", out var pageSizeRaw) && int.TryParse(pageSizeRaw, out var parsedPageSize)
            ? Math.Clamp(parsedPageSize, 1, 50_000)
            : 250;

        var cacheDir = ResolveDefaultCacheDirectory();
        var corpusPath = TryGetValue(argsMap, "corpus-file", out var corpusRaw)
            ? Path.GetFullPath(corpusRaw)
            : Path.Combine(cacheDir, "cve-corpus.ndjson");
        var functionMapPath = TryGetValue(argsMap, "function-map-file", out var mapRaw)
            ? Path.GetFullPath(mapRaw)
            : Path.Combine(cacheDir, "cve-function-map.ndjson");

        var selfTestReport = await RunPagingSelfTestAsync(corpusPath, functionMapPath, pageSize);
        var outputFormat = TryGetValue(argsMap, "output", out var outputRawForSelfTest) ? outputRawForSelfTest : "txt";
        var selfTestRendered = RenderPagingSelfTest(selfTestReport, outputFormat);

        var selfTestFileOnly = HasFlag(argsMap, "file-only");
        var selfTestHasOutPath = TryGetValue(argsMap, "out", out var selfTestOutPath);
        if (!selfTestFileOnly)
        {
            Console.Write(selfTestRendered);
        }

        if (selfTestHasOutPath)
        {
            var fullPath = Path.GetFullPath(selfTestOutPath);
            var dir = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }

            File.WriteAllText(fullPath, selfTestRendered, Encoding.UTF8);
            if (!selfTestFileOnly)
            {
                Console.WriteLine();
            }
            Console.Error.WriteLine($"[HEADLESS] Output file: {fullPath}");
        }

        return selfTestReport.AllChecksPass ? 0 : 5;
    }

    if (!TryGetValue(argsMap, "target", out var targetRaw) || !Uri.TryCreate(targetRaw, UriKind.Absolute, out var target))
    {
        WriteError("Missing/invalid required argument: --target <http(s)://...>");
        return 2;
    }

    var scope = TryGetValue(argsMap, "scope", out var scopeRaw) ? scopeRaw : "single";
    var output = TryGetValue(argsMap, "output", out var outputRaw) ? outputRaw : "txt";
    var resultFilter = TryGetValue(argsMap, "result-filter", out var filterRaw) ? filterRaw : "failed";
    var suite = TryGetValue(argsMap, "suite", out var suiteRaw) ? suiteRaw : string.Empty;
    var framework = TryGetValue(argsMap, "framework", out var frameworkRaw)
        ? frameworkRaw
        : (string.IsNullOrWhiteSpace(suite) ? "(all)" : string.Empty);
    var crawlOnly = HasFlag(argsMap, "crawl-only") || HasFlag(argsMap, "spider-only");
    var fileOnly = HasFlag(argsMap, "file-only");
    var hasOutPath = TryGetValue(argsMap, "out", out var outPath);

    if (fileOnly && !hasOutPath)
    {
        WriteError("--file-only requires --out <path>.");
        return 2;
    }

    var openApiSource = TryGetValue(argsMap, "openapi", out var openApiRaw) ? openApiRaw : string.Empty;
    var methodOverride = TryGetValue(argsMap, "method", out var methodRaw) ? methodRaw : "auto";
    var payloadLocation = TryGetValue(argsMap, "payload-location", out var payloadLocationRaw) ? payloadLocationRaw : "auto";
    var httpTrace = HasFlag(argsMap, "http-trace");
    if (crawlOnly)
    {
        var targets = await HeadlessScanEngine.ResolveTargetsForCliAsync(target, scope, openApiSource);
        var renderedTargets = RenderTargets(targets, output);

        if (!fileOnly)
        {
            Console.Write(renderedTargets);
        }

        if (hasOutPath)
        {
            var fullPath = Path.GetFullPath(outPath);
            var dir = Path.GetDirectoryName(fullPath);
            if (!string.IsNullOrWhiteSpace(dir))
            {
                Directory.CreateDirectory(dir);
            }

            File.WriteAllText(fullPath, renderedTargets, Encoding.UTF8);
            if (!fileOnly)
            {
                Console.WriteLine();
            }
            Console.Error.WriteLine($"[HEADLESS] Output file: {fullPath}");
        }

        return 0;
    }

    var options = new ScanOptions(target, scope, output, resultFilter, framework, suite, openApiSource, !fileOnly, methodOverride, payloadLocation, httpTrace);
    var report = await HeadlessScanEngine.RunAsync(options);
    var rendered = RenderReport(report, options, ApplyFilter(report.Findings, options.ResultFilter));

    if (!fileOnly)
    {
        Console.Write(rendered);
    }

    if (hasOutPath)
    {
        var fullPath = Path.GetFullPath(outPath);
        var dir = Path.GetDirectoryName(fullPath);
        if (!string.IsNullOrWhiteSpace(dir))
        {
            Directory.CreateDirectory(dir);
        }

        File.WriteAllText(fullPath, rendered, Encoding.UTF8);
        if (!fileOnly)
        {
            Console.WriteLine();
        }
        Console.Error.WriteLine($"[HEADLESS] Output file: {fullPath}");
    }

    var hasFail = report.Findings.Any(f => f.Verdict.Equals("fail", StringComparison.OrdinalIgnoreCase));
    var hasAny = report.Findings.Count > 0;
    var allInconclusive = hasAny && report.Findings.All(f => f.Verdict.Equals("inconclusive", StringComparison.OrdinalIgnoreCase));
    if (hasFail)
    {
        return 3;
    }

    // Treat all-inconclusive/no-findings runs as non-success in CI pipelines.
    if (!hasAny || allInconclusive)
    {
        return 4;
    }

    return 0;
}
catch (Exception ex)
{
    WriteError("Headless run failed.");
    WriteError($"{ex.GetType().Name}: {ex.Message}");
    if (!string.IsNullOrWhiteSpace(ex.StackTrace))
    {
        WriteError("Stack trace:");
        foreach (var line in ex.StackTrace.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None))
        {
            if (!string.IsNullOrWhiteSpace(line))
            {
                WriteError(line.TrimEnd());
            }
        }
    }
    return 1;
}

static string RenderReport(HeadlessReport report, ScanOptions options, List<Finding> displayFindings)
{
    var displayReport = report with { Findings = displayFindings };
    return options.Output.ToLowerInvariant() switch
    {
        "json" => JsonSerializer.Serialize(displayReport, new JsonSerializerOptions { WriteIndented = true }),
        "md" => RenderMarkdown(displayReport),
        _ => RenderText(displayReport)
    };
}

static string RenderTargets(IReadOnlyList<Uri> targets, string output)
{
    return output.ToLowerInvariant() switch
    {
        "json" => JsonSerializer.Serialize(targets.Select(t => t.ToString()).ToArray(), new JsonSerializerOptions { WriteIndented = true }),
        "md" => RenderTargetsMarkdown(targets),
        _ => RenderTargetsText(targets)
    };
}

static string RenderTargetsText(IReadOnlyList<Uri> targets)
{
    var sb = new StringBuilder();
    sb.AppendLine("[API_Tester.Headless] Discovered Targets");
    foreach (var target in targets)
    {
        sb.AppendLine(target.ToString());
    }
    return sb.ToString();
}

static string RenderTargetsMarkdown(IReadOnlyList<Uri> targets)
{
    var sb = new StringBuilder();
    sb.AppendLine("# API_Tester.Headless Discovered Targets");
    sb.AppendLine();
    foreach (var target in targets)
    {
        sb.AppendLine($"- `{target}`");
    }
    return sb.ToString();
}

static string RenderText(HeadlessReport report)
{
    var sb = new StringBuilder();
    sb.AppendLine("[API_Tester.Headless]");
    sb.AppendLine($"  target       : {report.Target}");
    sb.AppendLine($"  scope        : {report.Scope}");
    sb.AppendLine($"  framework    : {report.Framework}");
    sb.AppendLine($"  started_utc  : {report.StartedUtc:O}");
    sb.AppendLine($"  finished_utc : {report.FinishedUtc:O}");
    sb.AppendLine($"  targets      : {report.TargetsScanned}");
    sb.AppendLine();
    var failCount = report.Findings.Count(f => f.Verdict == "fail");
    var passCount = report.Findings.Count(f => f.Verdict == "pass");
    var inconclusiveCount = report.Findings.Count(f => f.Verdict == "inconclusive");
    sb.AppendLine("Summary:");
    sb.AppendLine($"  fail: {failCount}");
    sb.AppendLine($"  pass: {passCount}");
    sb.AppendLine($"  inconclusive: {inconclusiveCount}");
    sb.AppendLine();
    sb.AppendLine("Findings:");
    foreach (var f in report.Findings)
    {
        sb.AppendLine($"- [{f.Verdict}] {f.TestName} @ {f.Target}");
        sb.AppendLine($"    {f.Summary}");
    }
    return sb.ToString();
}

static string RenderMarkdown(HeadlessReport report)
{
    var sb = new StringBuilder();
    sb.AppendLine("# API_Tester.Headless Report");
    sb.AppendLine();
    sb.AppendLine($"- Target: `{report.Target}`");
    sb.AppendLine($"- Scope: `{report.Scope}`");
    sb.AppendLine($"- Framework: `{report.Framework}`");
    sb.AppendLine($"- Started (UTC): `{report.StartedUtc:O}`");
    sb.AppendLine($"- Finished (UTC): `{report.FinishedUtc:O}`");
    sb.AppendLine();
    sb.AppendLine("| Verdict | Test | Target | Summary |");
    sb.AppendLine("|---|---|---|---|");
    foreach (var f in report.Findings)
    {
        sb.AppendLine($"| {f.Verdict} | {f.TestName} | {f.Target} | {f.Summary.Replace("|", "/")} |");
    }
    return sb.ToString();
}

static List<Finding> ApplyFilter(List<Finding> findings, string filter)
{
    var normalized = (filter ?? "failed").Trim().ToLowerInvariant();
    return normalized switch
    {
        "all" => findings,
        "passed" => findings.Where(f => f.Verdict == "pass").ToList(),
        _ => findings.Where(f => f.Verdict == "fail").ToList()
    };
}

static Dictionary<string, string?> ParseArgs(string[] args)
{
    var map = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
    for (var i = 0; i < args.Length; i++)
    {
        var token = args[i];
        if (!token.StartsWith('-'))
        {
            continue;
        }

        var trimmed = token.TrimStart('-');
        var split = trimmed.Split('=', 2, StringSplitOptions.TrimEntries);
        if (split.Length == 2)
        {
            map[split[0]] = split[1];
            continue;
        }

        if (i + 1 < args.Length && !args[i + 1].StartsWith('-'))
        {
            map[split[0]] = args[++i];
        }
        else
        {
            map[split[0]] = "true";
        }
    }
    return map;
}

static bool HasFlag(IReadOnlyDictionary<string, string?> map, string key)
{
    return map.TryGetValue(key, out var raw) &&
           (string.IsNullOrWhiteSpace(raw) ||
            string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase));
}

static bool TryGetValue(IReadOnlyDictionary<string, string?> map, string key, out string value)
{
    if (map.TryGetValue(key, out var raw) && !string.IsNullOrWhiteSpace(raw))
    {
        value = raw.Trim();
        return true;
    }

    value = string.Empty;
    return false;
}

static string BuildHelpText()
{
    var sb = new StringBuilder();
    sb.AppendLine("API_Tester.Headless");
    sb.AppendLine("Headless runner for API_Tester scan workflows.");
    sb.AppendLine();
    sb.AppendLine("Usage:");
    sb.AppendLine("  API_Tester.Headless --target <url> [options]");
    sb.AppendLine();
    sb.AppendLine("Required:");
    sb.AppendLine("  --target <url>                Base API URL (http/https).");
    sb.AppendLine();
    sb.AppendLine("Options:");
    sb.AppendLine("  --scope <single|spider|openapi>");
    sb.AppendLine("                                Scan scope. Default: single.");
    sb.AppendLine("  --openapi <path-or-url>       Optional OpenAPI source for openapi scope.");
    sb.AppendLine("  --framework <name>            Optional framework filter.");
    sb.AppendLine("  --suite <key[,key...]>        Optional named suite filter (e.g. SUITE_AUTHZ).");
    sb.AppendLine("  --payload-location <auto|query|path|body|header|cookie>");
    sb.AppendLine("                                Payload placement strategy. Default: auto.");
    sb.AppendLine("  --output <txt|json|md>        Output format. Default: txt.");
    sb.AppendLine("  --result-filter <failed|passed|all>");
    sb.AppendLine("                                Result visibility. Default: failed.");
    sb.AppendLine("  --crawl-only                  Discover targets only; do not run tests.");
    sb.AppendLine("  --spider-only                 Alias for --crawl-only.");
    sb.AppendLine("  --out <path>                  Write output to file.");
    sb.AppendLine("  --file-only                   Do not print to console (requires --out).");
    sb.AppendLine("  --paging-selftest             Validate corpus/function-map in-memory paging slices.");
    sb.AppendLine("  --page-size <n>               Page size for paging self-test. Default: 250.");
    sb.AppendLine("  --corpus-file <path>          Optional corpus file path for paging self-test.");
    sb.AppendLine("  --function-map-file <path>    Optional function-map file path for paging self-test.");
    sb.AppendLine("  --help, -h                    Show this help.");
    sb.AppendLine();
    sb.AppendLine("Operational notes:");
    sb.AppendLine("  - single scope: base target only.");
    sb.AppendLine("  - spider scope: same-origin route discovery and route-level execution.");
    sb.AppendLine("  - openapi scope: endpoints parsed from an OpenAPI spec.");
    sb.AppendLine("  - result-filter controls visibility only, not execution.");
    sb.AppendLine("  - crawl-only uses scope to resolve targets and prints the list.");
    sb.AppendLine();
    sb.AppendLine("Examples:");
    sb.AppendLine("  API_Tester.Headless --target https://api.example.com");
    sb.AppendLine("  API_Tester.Headless --target https://api.example.com --scope spider --result-filter all");
    sb.AppendLine("  API_Tester.Headless --target https://api.example.com --scope openapi --openapi ./openapi.json");
    sb.AppendLine("  API_Tester.Headless --target https://api.example.com --framework \"OWASP API Security Top 10\" --output json");
    sb.AppendLine("  API_Tester.Headless --target https://api.example.com --suite SUITE_AUTHZ,SUITE_INJECTION");
    sb.AppendLine("  API_Tester.Headless --target https://api.example.com --scope spider --crawl-only");
    sb.AppendLine("  API_Tester.Headless --paging-selftest --output txt");
    return sb.ToString();
}

static void WriteError(string message)
{
    var previous = Console.ForegroundColor;
    Console.ForegroundColor = ConsoleColor.Red;
    Console.Error.WriteLine(message);
    Console.ForegroundColor = previous;
}

static async Task<PagingSelfTestReport> RunPagingSelfTestAsync(string corpusPath, string functionMapPath, int pageSize)
{
    var started = DateTime.UtcNow;
    var corpus = await LoadPagingDataSetAsync("corpus", corpusPath, pageSize);
    var functionMap = await LoadPagingDataSetAsync("function-map", functionMapPath, pageSize);

    var checks = new List<PagingCheckResult>
    {
        new("corpus-page1-size", corpus.Exists && (corpus.TotalRows < pageSize || corpus.Page1Rows == pageSize)),
        new("corpus-page2-start", corpus.Exists && (corpus.TotalRows <= pageSize || corpus.Page2Start == pageSize)),
        new("corpus-last-slice-range", corpus.Exists && corpus.LastStart >= 0 && corpus.LastEndExclusive <= corpus.TotalRows),
        new("function-map-page1-size", functionMap.Exists && (functionMap.TotalRows < pageSize || functionMap.Page1Rows == pageSize)),
        new("function-map-page2-start", functionMap.Exists && (functionMap.TotalRows <= pageSize || functionMap.Page2Start == pageSize)),
        new("function-map-last-slice-range", functionMap.Exists && functionMap.LastStart >= 0 && functionMap.LastEndExclusive <= functionMap.TotalRows)
    };

    var allChecksPass = checks.Where(c => c.Applies).All(c => c.Pass);
    return new PagingSelfTestReport(started, DateTime.UtcNow, pageSize, corpus, functionMap, checks, allChecksPass);
}

static async Task<PagingDataSetResult> LoadPagingDataSetAsync(string name, string path, int pageSize)
{
    if (!File.Exists(path))
    {
        return new PagingDataSetResult(name, path, false, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    var rows = await Task.Run(() => File.ReadLines(path).Where(l => !string.IsNullOrWhiteSpace(l)).ToArray());
    var total = rows.Length;
    var totalPages = Math.Max(1, (int)Math.Ceiling(total / (double)pageSize));
    var page1Rows = Math.Min(pageSize, total);
    var page2Start = total > pageSize ? pageSize : 0;
    var page2Rows = total > pageSize ? Math.Min(pageSize, total - page2Start) : 0;
    var lastStart = total == 0 ? 0 : (totalPages - 1) * pageSize;
    var lastEndExclusive = total;
    var lastRows = total == 0 ? 0 : total - lastStart;
    return new PagingDataSetResult(name, path, true, total, totalPages, page1Rows, page2Start, page2Rows, lastStart, lastEndExclusive, lastRows);
}

static string RenderPagingSelfTest(PagingSelfTestReport report, string output)
{
    if (string.Equals(output, "json", StringComparison.OrdinalIgnoreCase))
    {
        return JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
    }

    var sb = new StringBuilder();
    sb.AppendLine("[API_Tester.Headless Paging Self-Test]");
    sb.AppendLine($"started_utc  : {report.StartedUtc:O}");
    sb.AppendLine($"finished_utc : {report.FinishedUtc:O}");
    sb.AppendLine($"page_size    : {report.PageSize}");
    sb.AppendLine();
    AppendDataSet(sb, report.Corpus);
    sb.AppendLine();
    AppendDataSet(sb, report.FunctionMap);
    sb.AppendLine();
    sb.AppendLine("Checks:");
    foreach (var check in report.Checks)
    {
        var status = !check.Applies ? "SKIP" : check.Pass ? "PASS" : "FAIL";
        sb.AppendLine($"- {status}: {check.Name}");
    }
    sb.AppendLine();
    sb.AppendLine($"overall: {(report.AllChecksPass ? "PASS" : "FAIL")}");
    return sb.ToString().TrimEnd();
}

static void AppendDataSet(StringBuilder sb, PagingDataSetResult ds)
{
    sb.AppendLine($"{ds.Name}:");
    sb.AppendLine($"  path          : {ds.Path}");
    sb.AppendLine($"  exists        : {ds.Exists}");
    if (!ds.Exists)
    {
        return;
    }

    sb.AppendLine($"  total_rows    : {ds.TotalRows}");
    sb.AppendLine($"  total_pages   : {ds.TotalPages}");
    sb.AppendLine($"  page1_slice   : [0, {ds.Page1Rows})");
    sb.AppendLine($"  page2_slice   : [{ds.Page2Start}, {ds.Page2Start + ds.Page2Rows})");
    sb.AppendLine($"  last_slice    : [{ds.LastStart}, {ds.LastEndExclusive})");
    sb.AppendLine($"  last_rows     : {ds.LastRows}");
}

static string ResolveDefaultCacheDirectory()
{
    var baseDir = new DirectoryInfo(AppContext.BaseDirectory);
    var current = baseDir;
    for (var i = 0; i < 12 && current is not null; i++)
    {
        var solutionPath = Path.Combine(current.FullName, "API_Tester.slnx");
        if (File.Exists(solutionPath))
        {
            return Path.Combine(current.FullName, "cache");
        }

        current = current.Parent;
    }

    return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "API_Tester", "cache");
}

internal sealed record PagingDataSetResult(
    string Name,
    string Path,
    bool Exists,
    int TotalRows,
    int TotalPages,
    int Page1Rows,
    int Page2Start,
    int Page2Rows,
    int LastStart,
    int LastEndExclusive,
    int LastRows);

internal sealed record PagingCheckResult(string Name, bool Pass, bool Applies = true);

internal sealed record PagingSelfTestReport(
    DateTime StartedUtc,
    DateTime FinishedUtc,
    int PageSize,
    PagingDataSetResult Corpus,
    PagingDataSetResult FunctionMap,
    List<PagingCheckResult> Checks,
    bool AllChecksPass);

internal sealed record ScanOptions(
    Uri Target,
    string Scope,
    string Output,
    string ResultFilter,
    string Framework,
    string Suite,
    string OpenApiSource,
    bool StreamLogs,
    string MethodOverride,
    string PayloadLocation,
    bool HttpTrace);

internal sealed record Finding(
    string TestKey,
    string TestName,
    string Target,
    string Verdict,
    string Summary);

internal sealed record HeadlessReport(
    string Target,
    string Scope,
    string Framework,
    DateTime StartedUtc,
    DateTime FinishedUtc,
    int TargetsScanned,
    List<Finding> Findings);

internal enum OpenApiRouteIntent
{
    Unknown,
    Query,
    Path,
    Body,
    Header,
    Cookie,
    Method,
    Combo
}

internal static class HeadlessScanEngine
{
    private static readonly HttpClient Client = new() { Timeout = TimeSpan.FromSeconds(12) };
    private static readonly MainPage CoreTestHost = new();
    private static ScanOptions CurrentOptions = new(new Uri("http://127.0.0.1"), "single", "txt", "failed", "(all)", string.Empty, string.Empty, false, "auto", "query", false);
    private static Uri CurrentConfiguredTarget = new("http://127.0.0.1");
    private static OperationContract? CurrentAutomaticContract;
    private static OpenApiRouteIntent CurrentRouteIntent;
    private static IReadOnlyList<(OperationContract Contract, OpenApiRouteIntent Intent)> CurrentOpenApiContracts =
        Array.Empty<(OperationContract Contract, OpenApiRouteIntent Intent)>();

    public static async Task<IReadOnlyList<Uri>> ResolveTargetsForCliAsync(Uri baseUri, string scope, string openApiSource)
    {
        var targets = await ResolveTargetsAsync(baseUri, scope, openApiSource);
        return targets;
    }

    public static async Task<HeadlessReport> RunAsync(ScanOptions options)
    {
        CurrentOptions = options;
        CurrentConfiguredTarget = options.Target;
        CurrentAutomaticContract = null;
        CurrentRouteIntent = OpenApiRouteIntent.Unknown;
        CurrentOpenApiContracts = Array.Empty<(OperationContract Contract, OpenApiRouteIntent Intent)>();

        var normalizedScope = NormalizeScope(options.Scope);
        CurrentOpenApiContracts = await BuildOpenApiContractIndexAsync(options.Target, options.OpenApiSource);
        if (normalizedScope.Equals("single", StringComparison.OrdinalIgnoreCase) && CurrentOpenApiContracts.Count == 0)
        {
            var resolved = await TryResolveSingleTargetOperationContractAsync(options.Target, options.OpenApiSource);
            CurrentAutomaticContract = resolved.Contract;
            CurrentRouteIntent = resolved.Intent;
        }

        var started = DateTime.UtcNow;
        var targets = await ResolveTargetsAsync(options.Target, options.Scope, options.OpenApiSource);
        var tests = ResolveTests(options.Framework, options.Suite);
        var findings = new List<Finding>();

        if (options.StreamLogs)
        {
            Console.WriteLine($"[HEADLESS] Started: {started:O}");
            Console.WriteLine($"[HEADLESS] Scope={NormalizeScope(options.Scope)} Framework={DescribeExecutionSelection(options.Framework, options.Suite)}");
            Console.WriteLine($"[HEADLESS] Discovered targets={targets.Count}");
            Console.WriteLine($"[HEADLESS] Selected tests={tests.Count}");
        }

        foreach (var target in targets)
        {
            CurrentConfiguredTarget = target;
            var contractMatch = ResolveContractForTarget(target, CurrentOpenApiContracts);
            if (contractMatch is not null)
            {
                CurrentAutomaticContract = contractMatch.Value.Contract;
                CurrentRouteIntent = contractMatch.Value.Intent;
            }
            else if (!normalizedScope.Equals("single", StringComparison.OrdinalIgnoreCase))
            {
                CurrentAutomaticContract = null;
                CurrentRouteIntent = OpenApiRouteIntent.Unknown;
            }

            var targetTests = normalizedScope.Equals("openapi", StringComparison.OrdinalIgnoreCase)
                ? AdaptTestsForSingleTargetOpenApi(tests)
                : tests.ToList();

            if (options.StreamLogs)
            {
                Console.WriteLine($"[TARGET] {target}");
            }

            foreach (var test in targetTests)
            {
                if (options.StreamLogs)
                {
                    Console.WriteLine($"  [RUN] {GetTestName(test)}");
                }

                try
                {
                    var finding = await test(target);
                    findings.Add(finding);
                    if (options.StreamLogs)
                    {
                        Console.WriteLine($"  [{finding.Verdict.ToUpperInvariant()}] {finding.Summary}");
                    }
                }
                catch (Exception ex)
                {
                    var fail = new Finding("ENGINE", GetTestName(test), target.ToString(), "inconclusive", $"Execution exception: {ex.Message}");
                    findings.Add(fail);
                    if (options.StreamLogs)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.Error.WriteLine($"  [ERROR] {GetTestName(test)}: {ex.Message}");
                        Console.ResetColor();
                    }
                }
            }
        }

        return new HeadlessReport(
            options.Target.ToString(),
            NormalizeScope(options.Scope),
            DescribeExecutionSelection(options.Framework, options.Suite),
            started,
            DateTime.UtcNow,
            targets.Count,
            findings);
    }

    private static string GetTestName(Func<Uri, Task<Finding>> test)
    {
        if (test.Method.Name.Contains('<'))
        {
            return "Framework Test";
        }

        return test.Method.Name switch
        {
            nameof(RunSecurityHeaderTestAsync) => "Security Headers",
            nameof(RunCorsTestAsync) => "CORS",
            nameof(RunHttpMethodTestAsync) => "HTTP Method Abuse",
            nameof(RunSqlInjectionTestAsync) => "SQL Injection",
            nameof(RunXssTestAsync) => "XSS",
            nameof(RunSsrfTestAsync) => "SSRF",
            nameof(RunRateLimitTestAsync) => "Rate Limit",
            _ => test.Method.Name
        };
    }

    private static string NormalizeScope(string scope)
    {
        var raw = (scope ?? "single").Trim().ToLowerInvariant();
        if (raw.Contains("openapi"))
        {
            return "openapi";
        }

        return raw.Contains("spider") ? "spider" : "single";
    }

    private static IReadOnlyList<Func<Uri, Task<Finding>>> ResolveTests(string framework, string suite)
    {
        var tests = new List<Func<Uri, Task<Finding>>>();
        var selectedFrameworks = ResolveSelectedFrameworks(framework);
        var selectedSuites = ResolveSelectedSuites(suite);
        var seenKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var frameworkName in selectedFrameworks)
        {
            foreach (var key in Mappings.GetFrameworkControlKeys(frameworkName))
            {
                if (!seenKeys.Add(key))
                {
                    continue;
                }

                var resolved = FrameworkResolutionWorkflowUtilities.ResolveTestByKey(CoreTestHost, key);
                if (resolved.Test is null)
                {
                    continue;
                }

                var captureKey = key;
                var captureName = resolved.TestName;
                var captureTest = resolved.Test;
                tests.Add(async target =>
                {
                    try
                    {
                        var output = await CoreTestHost.ExecuteWithStandardContextAsync(captureKey, target, captureTest);
                        return BuildFindingFromOutput(captureKey, captureName, target, output);
                    }
                    catch (Exception ex)
                    {
                        return new Finding(captureKey, captureName, target.ToString(), "inconclusive", $"Execution exception: {ex.Message}");
                    }
                });
            }
        }

        foreach (var suiteKey in selectedSuites)
        {
            var suiteDefinition = SuiteCatalogMappings.GetNamedSuite(suiteKey);
            if (suiteDefinition is null)
            {
                continue;
            }

            foreach (var methodName in suiteDefinition.TestMethodNames)
            {
                var resolved = DelegateResolutionUtilities.TryResolveRunTestDelegate(CoreTestHost, methodName);
                if (resolved is null)
                {
                    continue;
                }

                var dedupeKey = $"suite:{suiteKey}:{methodName}";
                if (!seenKeys.Add(dedupeKey))
                {
                    continue;
                }

                var captureSuiteKey = suiteKey;
                var captureSuiteName = suiteDefinition.Name;
                var captureMethodName = methodName;
                var captureTest = resolved;
                tests.Add(async target =>
                {
                    try
                    {
                        var output = await CoreTestHost.ExecuteWithStandardContextAsync(captureSuiteKey, target, captureTest);
                        return BuildFindingFromOutput(
                            $"{captureSuiteKey}:{captureMethodName}",
                            $"{captureSuiteName}: {HumanizeMethodName(captureMethodName)}",
                            target,
                            output);
                    }
                    catch (Exception ex)
                    {
                        return new Finding(
                            $"{captureSuiteKey}:{captureMethodName}",
                            $"{captureSuiteName}: {HumanizeMethodName(captureMethodName)}",
                            target.ToString(),
                            "inconclusive",
                            $"Execution exception: {ex.Message}");
                    }
                });
            }
        }

        if (tests.Count > 0)
        {
            return tests;
        }

        // Fallback to the original slim test set if mapping resolution yields nothing.
        return new Func<Uri, Task<Finding>>[]
        {
            RunSecurityHeaderTestAsync,
            RunCorsTestAsync,
            RunHttpMethodTestAsync,
            RunSqlInjectionTestAsync,
            RunXssTestAsync,
            RunSsrfTestAsync,
            RunRateLimitTestAsync
        };
    }

    private static IReadOnlyList<string> ResolveSelectedSuites(string suite)
    {
        if (string.IsNullOrWhiteSpace(suite))
        {
            return Array.Empty<string>();
        }

        return suite
            .Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static string DescribeExecutionSelection(string framework, string suite)
    {
        var frameworkLabel = string.IsNullOrWhiteSpace(framework) ? "(all)" : framework;
        if (string.IsNullOrWhiteSpace(suite))
        {
            return frameworkLabel;
        }

        return $"{frameworkLabel}; suites={suite}";
    }

    private static string HumanizeMethodName(string methodName)
    {
        if (string.IsNullOrWhiteSpace(methodName))
        {
            return "Framework Test";
        }

        var normalized = methodName;
        if (normalized.StartsWith("Run", StringComparison.Ordinal))
        {
            normalized = normalized[3..];
        }

        if (normalized.EndsWith("TestsAsync", StringComparison.Ordinal))
        {
            normalized = normalized[..^10];
        }
        else if (normalized.EndsWith("TestAsync", StringComparison.Ordinal))
        {
            normalized = normalized[..^9];
        }
        else if (normalized.EndsWith("Async", StringComparison.Ordinal))
        {
            normalized = normalized[..^5];
        }

        normalized = Regex.Replace(normalized, "([a-z0-9])([A-Z])", "$1 $2");
        normalized = normalized.Replace("ATTamp CK", "ATT&CK", StringComparison.OrdinalIgnoreCase);
        return normalized.Trim();
    }

    private static IReadOnlyList<string> ResolveSelectedFrameworks(string framework)
    {
        if (string.IsNullOrWhiteSpace(framework))
        {
            return Array.Empty<string>();
        }

        if (framework.Equals("(all)", StringComparison.OrdinalIgnoreCase))
        {
            return SuiteCatalogMappings.GetStandardFrameworkPacks()
                .SelectMany(p => p.Frameworks)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
        }

        return new[] { framework.Trim() };
    }

    private static Finding BuildFindingFromOutput(string key, string testName, Uri target, string output)
    {
        if (string.IsNullOrWhiteSpace(output))
        {
            return new Finding(key, testName, target.ToString(), "inconclusive", "No output returned.");
        }

        var verdict = "pass";
        if (Regex.IsMatch(output, @"potential risk:|verdict:\s*fail|\|\s*fail\s*\|", RegexOptions.IgnoreCase))
        {
            verdict = "fail";
        }
        else if (Regex.IsMatch(output, @"no response|execution error|failed:", RegexOptions.IgnoreCase))
        {
            verdict = "inconclusive";
        }

        var summary =
            output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries)
                .Select(x => x.Trim())
                .FirstOrDefault(x =>
                    x.Contains("Potential risk:", StringComparison.OrdinalIgnoreCase) ||
                    x.Contains("No obvious", StringComparison.OrdinalIgnoreCase) ||
                    x.Contains("Execution error", StringComparison.OrdinalIgnoreCase))
            ?? output.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault()?.Trim()
            ?? "Completed.";

        if (summary.Length > 280)
        {
            summary = summary[..280];
        }

        return new Finding(key, testName, target.ToString(), verdict, summary);
    }

    private static async Task<List<Uri>> ResolveTargetsAsync(Uri baseUri, string scope, string openApiSource)
    {
        var normalizedScope = NormalizeScope(scope);
        if (normalizedScope.Equals("openapi", StringComparison.OrdinalIgnoreCase))
        {
            var openApiTargets = await ResolveOpenApiTargetsAsync(baseUri, openApiSource);
            return openApiTargets.Count == 0 ? [baseUri] : openApiTargets;
        }

        if (!normalizedScope.Equals("spider", StringComparison.OrdinalIgnoreCase))
        {
            return [baseUri];
        }

        var discovered = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { baseUri.ToString() };
        var queue = new Queue<Uri>();
        queue.Enqueue(baseUri);

        while (queue.Count > 0 && discovered.Count < 60)
        {
            var current = queue.Dequeue();
            string body;
            try
            {
                body = await Client.GetStringAsync(current);
            }
            catch
            {
                continue;
            }

            foreach (var href in ExtractLinks(body))
            {
                if (!Uri.TryCreate(current, href, out var next) || next is null)
                {
                    continue;
                }

                if (!IsSameOrigin(baseUri, next))
                {
                    continue;
                }

                var normalized = NormalizeEndpoint(next);
                if (discovered.Add(normalized))
                {
                    queue.Enqueue(next);
                }
            }
        }

        foreach (var candidate in BuildCommonRouteCandidates(baseUri))
        {
            discovered.Add(candidate);
        }

        var openApiTargetsForSpider = await ResolveOpenApiTargetsAsync(baseUri, openApiSource);
        foreach (var target in openApiTargetsForSpider)
        {
            discovered.Add(target.ToString());
        }

        return discovered
            .Select(x => Uri.TryCreate(x, UriKind.Absolute, out var u) ? u : null)
            .Where(x => x is not null)
            .Select(x => x!)
            .ToList();
    }

    private static async Task<List<Uri>> ResolveOpenApiTargetsAsync(Uri baseUri, string openApiSource)
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var source in ResolveOpenApiSources(baseUri, openApiSource))
        {
            string raw;
            if (source.IsFile)
            {
                if (!File.Exists(source.Value))
                {
                    continue;
                }

                raw = await File.ReadAllTextAsync(source.Value);
            }
            else
            {
                var response = await SafeSendAsync(new HttpRequestMessage(HttpMethod.Get, source.Value));
                if (response is null)
                {
                    continue;
                }

                using (response)
                {
                    if (!response.IsSuccessStatusCode)
                    {
                        continue;
                    }

                    raw = await ReadBodyAsync(response);
                }
            }

            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            try
            {
                using var doc = JsonDocument.Parse(raw);
                if (!doc.RootElement.TryGetProperty("paths", out var pathsNode) || pathsNode.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                foreach (var entry in pathsNode.EnumerateObject())
                {
                    var normalizedPath = Regex.Replace(entry.Name, "{[^}]+}", "1");
                    if (!normalizedPath.StartsWith('/'))
                    {
                        normalizedPath = "/" + normalizedPath;
                    }
                    paths.Add(normalizedPath);
                }
            }
            catch
            {
                // Invalid or unsupported OpenAPI payload.
            }
        }

        var results = paths
            .Select(path => Uri.TryCreate(baseUri, path, out var uri) ? uri : null)
            .Where(uri => uri is not null && IsSameOrigin(baseUri, uri))
            .Select(uri => uri!)
            .DistinctBy(uri => NormalizeEndpoint(uri))
            .OrderBy(uri => uri.AbsolutePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(uri => uri.Query, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (results.Count == 0)
        {
            results.Add(baseUri);
        }

        return results;
    }

    private static IEnumerable<(string Value, bool IsFile)> ResolveOpenApiSources(Uri baseUri, string openApiSource)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (!string.IsNullOrWhiteSpace(openApiSource))
        {
            var trimmed = openApiSource.Trim();
            if (File.Exists(trimmed) && seen.Add(trimmed))
            {
                yield return (trimmed, true);
            }
            else if (Uri.TryCreate(trimmed, UriKind.Absolute, out var absolute))
            {
                foreach (var expanded in ExpandOpenApiCandidateUrls(absolute))
                {
                    if (seen.Add(expanded))
                    {
                        yield return (expanded, false);
                    }
                }
            }
            else if (Uri.TryCreate(baseUri, trimmed, out var relative))
            {
                foreach (var expanded in ExpandOpenApiCandidateUrls(relative))
                {
                    if (seen.Add(expanded))
                    {
                        yield return (expanded, false);
                    }
                }
            }
        }

        foreach (var candidate in new[]
                 {
                     new Uri(baseUri, "/openapi.json").ToString(),
                     new Uri(baseUri, "/openapi/v1.json").ToString(),
                     new Uri(baseUri, "/openapi/v3.json").ToString(),
                     new Uri(baseUri, "/swagger/v1/swagger.json").ToString(),
                     new Uri(baseUri, "/swagger.json").ToString(),
                     new Uri(baseUri, "/v1/openapi.json").ToString()
                 })
        {
            if (seen.Add(candidate))
            {
                yield return (candidate, false);
            }
        }
    }

    private static IEnumerable<string> ExpandOpenApiCandidateUrls(Uri source)
    {
        yield return source.ToString();

        var path = source.AbsolutePath.TrimEnd('/');
        if (path.EndsWith("/swagger", StringComparison.OrdinalIgnoreCase) ||
            path.EndsWith("/swagger/index.html", StringComparison.OrdinalIgnoreCase))
        {
            yield return new Uri(source, "/swagger/v1/swagger.json").ToString();
            yield return new Uri(source, "/swagger.json").ToString();
        }

        if (path.EndsWith("/openapi", StringComparison.OrdinalIgnoreCase))
        {
            yield return new Uri(source, "/openapi.json").ToString();
        }
    }

    private static bool IsSameOrigin(Uri baseUri, Uri candidate)
    {
        return baseUri.Scheme.Equals(candidate.Scheme, StringComparison.OrdinalIgnoreCase) &&
               baseUri.Host.Equals(candidate.Host, StringComparison.OrdinalIgnoreCase) &&
               baseUri.Port == candidate.Port;
    }

    private static string NormalizeEndpoint(Uri uri)
    {
        var b = new UriBuilder(uri) { Fragment = string.Empty };
        return b.Uri.ToString().TrimEnd('/');
    }

    private static IEnumerable<string> ExtractLinks(string html)
    {
        var results = new List<string>();
        var rx = new Regex("(?:href|src|action)\\s*=\\s*['\\\"](?<u>[^'\\\"]+)['\\\"]", RegexOptions.IgnoreCase);
        foreach (Match m in rx.Matches(html))
        {
            var v = m.Groups["u"].Value.Trim();
            if (!string.IsNullOrWhiteSpace(v))
            {
                results.Add(v);
            }
        }
        return results;
    }

    private static IEnumerable<string> BuildCommonRouteCandidates(Uri baseUri)
    {
        var candidates = new[]
        {
            "/health", "/status", "/ready", "/live", "/metrics", "/version", "/testapi",
            "/openapi.json", "/openapi/v1.json", "/swagger", "/swagger/index.html", "/swagger/v1/swagger.json",
            "/api", "/api/v1", "/api/v2", "/v1", "/v2",
            "/users", "/users/1", "/products", "/products/1", "/orders", "/orders/1",
            "/reports", "/files", "/secure", "/auth", "/login", "/logout", "/register",
            "/admin", "/debug", "/internal", "/search", "/docs"
        };
        foreach (var c in candidates)
        {
            yield return new Uri(baseUri, c).ToString();
        }
    }

    private static async Task<Finding> RunSecurityHeaderTestAsync(Uri target)
    {
        using var response = await SafeGetAsync(target);
        if (response is null)
        {
            return new Finding("HEADERS", "Security Headers", target.ToString(), "inconclusive", "No response.");
        }

        var missing = new List<string>();
        if (!response.Headers.Contains("X-Content-Type-Options")) missing.Add("X-Content-Type-Options");
        if (!response.Headers.Contains("X-Frame-Options")) missing.Add("X-Frame-Options");
        if (!response.Headers.Contains("Strict-Transport-Security")) missing.Add("Strict-Transport-Security");

        return missing.Count > 0
            ? new Finding("HEADERS", "Security Headers", target.ToString(), "fail", $"Missing headers: {string.Join(", ", missing)}")
            : new Finding("HEADERS", "Security Headers", target.ToString(), "pass", "Core security headers present.");
    }

    private static async Task<Finding> RunCorsTestAsync(Uri target)
    {
        using var req = new HttpRequestMessage(HttpMethod.Get, target);
        req.Headers.TryAddWithoutValidation("Origin", "https://example.invalid");
        using var response = await SafeSendAsync(req);
        if (response is null)
        {
            return new Finding("CORS", "CORS Misconfiguration", target.ToString(), "inconclusive", "No response.");
        }

        var acao = response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values)
            ? values.FirstOrDefault() ?? string.Empty
            : string.Empty;

        return acao == "*"
            ? new Finding("CORS", "CORS Misconfiguration", target.ToString(), "fail", "Wildcard ACAO returned.")
            : new Finding("CORS", "CORS Misconfiguration", target.ToString(), "pass", "No wildcard ACAO observed.");
    }

    private static async Task<Finding> RunHttpMethodTestAsync(Uri target)
    {
        using var request = new HttpRequestMessage(HttpMethod.Trace, target);
        using var trace = await SafeSendAsync(request);
        if (trace is null)
        {
            return new Finding("METHODS", "HTTP Method Abuse", target.ToString(), "inconclusive", "No response.");
        }

        if (trace is not null && ((int)trace.StatusCode is >= 200 and < 300))
        {
            return new Finding("METHODS", "HTTP Method Abuse", target.ToString(), "fail", "TRACE method accepted.");
        }
        return new Finding("METHODS", "HTTP Method Abuse", target.ToString(), "pass", "TRACE not accepted.");
    }

    private static async Task<Finding> RunSqlInjectionTestAsync(Uri target)
    {
        var probe = AppendQuery(target, new Dictionary<string, string> { ["id"] = "' OR '1'='1" });
        using var response = await SafeGetAsync(probe);
        var body = await ReadBodyAsync(response);
        if (response is null)
        {
            return new Finding("SQLI", "SQL Injection", target.ToString(), "inconclusive", "No response.");
        }

        var fail = ContainsAny(body, "sql syntax", "odbc", "mysql", "postgresql", "sqlite", "unclosed quotation mark", "ora-");
        return fail
            ? new Finding("SQLI", "SQL Injection", target.ToString(), "fail", "SQL error signature detected.")
            : new Finding("SQLI", "SQL Injection", target.ToString(), "pass", "No SQL error signature detected.");
    }

    private static async Task<Finding> RunXssTestAsync(Uri target)
    {
        const string payload = "<script>alert(1)</script>";
        var probe = AppendQuery(target, new Dictionary<string, string> { ["q"] = payload });
        using var response = await SafeGetAsync(probe);
        var body = await ReadBodyAsync(response);
        if (response is null)
        {
            return new Finding("XSS", "Reflected XSS", target.ToString(), "inconclusive", "No response.");
        }

        var reflected = body.Contains(payload, StringComparison.OrdinalIgnoreCase);
        return reflected
            ? new Finding("XSS", "Reflected XSS", target.ToString(), "fail", "Payload reflected in response.")
            : new Finding("XSS", "Reflected XSS", target.ToString(), "pass", "No direct payload reflection.");
    }

    private static async Task<Finding> RunSsrfTestAsync(Uri target)
    {
        var probe = AppendQuery(target, new Dictionary<string, string> { ["url"] = "http://169.254.169.254/latest/meta-data/" });
        using var response = await SafeGetAsync(probe);
        var body = await ReadBodyAsync(response);
        if (response is null)
        {
            return new Finding("SSRF", "SSRF", target.ToString(), "inconclusive", "No response.");
        }

        var marker = ContainsAny(body, "meta-data", "instance-id", "iam/security-credentials");
        return marker
            ? new Finding("SSRF", "SSRF", target.ToString(), "fail", "Internal metadata markers detected.")
            : new Finding("SSRF", "SSRF", target.ToString(), "pass", "No internal metadata markers detected.");
    }

    private static async Task<Finding> RunRateLimitTestAsync(Uri target)
    {
        var tasks = Enumerable.Range(0, 12).Select(_ => SafeGetAsync(target)).ToArray();
        var responses = await Task.WhenAll(tasks);
        var success = responses.Count(r => r is not null && (int)r.StatusCode is >= 200 and < 300);
        var limited = responses.Count(r => r is not null && (int)r.StatusCode == 429);

        if (responses.All(r => r is null))
        {
            return new Finding("RATELIMIT", "Rate Limit", target.ToString(), "inconclusive", "No responses.");
        }

        var finding = limited == 0 && success >= 10
            ? new Finding("RATELIMIT", "Rate Limit", target.ToString(), "fail", "No throttling observed during burst.")
            : new Finding("RATELIMIT", "Rate Limit", target.ToString(), "pass", "Throttling or non-success responses observed.");

        foreach (var response in responses)
        {
            response?.Dispose();
        }

        return finding;
    }

    private static async Task<HttpResponseMessage?> SafeGetAsync(Uri uri)
    {
        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            return await SafeSendCoreAsync(request);
        }
        catch
        {
            return null;
        }
    }

    private static async Task<HttpResponseMessage?> SafeSendAsync(HttpRequestMessage request)
    {
        try
        {
            return await SafeSendCoreAsync(request);
        }
        catch
        {
            return null;
        }
    }

    private static async Task<HttpResponseMessage?> SafeSendCoreAsync(HttpRequestMessage request)
    {
        var methodOverride = ParseMethodOverride(CurrentOptions.MethodOverride);
        var payloadLocationRaw = (CurrentOptions.PayloadLocation ?? "auto").Trim().ToLowerInvariant();
        var payloadLocation = payloadLocationRaw switch
        {
            "path" => PayloadLocation.Path,
            "body" => PayloadLocation.Body,
            "header" => PayloadLocation.Header,
            "cookie" => PayloadLocation.Cookie,
            _ => PayloadLocation.Query
        };
        var useAutomaticContract = methodOverride is null && CurrentAutomaticContract is not null;
        var enablePayloadRelocation =
            NormalizeScope(CurrentOptions.Scope).Equals("single", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(payloadLocationRaw, "auto", StringComparison.OrdinalIgnoreCase);

        var options = new RequestPipelineOptions(
            CurrentConfiguredTarget,
            payloadLocation,
            methodOverride,
            enablePayloadRelocation,
            useAutomaticContract,
            CurrentAutomaticContract);
        RequestContractPipeline.Apply(request, options);
        if (CurrentOptions.HttpTrace)
        {
            var body = request.Content is null ? string.Empty : await ReadBodyAsync(new HttpResponseMessage { Content = request.Content });
            Console.WriteLine($"[HTTP] -> {request.Method} {request.RequestUri}");
            if (request.Headers.Any())
            {
                Console.WriteLine($"[HTTP]    headers: {string.Join(" | ", request.Headers.Select(h => $"{h.Key}={string.Join(",", h.Value)}"))}");
            }
            if (!string.IsNullOrWhiteSpace(body))
            {
                Console.WriteLine($"[HTTP]    body: {TrimForLog(body, 400)}");
            }
        }

        var response = await Client.SendAsync(request);
        if (CurrentOptions.HttpTrace)
        {
            Console.WriteLine($"[HTTP] <- {(int)response.StatusCode} {response.StatusCode} {request.RequestUri}");
        }

        return response;
    }

    private static HttpMethod? ParseMethodOverride(string raw)
    {
        var value = (raw ?? "auto").Trim().ToUpperInvariant();
        return value switch
        {
            "" or "AUTO" => null,
            "GET" => HttpMethod.Get,
            "POST" => HttpMethod.Post,
            "PUT" => HttpMethod.Put,
            "PATCH" => HttpMethod.Patch,
            "DELETE" => HttpMethod.Delete,
            "HEAD" => HttpMethod.Head,
            "OPTIONS" => HttpMethod.Options,
            _ => null
        };
    }

    private static string TrimForLog(string value, int max) =>
        value.Length <= max ? value : value[..max] + "...";

    private static async Task<string> ReadBodyAsync(HttpResponseMessage? response)
    {
        if (response?.Content is null)
        {
            return string.Empty;
        }
        try
        {
            return await response.Content.ReadAsStringAsync();
        }
        catch
        {
            return string.Empty;
        }
    }

    private static Uri AppendQuery(Uri uri, IDictionary<string, string> additions)
    {
        var builder = new UriBuilder(uri);
        var list = new List<string>();
        if (!string.IsNullOrWhiteSpace(builder.Query))
        {
            list.Add(builder.Query.TrimStart('?'));
        }
        list.AddRange(additions.Select(kv => $"{Uri.EscapeDataString(kv.Key)}={Uri.EscapeDataString(kv.Value)}"));
        builder.Query = string.Join("&", list.Where(x => !string.IsNullOrWhiteSpace(x)));
        return builder.Uri;
    }

    private static bool ContainsAny(string haystack, params string[] needles)
    {
        foreach (var needle in needles)
        {
            if (haystack.Contains(needle, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }

    private static List<Func<Uri, Task<Finding>>> AdaptTestsForSingleTargetOpenApi(IReadOnlyList<Func<Uri, Task<Finding>>> tests)
    {
        if (CurrentAutomaticContract is null)
        {
            return tests.ToList();
        }

        if (CurrentRouteIntent == OpenApiRouteIntent.Method)
        {
            var filtered = tests.Where(test =>
                    test == RunSecurityHeaderTestAsync ||
                    test == RunCorsTestAsync ||
                    test == RunHttpMethodTestAsync ||
                    test == RunRateLimitTestAsync)
                .ToList();
            return filtered.Count == 0 ? tests.ToList() : filtered;
        }

        return tests.ToList();
    }

    private static (OperationContract Contract, OpenApiRouteIntent Intent)? ResolveContractForTarget(
        Uri target,
        IReadOnlyList<(OperationContract Contract, OpenApiRouteIntent Intent)> contracts)
    {
        if (contracts.Count == 0)
        {
            return null;
        }

        var targetPath = RequestContractPipeline.NormalizeComparablePath(target);

        return contracts
            .Where(c => RequestContractPipeline.PathsMatchForScope(target, c.Contract.Endpoint))
            .OrderByDescending(c => RequestContractPipeline.NormalizeComparablePath(c.Contract.Endpoint)
                .Equals(targetPath, StringComparison.OrdinalIgnoreCase))
            .ThenByDescending(c => c.Contract.PathParameterNames.Count)
            .ThenByDescending(c => c.Contract.QueryParameterNames.Count + c.Contract.BodyPropertyNames.Count)
            .FirstOrDefault();
    }

    private static async Task<IReadOnlyList<(OperationContract Contract, OpenApiRouteIntent Intent)>> BuildOpenApiContractIndexAsync(
        Uri baseUri,
        string openApiSource)
    {
        var authorityRoot = new Uri(baseUri.GetLeftPart(UriPartial.Authority));
        var contracts = new List<(OperationContract Contract, OpenApiRouteIntent Intent)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var source in ResolveOpenApiSources(authorityRoot, openApiSource))
        {
            string raw;
            try
            {
                if (source.IsFile)
                {
                    if (!File.Exists(source.Value))
                    {
                        continue;
                    }

                    raw = await File.ReadAllTextAsync(source.Value);
                }
                else
                {
                    var response = await SafeSendAsync(new HttpRequestMessage(HttpMethod.Get, source.Value));
                    if (response is null)
                    {
                        continue;
                    }

                    using (response)
                    {
                        if (!response.IsSuccessStatusCode)
                        {
                            continue;
                        }

                        raw = await ReadBodyAsync(response);
                    }
                }
            }
            catch
            {
                continue;
            }

            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            try
            {
                using var doc = JsonDocument.Parse(raw);
                if (!doc.RootElement.TryGetProperty("paths", out var pathsNode) || pathsNode.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                foreach (var pathEntry in pathsNode.EnumerateObject())
                {
                    var candidate = BuildPathCandidate(authorityRoot, pathEntry.Name);
                    var methods = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var queryNames = new List<string>();
                    var bodyNames = new List<string>();
                    var pathNames = new List<string>();
                    string? bodyTemplateJson = null;

                    if (pathEntry.Value.TryGetProperty("parameters", out var pathParameters))
                    {
                        CollectQueryParameterNames(doc.RootElement, pathParameters, queryNames);
                        CollectPathParameterNames(doc.RootElement, pathParameters, pathNames);
                    }

                    foreach (var operation in pathEntry.Value.EnumerateObject())
                    {
                        if (!IsHttpMethodName(operation.Name))
                        {
                            continue;
                        }

                        methods.Add(operation.Name.ToUpperInvariant());
                        if (operation.Value.TryGetProperty("parameters", out var operationParameters))
                        {
                            CollectQueryParameterNames(doc.RootElement, operationParameters, queryNames);
                            CollectPathParameterNames(doc.RootElement, operationParameters, pathNames);
                        }

                        if (operation.Value.TryGetProperty("requestBody", out var requestBody))
                        {
                            CollectBodyPropertyNames(doc.RootElement, requestBody, bodyNames);
                            bodyTemplateJson ??= BuildBodyTemplateJson(doc.RootElement, requestBody);
                        }
                    }

                    var intent = ClassifyRouteIntent(pathEntry.Name, methods, queryNames, bodyNames, pathNames);
                    var contract = new OperationContract(
                        candidate,
                        methods.OrderBy(x => x, StringComparer.OrdinalIgnoreCase).ToArray(),
                        queryNames.ToArray(),
                        bodyNames.ToArray(),
                        pathNames.ToArray(),
                        null,
                        null,
                        null,
                        intent switch
                        {
                            OpenApiRouteIntent.Query => PayloadLocation.Query,
                            OpenApiRouteIntent.Path => PayloadLocation.Path,
                            OpenApiRouteIntent.Body => PayloadLocation.Body,
                            OpenApiRouteIntent.Header => PayloadLocation.Header,
                            OpenApiRouteIntent.Cookie => PayloadLocation.Cookie,
                            OpenApiRouteIntent.Combo => pathNames.Count > 0
                                ? PayloadLocation.Path
                                : (bodyNames.Count > 0 ? PayloadLocation.Body : PayloadLocation.Query),
                            _ => null
                        },
                        bodyTemplateJson);

                    var contractKey =
                        $"{RequestContractPipeline.NormalizeComparablePath(candidate)}|{string.Join(",", contract.AllowedMethods.OrderBy(x => x, StringComparer.OrdinalIgnoreCase))}";
                    if (seen.Add(contractKey))
                    {
                        contracts.Add((contract, intent));
                    }
                }
            }
            catch
            {
                // Ignore invalid OpenAPI payloads.
            }
        }

        return contracts;
    }

    private static async Task<(OperationContract? Contract, OpenApiRouteIntent Intent)> TryResolveSingleTargetOperationContractAsync(Uri target, string openApiSource)
    {
        var contracts = await BuildOpenApiContractIndexAsync(target, openApiSource);
        var contract = ResolveContractForTarget(target, contracts);
        return contract is null
            ? (null, OpenApiRouteIntent.Unknown)
            : (contract.Value.Contract, contract.Value.Intent);
    }

    private static Uri BuildPathCandidate(Uri authorityRoot, string openApiPath)
    {
        var normalizedPath = Regex.Replace(openApiPath, "{[^}]+}", "1");
        if (!normalizedPath.StartsWith('/'))
        {
            normalizedPath = "/" + normalizedPath;
        }

        return new Uri(authorityRoot, normalizedPath);
    }

    private static bool IsHttpMethodName(string value) =>
        value.Equals("get", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("post", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("put", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("patch", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("delete", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("head", StringComparison.OrdinalIgnoreCase) ||
        value.Equals("options", StringComparison.OrdinalIgnoreCase);

    private static void CollectPathParameterNames(JsonElement root, JsonElement parametersNode, List<string> names)
    {
        if (parametersNode.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var parameterNode in parametersNode.EnumerateArray())
        {
            var resolved = ResolveReference(root, parameterNode);
            if (!resolved.TryGetProperty("in", out var locationNode) ||
                !string.Equals(locationNode.GetString(), "path", StringComparison.OrdinalIgnoreCase) ||
                !resolved.TryGetProperty("name", out var nameNode))
            {
                continue;
            }

            var name = nameNode.GetString();
            if (!string.IsNullOrWhiteSpace(name) &&
                !names.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                names.Add(name);
            }
        }
    }

    private static void CollectQueryParameterNames(JsonElement root, JsonElement parametersNode, List<string> names)
    {
        if (parametersNode.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var parameterNode in parametersNode.EnumerateArray())
        {
            var resolved = ResolveReference(root, parameterNode);
            if (!resolved.TryGetProperty("in", out var locationNode) ||
                !locationNode.GetString().Equals("query", StringComparison.OrdinalIgnoreCase) ||
                !resolved.TryGetProperty("name", out var nameNode))
            {
                continue;
            }

            var name = nameNode.GetString();
            if (!string.IsNullOrWhiteSpace(name) &&
                !names.Contains(name, StringComparer.OrdinalIgnoreCase))
            {
                names.Add(name);
            }
        }
    }

    private static void CollectBodyPropertyNames(JsonElement root, JsonElement requestBodyNode, List<string> names)
    {
        var resolvedBody = ResolveReference(root, requestBodyNode);
        if (!resolvedBody.TryGetProperty("content", out var contentNode) || contentNode.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var contentEntry in contentNode.EnumerateObject())
        {
            if (!contentEntry.Name.Contains("json", StringComparison.OrdinalIgnoreCase) ||
                !contentEntry.Value.TryGetProperty("schema", out var schemaNode))
            {
                continue;
            }

            var schema = ResolveReference(root, schemaNode);
            if (!schema.TryGetProperty("properties", out var propertiesNode) || propertiesNode.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            foreach (var property in propertiesNode.EnumerateObject())
            {
                if (!string.IsNullOrWhiteSpace(property.Name) &&
                    !names.Contains(property.Name, StringComparer.OrdinalIgnoreCase))
                {
                    names.Add(property.Name);
                }
            }
        }
    }

    private static string? BuildBodyTemplateJson(JsonElement root, JsonElement requestBodyNode)
    {
        var resolvedBody = ResolveReference(root, requestBodyNode);
        if (!resolvedBody.TryGetProperty("content", out var contentNode) || contentNode.ValueKind != JsonValueKind.Object)
        {
            return null;
        }

        foreach (var contentEntry in contentNode.EnumerateObject())
        {
            if (!contentEntry.Name.Contains("json", StringComparison.OrdinalIgnoreCase) ||
                !contentEntry.Value.TryGetProperty("schema", out var schemaNode))
            {
                continue;
            }

            var schema = ResolveReference(root, schemaNode);
            if (!schema.TryGetProperty("properties", out var propertiesNode) || propertiesNode.ValueKind != JsonValueKind.Object)
            {
                continue;
            }

            var values = new List<string>();
            foreach (var property in propertiesNode.EnumerateObject())
            {
                values.Add($"{JsonSerializer.Serialize(property.Name)}:{BuildDefaultJsonValue(ResolveReference(root, property.Value))}");
            }

            return "{" + string.Join(",", values) + "}";
        }

        return null;
    }

    private static OpenApiRouteIntent ClassifyRouteIntent(
        string openApiPath,
        HashSet<string> methods,
        List<string> queryNames,
        List<string> bodyNames,
        List<string> pathNames)
    {
        var normalizedPath = openApiPath.Trim().ToLowerInvariant();
        if (normalizedPath.Contains("/combo"))
        {
            return OpenApiRouteIntent.Combo;
        }

        if (normalizedPath.Contains("/method"))
        {
            return OpenApiRouteIntent.Method;
        }

        if (normalizedPath.Contains("/header"))
        {
            return OpenApiRouteIntent.Header;
        }

        if (normalizedPath.Contains("/cookie"))
        {
            return OpenApiRouteIntent.Cookie;
        }

        if (normalizedPath.Contains("/body") || bodyNames.Count > 0)
        {
            return OpenApiRouteIntent.Body;
        }

        if (normalizedPath.Contains("/path") || pathNames.Count > 0)
        {
            return OpenApiRouteIntent.Path;
        }

        if (normalizedPath.Contains("/query") || queryNames.Count > 0)
        {
            return OpenApiRouteIntent.Query;
        }

        if (methods.Count > 1)
        {
            return OpenApiRouteIntent.Method;
        }

        return OpenApiRouteIntent.Unknown;
    }

    private static string BuildDefaultJsonValue(JsonElement schema)
    {
        if (schema.TryGetProperty("example", out var exampleNode))
        {
            return exampleNode.GetRawText();
        }

        var type = schema.TryGetProperty("type", out var typeNode) ? typeNode.GetString() : null;
        return type?.ToLowerInvariant() switch
        {
            "boolean" => "true",
            "integer" => "0",
            "number" => "0",
            "array" => "[]",
            "object" => "{}",
            _ => "\"sample\""
        };
    }

    private static JsonElement ResolveReference(JsonElement root, JsonElement node)
    {
        if (!node.TryGetProperty("$ref", out var refNode))
        {
            return node;
        }

        var reference = refNode.GetString();
        if (string.IsNullOrWhiteSpace(reference) || !reference.StartsWith("#/", StringComparison.Ordinal))
        {
            return node;
        }

        JsonElement current = root;
        foreach (var segment in reference[2..].Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            var decoded = segment.Replace("~1", "/").Replace("~0", "~");
            if (current.ValueKind != JsonValueKind.Object || !current.TryGetProperty(decoded, out current))
            {
                return node;
            }
        }

        return current;
    }
}
