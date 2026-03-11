using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using ApiTester.Shared;

namespace ApiTester.Core;

public sealed record ScanOptions(
    Uri Target,
    string Scope,
    string Output,
    string ResultFilter,
    string Framework,
    string OpenApiSource,
    bool StreamLogs,
    string MethodOverride,
    string PayloadLocation,
    bool HttpTrace);

public sealed record Finding(
    string TestKey,
    string TestName,
    string Target,
    string Verdict,
    string Summary);

public sealed record HeadlessReport(
    string Target,
    string Scope,
    string Framework,
    DateTime StartedUtc,
    DateTime FinishedUtc,
    int TargetsScanned,
    List<Finding> Findings);

public sealed record AuthProbeRequest(string Name, Func<HttpRequestMessage> BuildRequest);

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

public sealed partial class CoreScanEngine
{
    private readonly HttpClient _client = new() { Timeout = TimeSpan.FromSeconds(12) };
    private ScanOptions _currentOptions = new(new Uri("http://127.0.0.1"), "single", "txt", "failed", "(all)", string.Empty, false, "auto", "query", false);
    private OperationContract? _currentAutomaticContract;
    private OpenApiRouteIntent _currentRouteIntent;

    public async Task<HeadlessReport> RunAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);

        var started = DateTime.UtcNow;
        var targets = await ResolveTargetsAsync(options.Target, options.Scope, options.OpenApiSource);
        var tests = AdaptTestsForSingleTargetOpenApi(ResolveTests(options.Framework));
        var findings = new List<Finding>();

        if (options.StreamLogs)
        {
            Console.WriteLine($"[HEADLESS] Started: {started:O}");
            Console.WriteLine($"[HEADLESS] Scope={NormalizeScope(options.Scope)} Framework={options.Framework}");
            Console.WriteLine($"[HEADLESS] Discovered targets={targets.Count}");
            Console.WriteLine($"[HEADLESS] Selected tests={tests.Count}");
        }

        foreach (var target in targets)
        {
            if (options.StreamLogs)
            {
                Console.WriteLine($"[TARGET] {target}");
            }

            foreach (var test in tests)
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
            string.IsNullOrWhiteSpace(options.Framework) ? "(all)" : options.Framework,
            started,
            DateTime.UtcNow,
            targets.Count,
            findings);
    }

    public async Task<Finding> RunSecurityHeadersAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunSecurityHeaderTestAsync(options.Target);
    }

    public async Task<Finding> RunCorsAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunCorsTestAsync(options.Target);
    }

    public async Task<Finding> RunHttpMethodsAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunHttpMethodTestAsync(options.Target);
    }

    public async Task<Finding> RunSqlInjectionAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunSqlInjectionTestAsync(options.Target);
    }

    public async Task<Finding> RunXssAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunXssTestAsync(options.Target);
    }

    public async Task<Finding> RunSsrfAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunSsrfTestAsync(options.Target);
    }

    public async Task<Finding> RunRateLimitAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunRateLimitTestAsync(options.Target);
    }

    public async Task<Finding> RunInformationDisclosureAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunInformationDisclosureTestAsync(options.Target);
    }

    public async Task<Finding> RunTransportSecurityAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunTransportSecurityTestAsync(options.Target);
    }

    public async Task<Finding> RunErrorHandlingLeakageAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunErrorHandlingLeakageTestAsync(options.Target);
    }

    public async Task<Finding> RunAuthAndAccessControlAsync(ScanOptions options, string? testProfileKey = null)
    {
        await PrepareRunContextAsync(options);
        return await RunAuthAndAccessControlTestAsync(options.Target, testProfileKey);
    }

    public async Task<Finding> RunBrokenAuthenticationAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunAuthAndAccessControlTestAsync(options.Target, "BrokenAuthentication", "BROKENAUTH", "Broken Authentication");
    }

    public async Task<Finding> RunBrokenFunctionLevelAuthorizationAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunBrokenFunctionLevelAuthorizationTestAsync(options.Target);
    }

    public async Task<Finding> RunBrokenObjectPropertyLevelAuthorizationAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunBrokenObjectPropertyLevelAuthorizationTestAsync(options.Target);
    }

    public async Task<Finding> RunCrossTenantDataLeakageAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunCrossTenantDataLeakageTestAsync(options.Target, options.OpenApiSource);
    }

    public async Task<Finding> RunBolaAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunBolaTestAsync(options.Target);
    }

    public async Task<Finding> RunCookieSecurityFlagsAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunCookieSecurityFlagsTestAsync(options.Target);
    }

    public async Task<Finding> RunContentTypeValidationAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunContentTypeValidationTestAsync(options.Target);
    }

    public async Task<Finding> RunImproperInventoryManagementAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunImproperInventoryManagementTestAsync(options.Target);
    }

    public async Task<Finding> RunIdempotencyReplayAsync(ScanOptions options)
    {
        await PrepareRunContextAsync(options);
        return await RunIdempotencyReplayTestAsync(options.Target);
    }

    private async Task PrepareRunContextAsync(ScanOptions options)
    {
        _currentOptions = options;
        _currentAutomaticContract = null;
        _currentRouteIntent = OpenApiRouteIntent.Unknown;
        if (NormalizeScope(options.Scope).Equals("single", StringComparison.OrdinalIgnoreCase))
        {
            var resolved = await TryResolveSingleTargetOperationContractAsync(options.Target, options.OpenApiSource);
            _currentAutomaticContract = resolved.Contract;
            _currentRouteIntent = resolved.Intent;
        }
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

    private static string GetTestName(Func<Uri, Task<Finding>> test) => test.Method.Name switch
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

    private IReadOnlyList<Func<Uri, Task<Finding>>> ResolveTests(string framework)
    {
        var all = new Func<Uri, Task<Finding>>[]
        {
            RunSecurityHeaderTestAsync,
            RunCorsTestAsync,
            RunHttpMethodTestAsync,
            RunSqlInjectionTestAsync,
            RunXssTestAsync,
            RunSsrfTestAsync,
            RunRateLimitTestAsync
        };

        if (string.IsNullOrWhiteSpace(framework) || framework.Equals("(all)", StringComparison.OrdinalIgnoreCase))
        {
            return all;
        }

        var f = framework.Trim();
        if (ContainsAny(f, "owasp api security top 10", "owasp asvs", "owasp testing guide", "owasp masvs", "owasp samm"))
        {
            return [RunSqlInjectionTestAsync, RunXssTestAsync, RunSsrfTestAsync, RunRateLimitTestAsync, RunHttpMethodTestAsync, RunCorsTestAsync];
        }

        if (ContainsAny(f, "nist", "fedramp", "disa", "cmmc"))
        {
            return [RunSecurityHeaderTestAsync, RunCorsTestAsync, RunHttpMethodTestAsync, RunRateLimitTestAsync, RunSsrfTestAsync];
        }

        if (ContainsAny(f, "pci", "hipaa", "gdpr", "ccpa", "soc 2", "iso", "ffiec", "cis"))
        {
            return [RunSecurityHeaderTestAsync, RunHttpMethodTestAsync, RunSqlInjectionTestAsync, RunXssTestAsync, RunRateLimitTestAsync];
        }

        return all;
    }

    private async Task<List<Uri>> ResolveTargetsAsync(Uri baseUri, string scope, string openApiSource)
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

        return [baseUri];
    }

    private async Task<List<Uri>> ResolveOpenApiTargetsAsync(Uri baseUri, string openApiSource)
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
            }
        }

        return paths
            .Select(path => Uri.TryCreate(baseUri, path, out var uri) ? uri : null)
            .Where(uri => uri is not null && IsSameOrigin(baseUri, uri))
            .Select(uri => uri!)
            .DistinctBy(NormalizeEndpoint)
            .OrderBy(uri => uri.AbsolutePath, StringComparer.OrdinalIgnoreCase)
            .ThenBy(uri => uri.Query, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private IEnumerable<(string Value, bool IsFile)> ResolveOpenApiSources(Uri baseUri, string openApiSource)
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

    private static bool IsSameOrigin(Uri baseUri, Uri candidate) =>
        baseUri.Scheme.Equals(candidate.Scheme, StringComparison.OrdinalIgnoreCase) &&
        baseUri.Host.Equals(candidate.Host, StringComparison.OrdinalIgnoreCase) &&
        baseUri.Port == candidate.Port;

    private static string NormalizeEndpoint(Uri uri)
    {
        var builder = new UriBuilder(uri) { Fragment = string.Empty };
        return builder.Uri.ToString().TrimEnd('/');
    }

    private async Task<Finding> RunSecurityHeaderTestAsync(Uri target)
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

    private async Task<Finding> RunCorsTestAsync(Uri target)
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

    private async Task<Finding> RunHttpMethodTestAsync(Uri target)
    {
        using var request = new HttpRequestMessage(HttpMethod.Trace, target);
        using var trace = await SafeSendAsync(request);
        if (trace is null)
        {
            return new Finding("METHODS", "HTTP Method Abuse", target.ToString(), "inconclusive", "No response.");
        }

        return trace is not null && ((int)trace.StatusCode is >= 200 and < 300)
            ? new Finding("METHODS", "HTTP Method Abuse", target.ToString(), "fail", "TRACE method accepted.")
            : new Finding("METHODS", "HTTP Method Abuse", target.ToString(), "pass", "TRACE not accepted.");
    }

    private async Task<Finding> RunSqlInjectionTestAsync(Uri target)
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

    private async Task<Finding> RunXssTestAsync(Uri target)
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

    private async Task<Finding> RunSsrfTestAsync(Uri target)
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

    private async Task<Finding> RunRateLimitTestAsync(Uri target)
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

    private async Task<Finding> RunInformationDisclosureTestAsync(Uri target)
    {
        using var response = await SafeSendAsync(new HttpRequestMessage(HttpMethod.Get, target));
        if (response is null)
        {
            return new Finding("DISCLOSURE", "Information Disclosure", target.ToString(), "inconclusive", "No response.");
        }

        var headers = new[] { "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version" };
        var exposed = headers
            .Select(header => (Header: header, Value: TryGetHeader(response, header)))
            .Where(x => !string.IsNullOrWhiteSpace(x.Value))
            .Select(x => $"{x.Header}={x.Value}")
            .ToList();

        return exposed.Count > 0
            ? new Finding("DISCLOSURE", "Information Disclosure", target.ToString(), "fail", $"Potential disclosure: {string.Join("; ", exposed)}")
            : new Finding("DISCLOSURE", "Information Disclosure", target.ToString(), "pass", "No disclosure headers observed.");
    }

    private async Task<Finding> RunTransportSecurityTestAsync(Uri target)
    {
        using var response = await SafeSendAsync(new HttpRequestMessage(HttpMethod.Get, target));
        if (response is null)
        {
            return new Finding("TRANSPORT", "Transport Security", target.ToString(), "inconclusive", "No response.");
        }

        if (!target.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            return new Finding("TRANSPORT", "Transport Security", target.ToString(), "fail", "HTTP target detected (no TLS on this URL).");
        }

        return response.Headers.Contains("Strict-Transport-Security")
            ? new Finding("TRANSPORT", "Transport Security", target.ToString(), "pass", "HTTPS target with HSTS present.")
            : new Finding("TRANSPORT", "Transport Security", target.ToString(), "fail", "HTTPS target but HSTS header missing.");
    }

    private async Task<Finding> RunErrorHandlingLeakageTestAsync(Uri target)
    {
        var malformed = AppendQuery(target, new Dictionary<string, string> { ["malformed"] = "%ZZ%YY" });
        using var response = await SafeSendAsync(new HttpRequestMessage(HttpMethod.Get, malformed));
        var body = await ReadBodyAsync(response);
        if (response is null)
        {
            return new Finding("ERROR", "Error Handling Leakage", malformed.ToString(), "inconclusive", "No response.");
        }

        return ContainsAny(body, "exception", "stack trace", "at ", "innerexception")
            ? new Finding("ERROR", "Error Handling Leakage", malformed.ToString(), "fail", $"Potential stack-trace leakage observed. Status={FormatStatus(response)}")
            : new Finding("ERROR", "Error Handling Leakage", malformed.ToString(), "pass", $"No obvious stack-trace leakage detected. Status={FormatStatus(response)}");
    }

    private async Task<Finding> RunAuthAndAccessControlTestAsync(
        Uri target,
        string? testProfileKey,
        string findingKey = "AUTH",
        string testName = "Authentication and Access Control")
    {
        var probes = BuildAuthProbeRequests(target, testProfileKey);
        var accepted = 0;
        var blocked = 0;
        var noResponse = 0;

        foreach (var probe in probes)
        {
            using var response = await SafeSendAsync(probe.BuildRequest());
            if (response is null)
            {
                noResponse++;
                continue;
            }

            var status = (int)response.StatusCode;
            if (status is >= 200 and < 300)
            {
                accepted++;
            }
            else if (status is 401 or 403)
            {
                blocked++;
            }
        }

        var summary = accepted > 0
            ? $"Potential risk: {accepted}/{probes.Count} auth probes were accepted."
            : blocked > 0
                ? $"Auth barrier observed in {blocked}/{probes.Count} probes."
                : noResponse == probes.Count
                    ? "No auth probe responses received."
                    : "No obvious auth barrier signal from current probes.";

        return accepted > 0
            ? new Finding(findingKey, testName, target.ToString(), "fail", summary)
            : new Finding(findingKey, testName, target.ToString(), blocked > 0 ? "pass" : "inconclusive", summary);
    }

    private async Task<Finding> RunBrokenFunctionLevelAuthorizationTestAsync(Uri target)
    {
        using var response = await SafeSendAsync(BuildRoleEscalationRequest(target));
        var summary = response is not null && response.StatusCode == HttpStatusCode.OK
            ? "Potential risk: elevated role headers accepted."
            : "No obvious privilege escalation indicator.";

        return new Finding("BFLA", "Broken Function Level Authorization", target.ToString(), response is not null && response.StatusCode == HttpStatusCode.OK ? "fail" : "pass", summary);
    }

    private async Task<Finding> RunBrokenObjectPropertyLevelAuthorizationTestAsync(Uri target)
    {
        var testUri = AppendQuery(target, new Dictionary<string, string>
        {
            ["role"] = "admin",
            ["isAdmin"] = "true",
            ["permissions"] = "all"
        });

        using var response = await SafeSendAsync(new HttpRequestMessage(HttpMethod.Get, testUri));
        var body = await ReadBodyAsync(response);
        var risky = body.Contains("admin", StringComparison.OrdinalIgnoreCase) ||
                    body.Contains("permissions", StringComparison.OrdinalIgnoreCase);

        return new Finding(
            "BOPLA",
            "Broken Object Property Level Authorization",
            testUri.ToString(),
            risky ? "fail" : "pass",
            risky
                ? "Potential risk: elevated object properties reflected or processed."
                : "No obvious object-property authorization indicator.");
    }

    private async Task<Finding> RunCrossTenantDataLeakageTestAsync(Uri target, string openApiSource)
    {
        var endpoints = await ResolveCrossTenantEndpointsAsync(target, openApiSource);
        var suspicious = 0;

        foreach (var endpoint in endpoints)
        {
            var a = AppendQuery(endpoint, new Dictionary<string, string> { ["id"] = "1", ["tenantId"] = "tenant-a" });
            var b = AppendQuery(endpoint, new Dictionary<string, string> { ["id"] = "2", ["tenantId"] = "tenant-b" });
            using var ra = await SafeSendAsync(new HttpRequestMessage(HttpMethod.Get, a));
            using var rb = await SafeSendAsync(new HttpRequestMessage(HttpMethod.Get, b));
            var ba = await ReadBodyAsync(ra);
            var bb = await ReadBodyAsync(rb);

            if (ra is not null && rb is not null &&
                (int)ra.StatusCode is >= 200 and < 300 &&
                (int)rb.StatusCode is >= 200 and < 300 &&
                !string.Equals(ba, bb, StringComparison.Ordinal))
            {
                suspicious++;
            }
        }

        return suspicious > 0
            ? new Finding("XTENANT", "Cross-Tenant Data Leakage", target.ToString(), "fail", $"Potential risk: cross-tenant differential data exposure signals observed on {suspicious} endpoint pairs.")
            : new Finding("XTENANT", "Cross-Tenant Data Leakage", target.ToString(), "pass", "No obvious cross-tenant leakage differential observed.");
    }

    private async Task<Finding> RunBolaTestAsync(Uri target)
    {
        var original = AppendQuery(target, new Dictionary<string, string> { ["id"] = "1" });
        var tampered = AppendQuery(target, new Dictionary<string, string> { ["id"] = "999999" });
        using var originalResponse = await SafeSendAsync(new HttpRequestMessage(HttpMethod.Get, original));
        using var tamperedResponse = await SafeSendAsync(new HttpRequestMessage(HttpMethod.Get, tampered));

        var risky = originalResponse is not null && tamperedResponse is not null &&
                    originalResponse.StatusCode == tamperedResponse.StatusCode &&
                    originalResponse.StatusCode == HttpStatusCode.OK;

        return risky
            ? new Finding("BOLA", "BOLA / Object ID Tampering", tampered.ToString(), "fail", "Tampered object ID returned same success status.")
            : new Finding("BOLA", "BOLA / Object ID Tampering", tampered.ToString(), "pass", "No obvious BOLA indicator from status comparison.");
    }

    private async Task<Finding> RunCookieSecurityFlagsTestAsync(Uri target)
    {
        using var response = await SafeSendAsync(new HttpRequestMessage(HttpMethod.Get, target));
        if (response is null)
        {
            return new Finding("COOKIEFLAGS", "Cookie Security Flags", target.ToString(), "inconclusive", "No response.");
        }

        if (!response.Headers.TryGetValues("Set-Cookie", out var setCookies))
        {
            return new Finding("COOKIEFLAGS", "Cookie Security Flags", target.ToString(), "pass", "No Set-Cookie headers found.");
        }

        var missing = new List<string>();
        foreach (var cookie in setCookies)
        {
            if (!cookie.Contains("Secure", StringComparison.OrdinalIgnoreCase)) missing.Add("Secure");
            if (!cookie.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase)) missing.Add("HttpOnly");
            if (!cookie.Contains("SameSite", StringComparison.OrdinalIgnoreCase)) missing.Add("SameSite");
        }

        return missing.Count > 0
            ? new Finding("COOKIEFLAGS", "Cookie Security Flags", target.ToString(), "fail", $"Missing cookie attributes observed: {string.Join(", ", missing.Distinct(StringComparer.OrdinalIgnoreCase))}")
            : new Finding("COOKIEFLAGS", "Cookie Security Flags", target.ToString(), "pass", "Cookie flags Secure/HttpOnly/SameSite observed.");
    }

    private async Task<Finding> RunContentTypeValidationTestAsync(Uri target)
    {
        const string jsonBody = "{\"test\":\"value\"}";
        using var request = new HttpRequestMessage(HttpMethod.Post, target)
        {
            Content = new StringContent(jsonBody, System.Text.Encoding.UTF8, "text/plain")
        };
        using var response = await SafeSendAsync(request);
        if (response is null)
        {
            return new Finding("CONTENTTYPE", "Content-Type Validation", target.ToString(), "inconclusive", "No response.");
        }

        var enforced = response.StatusCode == HttpStatusCode.UnsupportedMediaType || response.StatusCode == HttpStatusCode.BadRequest;
        return enforced
            ? new Finding("CONTENTTYPE", "Content-Type Validation", target.ToString(), "pass", "Content-type validation appears enforced.")
            : new Finding("CONTENTTYPE", "Content-Type Validation", target.ToString(), "fail", "Invalid content-type may be accepted.");
    }

    private async Task<Finding> RunImproperInventoryManagementTestAsync(Uri target)
    {
        var paths = new[] { "/swagger", "/swagger/index.html", "/openapi.json", "/v1", "/v2", "/beta", "/internal" };
        var discovered = new List<string>();
        foreach (var path in paths)
        {
            var uri = new Uri(target, path);
            using var response = await SafeSendAsync(new HttpRequestMessage(HttpMethod.Get, uri));
            if (response is not null && (int)response.StatusCode is >= 200 and < 300)
            {
                discovered.Add(path);
            }
        }

        return discovered.Count > 0
            ? new Finding("INVENTORY", "Improper Inventory Management", target.ToString(), "fail", $"Exposed inventory-related paths: {string.Join(", ", discovered)}")
            : new Finding("INVENTORY", "Improper Inventory Management", target.ToString(), "pass", "No obvious inventory paths exposed.");
    }

    private async Task<Finding> RunIdempotencyReplayTestAsync(Uri target)
    {
        const string payload = "{\"amount\":100,\"currency\":\"USD\"}";
        const string key = "api-tester-idempotency-key";
        using var firstRequest = new HttpRequestMessage(HttpMethod.Post, target);
        firstRequest.Headers.TryAddWithoutValidation("Idempotency-Key", key);
        firstRequest.Content = new StringContent(payload, System.Text.Encoding.UTF8, "application/json");
        using var first = await SafeSendAsync(firstRequest);

        using var secondRequest = new HttpRequestMessage(HttpMethod.Post, target);
        secondRequest.Headers.TryAddWithoutValidation("Idempotency-Key", key);
        secondRequest.Content = new StringContent(payload, System.Text.Encoding.UTF8, "application/json");
        using var second = await SafeSendAsync(secondRequest);

        if (first is null || second is null)
        {
            return new Finding("IDEMPOTENCY", "Idempotency Replay", target.ToString(), "inconclusive", "No response for one or both replay probes.");
        }

        var risky = first.StatusCode == second.StatusCode && first.StatusCode == HttpStatusCode.OK;
        return risky
            ? new Finding("IDEMPOTENCY", "Idempotency Replay", target.ToString(), "fail", "Replay with same idempotency key not differentiated.")
            : new Finding("IDEMPOTENCY", "Idempotency Replay", target.ToString(), "pass", "No obvious replay acceptance indicator.");
    }

    private async Task<HttpResponseMessage?> SafeGetAsync(Uri uri)
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

    private async Task<HttpResponseMessage?> SafeSendAsync(HttpRequestMessage request)
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

    private async Task<HttpResponseMessage?> SafeSendCoreAsync(HttpRequestMessage request)
    {
        var methodOverride = ParseMethodOverride(_currentOptions.MethodOverride);
        var options = new RequestPipelineOptions(
            _currentOptions.Target,
            _currentOptions.PayloadLocation.Trim().ToLowerInvariant() switch
            {
                "path" => PayloadLocation.Path,
                "body" => PayloadLocation.Body,
                "header" => PayloadLocation.Header,
                "cookie" => PayloadLocation.Cookie,
                _ => PayloadLocation.Query
            },
            methodOverride,
            NormalizeScope(_currentOptions.Scope).Equals("single", StringComparison.OrdinalIgnoreCase),
            methodOverride is null && _currentAutomaticContract is not null,
            _currentAutomaticContract);
        RequestContractPipeline.Apply(request, options);
        if (_currentOptions.HttpTrace)
        {
            var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync();
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

        var response = await _client.SendAsync(request);
        if (_currentOptions.HttpTrace)
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

    private static string TrimForLog(string value, int max) => value.Length <= max ? value : value[..max] + "...";

    private static IReadOnlyList<AuthProbeRequest> BuildAuthProbeRequests(Uri baseUri, string? testKey)
    {
        var key = testKey?.Trim().ToUpperInvariant() ?? string.Empty;
        var probes = new List<AuthProbeRequest>
        {
            new("Unauthenticated GET", () => new HttpRequestMessage(HttpMethod.Get, baseUri)),
            new("Forged role headers", () =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
                req.Headers.TryAddWithoutValidation("X-Role", "admin");
                req.Headers.TryAddWithoutValidation("X-User-Type", "superuser");
                return req;
            }),
            new("Invalid bearer token", () =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
                req.Headers.TryAddWithoutValidation("Authorization", "Bearer invalid.apitester.token");
                return req;
            })
        };

        if (key is "N63AAL" or "N53IA2" or "ASVSV2" or "MASVSAUTH")
        {
            probes.Add(new AuthProbeRequest("Weak basic credentials", () =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
                var weak = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes("admin:admin"));
                req.Headers.TryAddWithoutValidation("Authorization", $"Basic {weak}");
                return req;
            }));
        }

        if (key is "API5" or "N53AC6" or "MITRET1078")
        {
            probes.Add(new AuthProbeRequest("Privilege claim override", () =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
                req.Headers.TryAddWithoutValidation("X-Permissions", "all");
                req.Headers.TryAddWithoutValidation("X-Scope", "admin:*");
                return req;
            }));
        }

        return probes;
    }

    private static HttpRequestMessage BuildRoleEscalationRequest(Uri target)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, target);
        request.Headers.TryAddWithoutValidation("X-Role", "admin");
        request.Headers.TryAddWithoutValidation("X-User-Type", "superuser");
        return request;
    }

    private async Task<List<Uri>> ResolveCrossTenantEndpointsAsync(Uri baseUri, string openApiSource)
    {
        var targets = await ResolveOpenApiTargetsAsync(baseUri, openApiSource);
        var endpoints = targets
            .Where(u => Regex.IsMatch(u.AbsolutePath, @"/\d+$") || u.AbsolutePath.Contains("/api/", StringComparison.OrdinalIgnoreCase))
            .Take(4)
            .ToList();

        if (endpoints.Count == 0)
        {
            endpoints.Add(baseUri);
        }

        return endpoints;
    }

    private static string FormatStatus(HttpResponseMessage? response)
    {
        if (response is null)
        {
            return "Error: No response";
        }

        var code = (int)response.StatusCode;
        return code >= 400 ? $"Error: {code} {response.StatusCode}" : $"{code} {response.StatusCode}";
    }

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

    private static string TryGetHeader(HttpResponseMessage response, string headerName)
    {
        try
        {
            if (response.Headers.TryGetValues(headerName, out var values))
            {
                return string.Join(",", values);
            }
        }
        catch
        {
        }

        try
        {
            if (response.Content.Headers.TryGetValues(headerName, out var values))
            {
                return string.Join(",", values);
            }
        }
        catch
        {
        }

        return string.Empty;
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

    private List<Func<Uri, Task<Finding>>> AdaptTestsForSingleTargetOpenApi(IReadOnlyList<Func<Uri, Task<Finding>>> tests)
    {
        if (_currentAutomaticContract is null)
        {
            return tests.ToList();
        }

        if (_currentRouteIntent == OpenApiRouteIntent.Method)
        {
            return tests.Where(test =>
                    test == RunSecurityHeaderTestAsync ||
                    test == RunCorsTestAsync ||
                    test == RunHttpMethodTestAsync ||
                    test == RunRateLimitTestAsync)
                .ToList();
        }

        return tests.ToList();
    }

    private async Task<(OperationContract? Contract, OpenApiRouteIntent Intent)> TryResolveSingleTargetOperationContractAsync(Uri target, string openApiSource)
    {
        var authorityRoot = new Uri(target.GetLeftPart(UriPartial.Authority));
        foreach (var source in ResolveOpenApiSources(authorityRoot, openApiSource))
        {
            string raw;
            try
            {
                if (source.IsFile)
                {
                    raw = await File.ReadAllTextAsync(source.Value);
                }
                else
                {
                    using var response = await _client.GetAsync(source.Value);
                    if (!response.IsSuccessStatusCode)
                    {
                        continue;
                    }

                    raw = await response.Content.ReadAsStringAsync();
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
                    if (!RequestContractPipeline.PathsMatchForScope(target, candidate))
                    {
                        continue;
                    }

                    var methods = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var queryNames = new List<string>();
                    var bodyNames = new List<string>();
                    var pathNames = new List<string>();
                    var bodyTemplateJson = (string?)null;

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
                    return (
                        new OperationContract(
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
                                OpenApiRouteIntent.Combo => pathNames.Count > 0 ? PayloadLocation.Path : (bodyNames.Count > 0 ? PayloadLocation.Body : PayloadLocation.Query),
                                _ => null
                            },
                            bodyTemplateJson),
                        intent);
                }
            }
            catch
            {
            }
        }

        return (null, OpenApiRouteIntent.Unknown);
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
            if (!string.IsNullOrWhiteSpace(name) && !names.Contains(name, StringComparer.OrdinalIgnoreCase))
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
                !string.Equals(locationNode.GetString(), "query", StringComparison.OrdinalIgnoreCase) ||
                !resolved.TryGetProperty("name", out var nameNode))
            {
                continue;
            }

            var name = nameNode.GetString();
            if (!string.IsNullOrWhiteSpace(name) && !names.Contains(name, StringComparer.OrdinalIgnoreCase))
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
                if (!string.IsNullOrWhiteSpace(property.Name) && !names.Contains(property.Name, StringComparer.OrdinalIgnoreCase))
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
        if (normalizedPath.Contains("/combo")) return OpenApiRouteIntent.Combo;
        if (normalizedPath.Contains("/method")) return OpenApiRouteIntent.Method;
        if (normalizedPath.Contains("/header")) return OpenApiRouteIntent.Header;
        if (normalizedPath.Contains("/cookie")) return OpenApiRouteIntent.Cookie;
        if (normalizedPath.Contains("/body") || bodyNames.Count > 0) return OpenApiRouteIntent.Body;
        if (normalizedPath.Contains("/path") || pathNames.Count > 0) return OpenApiRouteIntent.Path;
        if (normalizedPath.Contains("/query") || queryNames.Count > 0) return OpenApiRouteIntent.Query;
        if (methods.Count > 1) return OpenApiRouteIntent.Method;
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
