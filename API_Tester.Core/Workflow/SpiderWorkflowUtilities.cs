using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace ApiTester.Core;

public static class SpiderWorkflowUtilities
{
    private static readonly Regex LinkAttributeRegex = new(
        "(?:href|src|action)\\s*=\\s*[\"'](?<u>[^\"'#>]+)[\"']",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ApiPathRegex = new(
        "\"(?<p>/[a-zA-Z0-9_./\\-{}:]+)\"\\s*:",
        RegexOptions.Compiled);

    private static readonly Regex SitemapLocRegex = new(
        "<loc>\\s*(?<u>[^<\\s]+)\\s*</loc>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex ScriptRouteRegex = new(
        "[\"'](?<u>/[a-zA-Z0-9][a-zA-Z0-9_./\\-{}:]*)[\"']",
        RegexOptions.Compiled);

    private static readonly Regex RouteLikePathRegex = new(
        "(?<u>/[a-zA-Z0-9][a-zA-Z0-9_./\\-]{0,120})",
        RegexOptions.Compiled);

    public static async Task<SpiderResult> CrawlSiteAsync(
        Uri baseUri,
        int maxPages,
        int maxDepth,
        bool includeCommonCandidates,
        Func<Func<HttpRequestMessage>, Task<HttpResponseMessage?>> safeSendAsync,
        Func<Uri, Task<JsonDocument?>> tryFetchOpenApiDocumentAsync)
    {
        var queue = new Queue<(Uri Uri, int Depth)>();
        var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var scheduled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var discoveredEndpoints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var failures = new List<string>();

        void EnqueueIfEligible(Uri candidate, int depth)
        {
            if (depth > maxDepth || !DiscoveryUtilities.IsSameOrigin(baseUri, candidate))
            {
                return;
            }

            var candidateKey = DiscoveryUtilities.NormalizeEndpointKey(candidate);
            if (visited.Contains(candidateKey) || !scheduled.Add(candidateKey))
            {
                return;
            }

            discoveredEndpoints.Add(candidateKey);
            queue.Enqueue((candidate, depth));
        }

        foreach (var seed in BuildSpiderSeeds(baseUri))
        {
            EnqueueIfEligible(seed, 0);
        }

        if (includeCommonCandidates)
        {
            foreach (var common in BuildCommonRouteCandidates(baseUri))
            {
                EnqueueIfEligible(common, 0);
            }
        }

        var openApiDocument = await tryFetchOpenApiDocumentAsync(baseUri);
        if (openApiDocument is not null)
        {
            try
            {
                foreach (var template in ExtractOpenApiPathTemplates(openApiDocument))
                {
                    foreach (var expanded in ExpandRouteTemplateCandidates(template))
                    {
                        try
                        {
                            var seeded = new Uri(baseUri, expanded);
                            if (!DiscoveryUtilities.IsSameOrigin(baseUri, seeded))
                            {
                                continue;
                            }

                            EnqueueIfEligible(seeded, 0);
                        }
                        catch
                        {
                            // Ignore invalid OpenAPI path entries.
                        }
                    }
                }
            }
            finally
            {
                openApiDocument.Dispose();
            }
        }

        while (queue.Count > 0 && visited.Count < maxPages)
        {
            var (current, depth) = queue.Dequeue();
            var key = DiscoveryUtilities.NormalizeEndpointKey(current);
            if (!visited.Add(key))
            {
                continue;
            }

            var response = await safeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, current));
            if (response is null)
            {
                failures.Add($"{current}: no response");
                continue;
            }

            discoveredEndpoints.Add(key);
            var body = await HttpEvidenceUtilities.ReadBodyAsync(response);
            if (string.IsNullOrWhiteSpace(body))
            {
                continue;
            }

            var mediaType = response.Content.Headers.ContentType?.MediaType ?? string.Empty;
            var isHtmlLike = mediaType.Contains("html", StringComparison.OrdinalIgnoreCase) ||
                             mediaType.Contains("xml", StringComparison.OrdinalIgnoreCase);
            var isJsonLike = mediaType.Contains("json", StringComparison.OrdinalIgnoreCase);
            var looksLikeHtml = isHtmlLike || body.Contains("<html", StringComparison.OrdinalIgnoreCase);
            var looksLikeJson = isJsonLike || body.TrimStart().StartsWith("{", StringComparison.Ordinal) || body.TrimStart().StartsWith("[", StringComparison.Ordinal);
            var looksLikeSitemap = mediaType.Contains("xml", StringComparison.OrdinalIgnoreCase) ||
                                   body.Contains("<urlset", StringComparison.OrdinalIgnoreCase) ||
                                   body.Contains("<sitemapindex", StringComparison.OrdinalIgnoreCase);

            if (depth < maxDepth && looksLikeHtml)
            {
                foreach (var raw in ExtractAttributeLinks(body))
                {
                    if (!DiscoveryUtilities.TryResolveSameOriginUri(current, raw, out var next))
                    {
                        continue;
                    }

                    var nextKey = DiscoveryUtilities.NormalizeEndpointKey(next);
                    if (!visited.Contains(nextKey))
                    {
                        EnqueueIfEligible(next, depth + 1);
                    }
                }
            }

            if (depth < maxDepth && looksLikeSitemap)
            {
                foreach (var raw in ExtractSitemapLocations(body))
                {
                    if (!DiscoveryUtilities.TryResolveSameOriginUri(current, raw, out var next))
                    {
                        continue;
                    }

                    var nextKey = DiscoveryUtilities.NormalizeEndpointKey(next);
                    if (!visited.Contains(nextKey))
                    {
                        EnqueueIfEligible(next, depth + 1);
                    }
                }
            }

            if (depth < maxDepth && (looksLikeHtml || mediaType.Contains("javascript", StringComparison.OrdinalIgnoreCase)))
            {
                foreach (var raw in ExtractScriptRouteLiterals(body))
                {
                    if (!DiscoveryUtilities.TryResolveSameOriginUri(current, raw, out var next))
                    {
                        continue;
                    }

                    var nextKey = DiscoveryUtilities.NormalizeEndpointKey(next);
                    if (!visited.Contains(nextKey))
                    {
                        EnqueueIfEligible(next, depth + 1);
                    }
                }
            }

            if (looksLikeJson || current.AbsolutePath.Contains("openapi", StringComparison.OrdinalIgnoreCase))
            {
                foreach (Match match in ApiPathRegex.Matches(body))
                {
                    var path = match.Groups["p"].Value;
                    if (!path.StartsWith("/", StringComparison.Ordinal))
                    {
                        continue;
                    }

                    try
                    {
                        var next = new Uri(baseUri, path);
                        if (DiscoveryUtilities.IsSameOrigin(baseUri, next))
                        {
                            var nextKey = DiscoveryUtilities.NormalizeEndpointKey(next);
                            discoveredEndpoints.Add(nextKey);
                            if (depth < maxDepth && !visited.Contains(nextKey))
                            {
                                EnqueueIfEligible(next, depth + 1);
                            }
                        }
                    }
                    catch
                    {
                        // Ignore parse errors from loose schema snippets.
                    }
                }
            }

            if (depth < maxDepth)
            {
                foreach (var raw in ExtractRouteLikeCandidates(body))
                {
                    if (!DiscoveryUtilities.TryResolveSameOriginUri(current, raw, out var next))
                    {
                        continue;
                    }

                    EnqueueIfEligible(next, depth + 1);
                }

                foreach (var variant in BuildPathVariants(current))
                {
                    EnqueueIfEligible(variant, depth + 1);
                }
            }
        }

        return new SpiderResult(visited, discoveredEndpoints, failures);
    }

    public static async Task<string> RunAdaptiveEndpointSweepAsync(
        Uri baseUri,
        IEnumerable<string> discoveredEndpoints,
        IReadOnlyList<DynamicProbe> sweepTests,
        IProgress<string>? progress = null)
    {
        var endpointUris = discoveredEndpoints
            .Select(e => Uri.TryCreate(e, UriKind.Absolute, out var parsed) ? parsed : null)
            .Where(u => u is not null)
            .Select(u => u!)
            .Where(u => DiscoveryUtilities.IsSameOrigin(baseUri, u))
            .DistinctBy(DiscoveryUtilities.NormalizeEndpointKey)
            .OrderBy(u => u.AbsolutePath, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (endpointUris.Count == 0)
        {
            return "[Adaptive Endpoint Sweep]\n- No discovered endpoints available for adaptive sweep.";
        }

        var sections = new List<string>();
        var executed = 0;
        var total = endpointUris.Count * sweepTests.Count;

        foreach (var endpoint in endpointUris)
        {
            foreach (var sweep in sweepTests)
            {
                executed++;
                progress?.Report($"Adaptive sweep: {executed}/{total} - {sweep.Name} @ {endpoint.AbsolutePath}");
                try
                {
                    sections.Add(await sweep.Execute(endpoint));
                }
                catch (Exception ex)
                {
                    sections.Add($"[{sweep.Name}] Target: {endpoint} - Execution error: {ex.Message}");
                }
            }
        }

        var riskSignals = sections.Sum(r => Regex.Matches(r, "Potential risk:", RegexOptions.IgnoreCase).Count);
        var sb = new StringBuilder();
        sb.AppendLine("[Adaptive Endpoint Sweep]");
        sb.AppendLine($"Endpoints sampled: {endpointUris.Count}");
        sb.AppendLine($"Checks executed: {sections.Count}");
        sb.AppendLine($"Potential-risk signals: {riskSignals}");
        sb.AppendLine("Sampled endpoints:");
        foreach (var endpoint in endpointUris)
        {
            sb.AppendLine($"- {endpoint}");
        }

        return sb.ToString().TrimEnd();
    }

    private static IEnumerable<string> ExtractOpenApiPathTemplates(JsonDocument document)
    {
        if (!document.RootElement.TryGetProperty("paths", out var paths) ||
            paths.ValueKind != JsonValueKind.Object)
        {
            yield break;
        }

        foreach (var path in paths.EnumerateObject())
        {
            if (string.IsNullOrWhiteSpace(path.Name))
            {
                continue;
            }

            yield return path.Name.StartsWith("/", StringComparison.Ordinal) ? path.Name : "/" + path.Name;
        }
    }

    private static IEnumerable<string> ExpandRouteTemplateCandidates(string pathTemplate)
    {
        if (string.IsNullOrWhiteSpace(pathTemplate))
        {
            yield break;
        }

        var normalized = pathTemplate.StartsWith("/", StringComparison.Ordinal) ? pathTemplate : "/" + pathTemplate;
        var hasPlaceholders = normalized.Contains('{') && normalized.Contains('}');
        if (!hasPlaceholders)
        {
            yield return normalized;
        }

        var concrete = Regex.Replace(normalized, "\\{(?<name>[^}/]+)\\}", match =>
        {
            var name = match.Groups["name"].Value.Trim().ToLowerInvariant();
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

        if (!string.Equals(concrete, normalized, StringComparison.OrdinalIgnoreCase))
        {
            yield return concrete;
        }
    }

    private static IEnumerable<string> ExtractRouteLikeCandidates(string body)
    {
        var found = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match match in RouteLikePathRegex.Matches(body))
        {
            var raw = match.Groups["u"].Value.Trim();
            if (string.IsNullOrWhiteSpace(raw) ||
                raw.Length < 2 ||
                raw.Contains("//", StringComparison.Ordinal) ||
                raw.EndsWith(".js", StringComparison.OrdinalIgnoreCase) ||
                raw.EndsWith(".css", StringComparison.OrdinalIgnoreCase) ||
                raw.EndsWith(".png", StringComparison.OrdinalIgnoreCase) ||
                raw.EndsWith(".jpg", StringComparison.OrdinalIgnoreCase) ||
                raw.EndsWith(".svg", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            found.Add(raw);
        }

        return found;
    }

    private static IEnumerable<Uri> BuildPathVariants(Uri current)
    {
        var variants = new List<Uri>();
        var trimmed = current.AbsolutePath.Trim('/');
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return variants;
        }

        var segments = trimmed.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0)
        {
            return variants;
        }

        var parent = "/" + string.Join('/', segments.Take(segments.Length - 1));
        if (parent.Length > 1 && Uri.TryCreate(current, parent, out var parentUri))
        {
            variants.Add(parentUri);
        }

        var leaf = segments[^1];
        if (Uri.TryCreate(current, leaf + "/1", out var numericChild))
        {
            variants.Add(numericChild);
        }
        if (Uri.TryCreate(current, leaf + "/test", out var testChild))
        {
            variants.Add(testChild);
        }

        return variants;
    }

    private static IEnumerable<Uri> BuildSpiderSeeds(Uri baseUri)
    {
        var paths = new[]
        {
            baseUri.ToString(),
            "/",
            "/robots.txt",
            "/sitemap.xml",
            "/swagger",
            "/swagger/index.html",
            "/swagger/v1/swagger.json",
            "/openapi.json",
            "/openapi/v1.json",
            "/.well-known/openid-configuration",
            "/graphql",
            "/api",
            "/v1",
            "/v2"
        };

        foreach (var path in paths)
        {
            Uri uri;
            try
            {
                uri = path.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? new Uri(path) : new Uri(baseUri, path);
            }
            catch
            {
                continue;
            }

            if (DiscoveryUtilities.IsSameOrigin(baseUri, uri))
            {
                yield return uri;
            }
        }
    }

    private static IEnumerable<Uri> BuildCommonRouteCandidates(Uri baseUri)
    {
        var staticPaths = new[]
        {
            "/health", "/status", "/ready", "/live", "/metrics", "/version", "/testapi",
            "/api", "/api/v1", "/api/v2", "/v1", "/v2",
            "/users", "/users/1", "/products", "/products/1", "/orders", "/orders/1",
            "/reports", "/files", "/secure", "/auth", "/login", "/logout", "/register",
            "/admin", "/search", "/docs", "/swagger", "/swagger/index.html"
        };

        var businessNouns = new[]
        {
            "account", "accounts", "wallet", "wallets", "balance", "balances",
            "payment", "payments", "transfer", "transfers", "withdraw", "withdrawal", "withdrawals",
            "deposit", "deposits", "payout", "payouts", "invoice", "invoices",
            "checkout", "cart", "orders", "refund", "refunds", "transaction", "transactions",
            "statement", "statements", "beneficiary", "beneficiaries"
        };

        var routeVariants = new[]
        {
            "", "/1", "/test", "/apitester", "/status", "/history", "/latest"
        };

        var prefixes = new[]
        {
            "", "/api", "/api/v1", "/api/v2", "/v1", "/v2"
        };

        var generated = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var path in staticPaths)
        {
            generated.Add(path);
        }

        foreach (var noun in businessNouns)
        {
            foreach (var prefix in prefixes)
            {
                foreach (var variant in routeVariants)
                {
                    var full = $"{prefix}/{noun}{variant}".Replace("//", "/");
                    if (!full.StartsWith("/", StringComparison.Ordinal))
                    {
                        full = "/" + full;
                    }

                    generated.Add(full);
                }
            }
        }

        foreach (var path in generated)
        {
            if (Uri.TryCreate(baseUri, path, out var uri) && uri is not null && DiscoveryUtilities.IsSameOrigin(baseUri, uri))
            {
                yield return uri;
            }
        }
    }

    private static List<string> ExtractAttributeLinks(string body)
    {
        var links = new List<string>();
        foreach (Match match in LinkAttributeRegex.Matches(body))
        {
            var raw = match.Groups["u"].Value.Trim();
            if (!string.IsNullOrWhiteSpace(raw))
            {
                links.Add(raw);
            }
        }

        return links;
    }

    private static List<string> ExtractSitemapLocations(string body)
    {
        var links = new List<string>();
        foreach (Match match in SitemapLocRegex.Matches(body))
        {
            var raw = match.Groups["u"].Value.Trim();
            if (!string.IsNullOrWhiteSpace(raw))
            {
                links.Add(raw);
            }
        }

        return links;
    }

    private static List<string> ExtractScriptRouteLiterals(string body)
    {
        var links = new List<string>();
        foreach (Match match in ScriptRouteRegex.Matches(body))
        {
            var raw = match.Groups["u"].Value.Trim();
            if (!string.IsNullOrWhiteSpace(raw))
            {
                links.Add(raw);
            }
        }

        return links;
    }
}
