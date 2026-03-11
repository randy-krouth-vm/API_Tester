using System.Text;
using System.Text.Json;
using System.Linq;

namespace API_Tester.SecurityCatalog;

public static class CveCorpusService
{
    private const string NvdApi = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private static Func<HttpClient> HttpClientFactory = CreateDefaultHttpClient;
    private static Func<string> AppDataDirectoryProvider = () => Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
    private static readonly string CacheDirectoryPath = ResolveCacheDirectory();

    private static string DataFilePath => Path.Combine(CacheDirectoryPath, "cve-corpus.ndjson");
    private static string MetaFilePath => Path.Combine(CacheDirectoryPath, "cve-corpus.meta.json");
    private static string FunctionMapFilePath => Path.Combine(CacheDirectoryPath, "cve-function-map.ndjson");
    private static string FunctionMapMetaFilePath => Path.Combine(CacheDirectoryPath, "cve-function-map.meta.json");
    private static readonly object CorpusPageCacheLock = new();
    private static CorpusPageCacheEntry? CorpusPageCache;
    private static readonly object FunctionMapPageCacheLock = new();
    private static FunctionMapPageCacheEntry? FunctionMapPageCache;
    private static readonly object FunctionMapFilterCacheLock = new();
    private static readonly Dictionary<string, FunctionMapFilterCacheEntry> FunctionMapFilterCache = new(StringComparer.OrdinalIgnoreCase);

    public static void ConfigureHttpClientFactory(Func<HttpClient> factory)
    {
        if (factory is null)
        {
            return;
        }

        HttpClientFactory = factory;
    }

    public static void ConfigureAppDataDirectoryProvider(Func<string> provider)
    {
        if (provider is null)
        {
            return;
        }

        AppDataDirectoryProvider = provider;
    }

    private static HttpClient CreateDefaultHttpClient() =>
    new() { Timeout = TimeSpan.FromSeconds(60) };

    public static async Task<bool> HasCorpusAsync() => await Task.FromResult(File.Exists(DataFilePath) && File.Exists(MetaFilePath));
    public static async Task<bool> HasFunctionMapAsync() => await Task.FromResult(File.Exists(FunctionMapFilePath) && File.Exists(FunctionMapMetaFilePath));

    public static string BuildLocalFileStatus()
    {
        static string FormatFileStatus(string path, string label)
        {
            if (!File.Exists(path))
            {
                return $"- {label}: missing";
            }

            var info = new FileInfo(path);
            return $"- {label}: present | updated (UTC): {info.LastWriteTimeUtc:yyyy-MM-dd HH:mm:ss}Z | size: {info.Length:N0} bytes";
        }

        var sb = new StringBuilder();
        sb.AppendLine(FormatFileStatus(DataFilePath, "cve-corpus.ndjson"));
        sb.AppendLine(FormatFileStatus(MetaFilePath, "cve-corpus.meta.json"));
        sb.AppendLine(FormatFileStatus(FunctionMapFilePath, "cve-function-map.ndjson"));
        sb.Append(FormatFileStatus(FunctionMapMetaFilePath, "cve-function-map.meta.json"));
        return sb.ToString();
    }

    public static async Task<CveCorpusMetadata?> LoadMetadataAsync()
    {
        if (!File.Exists(MetaFilePath))
        {
            return await TryRebuildCorpusMetadataAsync();
        }

        try
        {
            var json = await File.ReadAllTextAsync(MetaFilePath);
            var parsed = JsonSerializer.Deserialize<CveCorpusMetadata>(json);
            return parsed ?? await TryRebuildCorpusMetadataAsync();
        }
        catch
        {
            return await TryRebuildCorpusMetadataAsync();
        }
    }

    private static async Task<CveCorpusMetadata?> TryRebuildCorpusMetadataAsync()
    {
        if (!File.Exists(DataFilePath))
        {
            return null;
        }

        var count = 0;
        using (var stream = new FileStream(DataFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var reader = new StreamReader(stream, Encoding.UTF8))
        {
            while (true)
            {
                var line = await reader.ReadLineAsync();
                if (line is null)
                {
                    break;
                }

                if (!string.IsNullOrWhiteSpace(line))
                {
                    count++;
                }
            }
        }

        var fileInfo = new FileInfo(DataFilePath);
        var rebuilt = new CveCorpusMetadata(
        "Local cache (metadata rebuilt from cve-corpus.ndjson)",
        fileInfo.LastWriteTimeUtc.ToString("yyyy-MM-ddTHH:mm:ssZ"),
        count,
        count,
        "Metadata was missing or invalid and was rebuilt from local corpus file.");

        try
        {
            await File.WriteAllTextAsync(
            MetaFilePath,
            JsonSerializer.Serialize(rebuilt, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch
        {
            // If write fails, still return reconstructed metadata for in-memory use.
        }

        return rebuilt;
    }

    public static async Task<string> BuildSummaryAsync()
    {
        var meta = await LoadMetadataAsync();
        if (meta is null || !File.Exists(DataFilePath))
        {
            return "CVE corpus not present. Use 'Sync Complete CVE Corpus (NVD)' first.";
        }

        var sb = new StringBuilder();
        sb.AppendLine("=== Local CVE Corpus (NVD 2.0) ===");
        sb.AppendLine($"Source: {meta.Source}");
        sb.AppendLine($"Synced At (UTC): {meta.SyncedAtUtc}");
        sb.AppendLine($"Stored CVE Count: {meta.Count}");
        sb.AppendLine($"NVD Total Results At Sync: {meta.TotalResults}");
        sb.AppendLine($"Notes: {meta.Notes}");
        sb.AppendLine();
        sb.AppendLine("Coverage Mapping:");
        sb.AppendLine("- Mapping is heuristic (CWE + description keywords) and indicates likely coverage probes.");
        sb.AppendLine();

        var coverageCounts = new Dictionary<string, int>(StringComparer.Ordinal);
        var unmapped = 0;
        var totalMappedRecords = 0;

        await foreach (var record in ReadRecordsAsync())
        {
            var mapped = CveCoverageMapper.MapToFunctions(record);
            if (mapped.Count == 0)
            {
                unmapped++;
            }
            else
            {
                totalMappedRecords++;
                foreach (var function in mapped)
                {
                    coverageCounts.TryGetValue(function, out var current);
                    coverageCounts[function] = current + 1;
                }
            }

        }

        sb.AppendLine($"Mapped CVEs: {totalMappedRecords}");
        sb.AppendLine($"Unmapped CVEs: {unmapped}");
        sb.AppendLine();
        sb.AppendLine("Top mapped probe functions:");
        foreach (var kv in coverageCounts
        .OrderByDescending(x => x.Value)
        .ThenBy(x => x.Key, StringComparer.Ordinal)
        .Take(20))
        {
            sb.AppendLine($"- {kv.Key}: {kv.Value}");
        }
        if (coverageCounts.Count == 0)
        {
            sb.AppendLine("- None");
        }
        return sb.ToString().TrimEnd();
    }

    public static async Task<CveCorpusMetadata> SyncFromNvdAsync(IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        var apiKey = Environment.GetEnvironmentVariable("NVD_API_KEY");
        var pageSize = 2000;
        var startIndex = 0;
        var totalResults = int.MaxValue;
        var writeCount = 0;

        Directory.CreateDirectory(CacheDirectoryPath);
        if (File.Exists(DataFilePath))
        {
            File.Delete(DataFilePath);
        }

        using var writer = new StreamWriter(DataFilePath, false, Encoding.UTF8);

        while (startIndex < totalResults)
        {
            cancellationToken.ThrowIfCancellationRequested();

            var url = $"{NvdApi}?startIndex={startIndex}&resultsPerPage={pageSize}";
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            if (!string.IsNullOrWhiteSpace(apiKey))
            {
                request.Headers.TryAddWithoutValidation("apiKey", apiKey);
            }

            using var client = HttpClientFactory();
            using var response = await client.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();
            var json = await response.Content.ReadAsStringAsync(cancellationToken);

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            totalResults = root.GetProperty("totalResults").GetInt32();
            var vulnerabilities = root.GetProperty("vulnerabilities");
            var fetched = vulnerabilities.GetArrayLength();

            foreach (var vuln in vulnerabilities.EnumerateArray())
            {
                var cve = vuln.GetProperty("cve");
                var id = GetString(cve, "id");
                var published = GetString(cve, "published");
                var lastModified = GetString(cve, "lastModified");
                var source = GetString(cve, "sourceIdentifier");
                var description = GetDescription(cve);
                var (severity, score) = GetSeverityAndScore(cve);
                var cwe = GetCwe(cve);

                var record = new CveRecord(id, published, lastModified, source, description, severity, score, cwe);
                await writer.WriteLineAsync(JsonSerializer.Serialize(record));
                writeCount++;
            }

            await writer.FlushAsync();
            progress?.Report($"Fetched {writeCount}/{totalResults} CVEs...");
            startIndex += fetched;

            if (fetched == 0)
            {
                break;
            }

            // NVD rate limits are stricter without an API key.
            var delayMs = string.IsNullOrWhiteSpace(apiKey) ? 7000 : 800;
            await Task.Delay(delayMs, cancellationToken);
        }

        var meta = new CveCorpusMetadata(
        "NVD CVE API 2.0",
        DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
        writeCount,
        totalResults == int.MaxValue ? writeCount : totalResults,
        string.IsNullOrWhiteSpace(apiKey)
        ? "Synced without NVD_API_KEY; throttled request pacing applied."
        : "Synced with NVD_API_KEY.");

        await File.WriteAllTextAsync(MetaFilePath, JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true }), cancellationToken);
        lock (CorpusPageCacheLock)
        {
            CorpusPageCache = null;
        }
        progress?.Report($"Sync complete. Stored {writeCount} CVEs.");
        return meta;
    }

    public static string GetCacheDirectoryPath() => CacheDirectoryPath;

    public static async Task<string> BuildCorpusPageAsync(int page, int pageSize = 250)
    {
        var pageData = await GetCorpusPageAsync(page, pageSize);

        var sb = new StringBuilder();
        sb.AppendLine("=== CVE Corpus Paged View ===");
        sb.AppendLine($"Page: {pageData.Page}/{pageData.TotalPages} | Page size: {pageData.PageSize} | Total CVEs: {pageData.TotalRows}");
        sb.AppendLine($"Total elements in memory: {pageData.TotalRows}");
        var startIndex = Math.Max(0, (pageData.Page - 1) * pageData.PageSize);
        var endExclusive = startIndex + pageData.Rows.Count;
        sb.AppendLine($"In-memory slice: [{startIndex}, {endExclusive})");
        var firstRow = pageData.Rows.Count == 0 ? 0 : pageData.Rows[0].RowNumber;
        var lastRow = pageData.Rows.Count == 0 ? 0 : pageData.Rows[^1].RowNumber;
        sb.AppendLine($"Showing rows {firstRow} to {lastRow}");
        sb.AppendLine();
        for (var i = 0; i < pageData.Rows.Count; i++)
        {
            var row = pageData.Rows[i];
            sb.AppendLine($"- [{row.RowNumber}] {row.CveId}");
        }

        if (pageData.Rows.Count == 0)
        {
            sb.AppendLine("- No rows in this page.");
        }

        return sb.ToString().TrimEnd();
    }

    public static async Task<string> BuildFunctionMapPageAsync(int page, int pageSize = 250)
    {
        var pageData = await GetFunctionMapPageAsync(page, pageSize);

        var sb = new StringBuilder();
        sb.AppendLine("=== CVE Function Map Paged View ===");
        sb.AppendLine($"Page: {pageData.Page} of {pageData.TotalPages} | Page size: {pageData.PageSize} | Total mapped CVEs: {pageData.TotalRows}");
        sb.AppendLine($"Total elements in memory: {pageData.TotalRows}");
        var startIndex = Math.Max(0, (pageData.Page - 1) * pageData.PageSize);
        var firstRow = pageData.Rows.Count == 0 ? 0 : pageData.Rows[0].RowNumber;
        var lastRow = pageData.Rows.Count == 0 ? 0 : pageData.Rows[^1].RowNumber;
        sb.AppendLine($"Showing rows {firstRow} to {lastRow}");
        sb.AppendLine();
        for (var i = 0; i < pageData.Rows.Count; i++)
        {
            var row = pageData.Rows[i];
            sb.AppendLine($"- [{row.RowNumber}] {row.CveId}");
        }

        if (pageData.Rows.Count == 0)
        {
            sb.AppendLine("- No rows in this page.");
        }

        return sb.ToString().TrimEnd();
    }

    public static async Task<CveCorpusPageResult> GetCorpusPageAsync(int page, int pageSize = 250)
    {
        if (!File.Exists(DataFilePath))
        {
            return new CveCorpusPageResult(1, 1, pageSize, 0, Array.Empty<CveCorpusPageRow>());
        }

        var allRows = await EnsureCorpusPageCacheAsync();
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 25, 2000);
        var totalRows = allRows.Length;
        var totalPages = Math.Max(1, (int)Math.Ceiling(totalRows / (double)pageSize));
        if (page > totalPages)
        {
            page = totalPages;
        }

        var start = (page - 1) * pageSize;
        var rows = allRows.Skip(start).Take(pageSize).ToArray();

        return new CveCorpusPageResult(page, totalPages, pageSize, totalRows, rows);
    }

    public static async Task<CveFunctionMapPageResult> GetFunctionMapPageAsync(int page, int pageSize = 250)
    {
        if (!File.Exists(FunctionMapFilePath))
        {
            return new CveFunctionMapPageResult(1, 1, pageSize, 0, Array.Empty<CveFunctionMapPageRow>());
        }

        var allRows = await EnsureFunctionMapPageCacheAsync();
        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 25, 2000);
        var totalRows = allRows.Length;
        var totalPages = Math.Max(1, (int)Math.Ceiling(totalRows / (double)pageSize));
        if (page > totalPages)
        {
            page = totalPages;
        }

        var start = (page - 1) * pageSize;
        var rows = allRows.Skip(start).Take(pageSize).ToArray();

        return new CveFunctionMapPageResult(page, totalPages, pageSize, totalRows, rows);
    }

    public static async Task<IReadOnlyList<CveFunctionMapPageRow>> GetAllFunctionMapRowsByConfidenceAsync(string confidence)
    {
        if (string.IsNullOrWhiteSpace(confidence) ||
        confidence.Equals("Off", StringComparison.OrdinalIgnoreCase) ||
        !File.Exists(FunctionMapFilePath))
        {
            return Array.Empty<CveFunctionMapPageRow>();
        }

        var normalized = confidence.Trim().ToUpperInvariant();
        var allRows = await EnsureFunctionMapPageCacheAsync();
        return allRows
        .Where(r => r.Confidence.Equals(normalized, StringComparison.OrdinalIgnoreCase))
        .ToArray();
    }

    public static async Task<CveFunctionMapPageResult> GetFunctionMapFilteredPageAsync(
    string confidence,
    int page,
    int pageSize = 250)
    {
        if (string.IsNullOrWhiteSpace(confidence) ||
        confidence.Equals("Off", StringComparison.OrdinalIgnoreCase) ||
        !File.Exists(FunctionMapFilePath))
        {
            return new CveFunctionMapPageResult(1, 1, pageSize, 0, Array.Empty<CveFunctionMapPageRow>());
        }

        var normalized = confidence.Trim().ToUpperInvariant();
        CveFunctionMapPageRow[] sorted;

        lock (FunctionMapFilterCacheLock)
        {
            if (FunctionMapFilterCache.TryGetValue(normalized, out var cached))
            {
                sorted = cached.Rows;
            }
            else
            {
                sorted = Array.Empty<CveFunctionMapPageRow>();
            }
        }

        if (sorted.Length == 0)
        {
            var all = await GetAllFunctionMapRowsByConfidenceAsync(normalized);
            sorted = await Task.Run(() => all
            .OrderByDescending(r => ParseInvariantDouble(r.RealWorldCoverageScore))
            .ThenByDescending(r => ParseInvariantDouble(r.ConfidenceScore))
            .ThenBy(r => r.CveId, StringComparer.OrdinalIgnoreCase)
            .ToArray());

            lock (FunctionMapFilterCacheLock)
            {
                FunctionMapFilterCache[normalized] = new FunctionMapFilterCacheEntry(sorted);
            }
        }

        if (sorted.Length == 0)
        {
            return new CveFunctionMapPageResult(1, 1, pageSize, 0, Array.Empty<CveFunctionMapPageRow>());
        }

        page = Math.Max(1, page);
        pageSize = Math.Clamp(pageSize, 25, 2000);
        var totalRows = sorted.Length;
        var totalPages = Math.Max(1, (int)Math.Ceiling(totalRows / (double)pageSize));
        if (page > totalPages)
        {
            page = totalPages;
        }

        var start = (page - 1) * pageSize;
        var rows = sorted.Skip(start).Take(pageSize).ToArray();
        return new CveFunctionMapPageResult(page, totalPages, pageSize, totalRows, rows);
    }

    public static async Task<string> BuildCveLookupAsync(string cveId)
    {
        var normalized = (cveId ?? string.Empty).Trim().ToUpperInvariant();
        if (string.IsNullOrWhiteSpace(normalized))
        {
            return "Enter a CVE ID (for example: CVE-2024-12345).";
        }

        CveRecord? corpusRecord = null;
        CveFunctionMapRecord? mapRecord = null;

        if (File.Exists(DataFilePath))
        {
            using var stream = new FileStream(DataFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var reader = new StreamReader(stream, Encoding.UTF8);
            while (true)
            {
                var line = await reader.ReadLineAsync();
                if (line is null)
                {
                    break;
                }

                if (!line.Contains(normalized, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                try
                {
                    var parsed = JsonSerializer.Deserialize<CveRecord>(line);
                    if (parsed is not null && string.Equals(parsed.CveId, normalized, StringComparison.OrdinalIgnoreCase))
                    {
                        corpusRecord = parsed;
                        break;
                    }
                }
                catch
                {
                    // ignore malformed rows
                }
            }
        }

        if (File.Exists(FunctionMapFilePath))
        {
            using var stream = new FileStream(FunctionMapFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            using var reader = new StreamReader(stream, Encoding.UTF8);
            while (true)
            {
                var line = await reader.ReadLineAsync();
                if (line is null)
                {
                    break;
                }

                if (!line.Contains(normalized, StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var parsed = ParseFunctionMapRecord(line);
                if (parsed is not null && string.Equals(parsed.CveId, normalized, StringComparison.OrdinalIgnoreCase))
                {
                    mapRecord = parsed;
                    break;
                }
            }
        }

        if (corpusRecord is null && mapRecord is null)
        {
            return $"CVE not found in local files: {normalized}";
        }

        var sb = new StringBuilder();
        sb.AppendLine("=== CVE Lookup ===");
        sb.AppendLine($"Query: {normalized}");
        sb.AppendLine();

        if (corpusRecord is not null)
        {
            sb.AppendLine("[Corpus]");
            sb.AppendLine($"- CVE: {corpusRecord.CveId}");
            sb.AppendLine($"- Severity: {corpusRecord.Severity}");
            sb.AppendLine($"- Score: {corpusRecord.Score?.ToString("F1") ?? "n/a"}");
            sb.AppendLine($"- CWE: {corpusRecord.Cwe}");
            sb.AppendLine($"- Published: {corpusRecord.Published}");
            sb.AppendLine($"- LastModified: {corpusRecord.LastModified}");
            sb.AppendLine($"- Source: {corpusRecord.Source}");
            sb.AppendLine($"- Description: {corpusRecord.Description}");
            sb.AppendLine();
        }

        if (mapRecord is not null)
        {
            sb.AppendLine("[Internal Mapping]");
            sb.AppendLine("- Note: Scores use the default internal test template.");
            sb.AppendLine("- Tuning internal default settings can improve practical coverage for specific environments.");
            sb.AppendLine($"- {CveCoverageMapper.ToDetectionLabel(mapRecord.Confidence)}");
            sb.AppendLine($"- Confidence score: {mapRecord.ConfidenceScore:F2}");
            sb.AppendLine($"- EstimatedDefaultCoverage: {mapRecord.RealWorldCoverageScore:F2}/100");
            sb.AppendLine("- Functions:");
            if (!mapRecord.Functions.Any())
            {
                sb.AppendLine("  - None");
            }
            else
            {
                foreach (var function in mapRecord.Functions)
                {
                    sb.AppendLine($"  - {function}");
                }
            }
            sb.AppendLine($"- Default settings: {mapRecord.DefaultSettings}");
            sb.AppendLine($"- Signals: {string.Join(", ", mapRecord.Signals)}");
        }

        return sb.ToString().TrimEnd();
    }

    public static async Task<CveFunctionMapMetadata> BuildFunctionMapAsync(IProgress<string>? progress = null, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(DataFilePath))
        {
            throw new FileNotFoundException("CVE corpus file was not found. Sync CVEs first.", DataFilePath);
        }

        Directory.CreateDirectory(CacheDirectoryPath);
        if (File.Exists(FunctionMapFilePath))
        {
            File.Delete(FunctionMapFilePath);
        }

        var processed = 0;
        var high = 0;
        var medium = 0;
        var low = 0;
        var uniqueFunctions = new HashSet<string>(StringComparer.Ordinal);

        using var writer = new StreamWriter(FunctionMapFilePath, false, Encoding.UTF8);
        await foreach (var record in ReadRecordsAsync())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var mapped = CveCoverageMapper.MapWithDiagnostics(record);

            switch (mapped.Confidence)
            {
                case "high":
                    high++;
                    break;
                case "medium":
                    medium++;
                    break;
                default:
                    low++;
                    break;
            }

            foreach (var function in mapped.Functions)
            {
                uniqueFunctions.Add(function);
            }

            var score = CveCoverageMapper.CalculatePerformanceConfidenceScore(
            mapped.Confidence,
            mapped.Functions,
            mapped.Signals);
            var defaultSettings = CveCoverageMapper.BuildDefaultSettingsProfile(mapped.Functions);
            var preventionScore = CveCoverageMapper.CalculateDefaultSettingsPreventionScore(score, mapped.Functions);
            var realWorldCoverageScore = CveCoverageMapper.CalculateRealWorldCoverageScore(
            mapped.Confidence,
            score,
            preventionScore,
            mapped.Functions,
            mapped.Signals,
            defaultSettings);
            var mapRecord = new CveFunctionMapRecord(
            record.CveId,
            record.Cwe,
            record.Severity,
            mapped.Functions.ToArray(),
            mapped.Confidence,
            score,
            preventionScore,
            realWorldCoverageScore,
            defaultSettings,
            mapped.Signals.ToArray());

            await writer.WriteLineAsync(JsonSerializer.Serialize(mapRecord));
            processed++;

            if (processed % 2000 == 0)
            {
                progress?.Report($"Mapped {processed} CVEs to internal functions...");
                await writer.FlushAsync();
            }
        }

        await writer.FlushAsync();

        var meta = new CveFunctionMapMetadata(
        "Generated from local NVD corpus",
        DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"),
        processed,
        high,
        medium,
        low,
        uniqueFunctions.Count,
        "Heuristic mapping using CWE, description keywords, and defensive fallback.");

        await File.WriteAllTextAsync(
        FunctionMapMetaFilePath,
        JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true }),
        cancellationToken);

        lock (FunctionMapFilterCacheLock)
        {
            FunctionMapFilterCache.Clear();
        }
        lock (FunctionMapPageCacheLock)
        {
            FunctionMapPageCache = null;
        }

        progress?.Report($"Function mapping complete. Processed {processed} CVEs.");
        return meta;
    }

    public static async Task<string> BuildFunctionMapSummaryAsync()
    {
        if (!File.Exists(FunctionMapMetaFilePath) || !File.Exists(FunctionMapFilePath))
        {
            return "Function map not present. Use 'Build CVE Function Map' first.";
        }

        CveFunctionMapMetadata? meta;
        try
        {
            meta = JsonSerializer.Deserialize<CveFunctionMapMetadata>(await File.ReadAllTextAsync(FunctionMapMetaFilePath));
        }
        catch
        {
            meta = null;
        }

        if (meta is null)
        {
            return "Function map metadata could not be loaded.";
        }

        var topFunctions = new Dictionary<string, int>(StringComparer.Ordinal);
        double scoreTotal = 0;
        var scoreCount = 0;
        double preventionTotal = 0;
        double realWorldCoverageTotal = 0;
        var rwHigh = 0;
        var rwMedium = 0;
        var rwLow = 0;

        using (var stream = new FileStream(FunctionMapFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var reader = new StreamReader(stream, Encoding.UTF8))
        {
            while (true)
            {
                var line = await reader.ReadLineAsync();
                if (line is null)
                {
                    break;
                }

                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                var record = ParseFunctionMapRecord(line);
                if (record is null)
                {
                    continue;
                }

                scoreTotal += record.ConfidenceScore;
                preventionTotal += record.DefaultSettingsPreventionScore;
                realWorldCoverageTotal += record.RealWorldCoverageScore;
                scoreCount++;
                if (record.RealWorldCoverageScore >= 80)
                {
                    rwHigh++;
                }
                else if (record.RealWorldCoverageScore >= 60)
                {
                    rwMedium++;
                }
                else
                {
                    rwLow++;
                }

                foreach (var function in record.Functions)
                {
                    topFunctions.TryGetValue(function, out var current);
                    topFunctions[function] = current + 1;
                }
            }
        }

        var sb = new StringBuilder();
        sb.AppendLine("=== CVE Internal Function Map Summary ===");
        sb.AppendLine($"Generated At (UTC): {meta.GeneratedAtUtc}");
        sb.AppendLine($"Mapped CVEs: {meta.Count}");
        sb.AppendLine($"Confidence: high={meta.HighConfidence}, medium={meta.MediumConfidence}, low={meta.LowConfidence}");
        sb.AppendLine($"Average confidence score: {(scoreCount == 0 ? 0 : (scoreTotal / scoreCount)):F2}");
        sb.AppendLine($"Average EstimatedDefaultCoverage: {(scoreCount == 0 ? 0 : (realWorldCoverageTotal / scoreCount)):F2}/100");
        sb.AppendLine($"Real-world coverage bands: high(>=80)={rwHigh}, medium(60-79.99)={rwMedium}, low(<60)={rwLow}");
        sb.AppendLine($"Unique internal functions covered: {meta.UniqueFunctionsCovered}");
        sb.AppendLine($"Notes: {meta.Notes}");
        sb.AppendLine("Coverage note: values are based on the default internal test template.");
        sb.AppendLine("Coverage note: modifying internal default settings can increase practical coverage.");
        sb.AppendLine();
        sb.AppendLine("Top mapped internal functions:");
        foreach (var kv in topFunctions.OrderByDescending(x => x.Value).ThenBy(x => x.Key, StringComparer.Ordinal).Take(20))
        {
            sb.AppendLine($"- {kv.Key}: {kv.Value}");
        }

        if (topFunctions.Count == 0)
        {
            sb.AppendLine("- None");
        }

        return sb.ToString().TrimEnd();
    }

    private static async IAsyncEnumerable<CveRecord> ReadRecordsAsync()
    {
        if (!File.Exists(DataFilePath))
        {
            yield break;
        }

        using var stream = new FileStream(DataFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var reader = new StreamReader(stream, Encoding.UTF8);
        while (true)
        {
            var line = await reader.ReadLineAsync();
            if (line is null)
            {
                break;
            }

            if (string.IsNullOrWhiteSpace(line))
            {
                continue;
            }

            CveRecord? record;
            try
            {
                record = JsonSerializer.Deserialize<CveRecord>(line);
            }
            catch
            {
                continue;
            }

            if (record is not null)
            {
                yield return record;
            }
        }
    }

    private static string GetString(JsonElement element, string property)
    {
        return element.TryGetProperty(property, out var value) && value.ValueKind == JsonValueKind.String
        ? value.GetString() ?? string.Empty
        : string.Empty;
    }

    private static CveFunctionMapRecord? ParseFunctionMapRecord(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return null;
        }

        try
        {
            var direct = JsonSerializer.Deserialize<CveFunctionMapRecord>(line);
            if (direct is not null)
            {
                if (direct.RealWorldCoverageScore > 0)
                {
                    return direct;
                }

                // Backfill real-world score for legacy rows that predate this field.
                var recomputed = CveCoverageMapper.CalculateRealWorldCoverageScore(
                direct.Confidence,
                direct.ConfidenceScore,
                direct.DefaultSettingsPreventionScore,
                direct.Functions,
                direct.Signals,
                direct.DefaultSettings);

                return direct with { RealWorldCoverageScore = recomputed };
            }
        }
        catch
        {
            // Fall through to tolerant parser for legacy rows.
        }

        try
        {
            using var doc = JsonDocument.Parse(line);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                return null;
            }

            var cveId = GetString(root, "CveId");
            if (string.IsNullOrWhiteSpace(cveId))
            {
                return null;
            }

            var cwe = GetString(root, "Cwe");
            var severity = GetString(root, "Severity");
            var confidence = GetString(root, "Confidence");
            var confidenceScore = root.TryGetProperty("ConfidenceScore", out var cs) && cs.ValueKind == JsonValueKind.Number ? cs.GetDouble() : 0.0;
            var preventionScore = root.TryGetProperty("DefaultSettingsPreventionScore", out var ps) && ps.ValueKind == JsonValueKind.Number ? ps.GetDouble() : 0.0;
            var defaultSettings = GetString(root, "DefaultSettings");

            var functions = root.TryGetProperty("Functions", out var fns) && fns.ValueKind == JsonValueKind.Array
            ? fns.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString() ?? string.Empty).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray()
            : Array.Empty<string>();
            var signals = root.TryGetProperty("Signals", out var sigs) && sigs.ValueKind == JsonValueKind.Array
            ? sigs.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString() ?? string.Empty).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray()
            : Array.Empty<string>();
            var realWorldCoverageScore = root.TryGetProperty("RealWorldCoverageScore", out var rws) && rws.ValueKind == JsonValueKind.Number
            ? rws.GetDouble()
            : CveCoverageMapper.CalculateRealWorldCoverageScore(
            confidence,
            confidenceScore,
            preventionScore,
            functions,
            signals,
            defaultSettings);
            if (realWorldCoverageScore <= 0)
            {
                realWorldCoverageScore = CveCoverageMapper.CalculateRealWorldCoverageScore(
                confidence,
                confidenceScore,
                preventionScore,
                functions,
                signals,
                defaultSettings);
            }

            return new CveFunctionMapRecord(
            cveId,
            cwe,
            severity,
            functions,
            confidence,
            confidenceScore,
            preventionScore,
            realWorldCoverageScore,
            defaultSettings,
            signals);
        }
        catch
        {
            return null;
        }
    }

    private static double ParseInvariantDouble(string value) =>
    double.TryParse(value, out var parsed) ? parsed : 0.0;

    private static async Task<CveCorpusPageRow[]> EnsureCorpusPageCacheAsync()
    {
        lock (CorpusPageCacheLock)
        {
            if (CorpusPageCache is not null)
            {
                return CorpusPageCache.Rows;
            }
        }

        var rows = new List<CveCorpusPageRow>(4096);
        using (var stream = new FileStream(DataFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var reader = new StreamReader(stream, Encoding.UTF8))
        {
            while (true)
            {
                var line = await reader.ReadLineAsync();
                if (line is null)
                {
                    break;
                }

                try
                {
                    var record = JsonSerializer.Deserialize<CveRecord>(line);
                    if (record is null)
                    {
                        continue;
                    }

                    rows.Add(new CveCorpusPageRow(
                    rows.Count + 1,
                    record.CveId,
                    record.Severity,
                    record.Score?.ToString("F1") ?? "n/a",
                    record.Cwe));
                }
                catch
                {
                    // skip malformed records
                }
            }
        }

        var cached = new CorpusPageCacheEntry(rows.ToArray());
        lock (CorpusPageCacheLock)
        {
            CorpusPageCache ??= cached;
            return CorpusPageCache.Rows;
        }
    }

    private static async Task<CveFunctionMapPageRow[]> EnsureFunctionMapPageCacheAsync()
    {
        lock (FunctionMapPageCacheLock)
        {
            if (FunctionMapPageCache is not null)
            {
                return FunctionMapPageCache.Rows;
            }
        }

        var rows = new List<CveFunctionMapPageRow>(4096);
        using (var stream = new FileStream(FunctionMapFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var reader = new StreamReader(stream, Encoding.UTF8))
        {
            while (true)
            {
                var line = await reader.ReadLineAsync();
                if (line is null)
                {
                    break;
                }

                var record = ParseFunctionMapRecord(line);
                if (record is null)
                {
                    continue;
                }

                var preview = string.Join(", ", record.Functions);
                rows.Add(new CveFunctionMapPageRow(
                rows.Count + 1,
                record.CveId,
                record.Confidence.ToUpperInvariant(),
                record.ConfidenceScore.ToString("F2"),
                record.DefaultSettingsPreventionScore.ToString("F1"),
                record.RealWorldCoverageScore.ToString("F1"),
                record.Cwe,
                preview));
            }
        }

        var cached = new FunctionMapPageCacheEntry(rows.ToArray());
        lock (FunctionMapPageCacheLock)
        {
            FunctionMapPageCache ??= cached;
            return FunctionMapPageCache.Rows;
        }
    }

    private sealed record CorpusPageCacheEntry(
    CveCorpusPageRow[] Rows);

    private sealed record FunctionMapPageCacheEntry(
    CveFunctionMapPageRow[] Rows);

    private sealed record FunctionMapFilterCacheEntry(
    CveFunctionMapPageRow[] Rows);

    private static string GetDescription(JsonElement cve)
    {
        if (!cve.TryGetProperty("descriptions", out var descriptions) || descriptions.ValueKind != JsonValueKind.Array)
        {
            return string.Empty;
        }

        foreach (var item in descriptions.EnumerateArray())
        {
            var lang = GetString(item, "lang");
            if (lang.Equals("en", StringComparison.OrdinalIgnoreCase))
            {
                return GetString(item, "value");
            }
        }

        return descriptions.GetArrayLength() > 0 ? GetString(descriptions[0], "value") : string.Empty;
    }

    private static (string Severity, double? Score) GetSeverityAndScore(JsonElement cve)
    {
        if (!cve.TryGetProperty("metrics", out var metrics) || metrics.ValueKind != JsonValueKind.Object)
        {
            return ("Unknown", null);
        }

        var metricFamilies = new[] { "cvssMetricV31", "cvssMetricV30", "cvssMetricV2" };
        foreach (var family in metricFamilies)
        {
            if (!metrics.TryGetProperty(family, out var list) || list.ValueKind != JsonValueKind.Array || list.GetArrayLength() == 0)
            {
                continue;
            }

            var first = list[0];
            if (!first.TryGetProperty("cvssData", out var cvssData))
            {
                continue;
            }

            var severity = GetString(cvssData, "baseSeverity");
            var score = cvssData.TryGetProperty("baseScore", out var scoreEl) && scoreEl.ValueKind == JsonValueKind.Number
            ? scoreEl.GetDouble()
            : (double?)null;

            return (string.IsNullOrWhiteSpace(severity) ? "Unknown" : severity, score);
        }

        return ("Unknown", null);
    }

    private static string GetCwe(JsonElement cve)
    {
        if (!cve.TryGetProperty("weaknesses", out var weaknesses) || weaknesses.ValueKind != JsonValueKind.Array)
        {
            return "Unknown";
        }

        foreach (var weakness in weaknesses.EnumerateArray())
        {
            if (!weakness.TryGetProperty("description", out var descs) || descs.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var desc in descs.EnumerateArray())
            {
                var value = GetString(desc, "value");
                if (!string.IsNullOrWhiteSpace(value))
                {
                    return value;
                }
            }
        }

        return "Unknown";
    }

    private static string ResolveCacheDirectory()
    {
        var baseDir = new DirectoryInfo(AppContext.BaseDirectory);
        var current = baseDir;

        // Walk upward to find the repo root where API_Tester.slnx exists.
        for (var i = 0; i < 12 && current is not null; i++)
        {
            var solutionPath = Path.Combine(current.FullName, "API_Tester.slnx");
            if (File.Exists(solutionPath))
            {
                var repoCache = Path.Combine(current.FullName, "cache");
                Directory.CreateDirectory(repoCache);
                return repoCache;
            }

            current = current.Parent;
        }

        // Fallback for packaged/runtime environments where repo path is unavailable.
        var appCache = Path.Combine(AppDataDirectoryProvider(), "cache");
        Directory.CreateDirectory(appCache);
        return appCache;
    }
}

