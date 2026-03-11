using System.Text.Json;

namespace ApiTester.Core;

public sealed record BaselineArtifactItem(string Label, string Path);

public static class AuditArtifactStorage
{
    public static string GetAuditArtifactRoot(string appDataDirectory) =>
        Path.Combine(appDataDirectory, "audit-runs");

    public static List<BaselineArtifactItem> EnumerateBaselineArtifacts(string root)
    {
        var items = new List<BaselineArtifactItem>();
        if (!Directory.Exists(root))
        {
            return items;
        }

        foreach (var path in Directory.EnumerateFiles(root, "*.audit.json", SearchOption.AllDirectories))
        {
            var fileName = Path.GetFileName(path);
            var ts = File.GetLastWriteTimeUtc(path).ToString("yyyy-MM-dd HH:mm:ss");
            items.Add(new BaselineArtifactItem($"{ts} UTC | {fileName}", path));
        }

        return items
            .OrderByDescending(i => i.Label, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public static async Task<string> BuildDeltaSummaryAsync(
        IReadOnlyList<TestEvidenceRecord> current,
        string root,
        string? baselinePath = null)
    {
        try
        {
            var baseline = baselinePath;
            if (string.IsNullOrWhiteSpace(baseline))
            {
                if (!Directory.Exists(root))
                {
                    return "No previous baseline found.";
                }

                baseline = Directory
                    .EnumerateFiles(root, "*.audit.json", SearchOption.AllDirectories)
                    .OrderByDescending(File.GetLastWriteTimeUtc)
                    .FirstOrDefault();
            }

            if (string.IsNullOrWhiteSpace(baseline) || !File.Exists(baseline))
            {
                return "No previous baseline found.";
            }

            var json = await File.ReadAllTextAsync(baseline);
            var prior = JsonSerializer.Deserialize<AuditRunArtifact>(json);
            if (prior is null || prior.Records.Count == 0)
            {
                return "Previous baseline unreadable or empty.";
            }

            var priorMap = prior.Records
                .GroupBy(r => $"{r.FrameworkName}|{r.ControlId}|{r.TargetUri}")
                .ToDictionary(g => g.Key, g => g.Last().Verdict, StringComparer.OrdinalIgnoreCase);
            var currentMap = current
                .GroupBy(r => $"{r.FrameworkName}|{r.ControlId}|{r.TargetUri}")
                .ToDictionary(g => g.Key, g => g.Last().Verdict, StringComparer.OrdinalIgnoreCase);

            var improved = 0;
            var regressed = 0;
            var unchanged = 0;

            foreach (var (key, verdict) in currentMap)
            {
                if (!priorMap.TryGetValue(key, out var previousVerdict))
                {
                    continue;
                }

                if (previousVerdict == verdict)
                {
                    unchanged++;
                }
                else if (previousVerdict == "fail" && verdict == "pass")
                {
                    improved++;
                }
                else if (previousVerdict == "pass" && verdict == "fail")
                {
                    regressed++;
                }
            }

            return $"Compared with baseline ({Path.GetFileName(baseline)}): improved={improved}, regressed={regressed}, unchanged={unchanged}.";
        }
        catch
        {
            return "Delta comparison unavailable.";
        }
    }

    public static async Task<string> SaveAuditArtifactAsync(
        AuditRunArtifact artifact,
        string root,
        Func<AuditRunArtifact, string> buildPciReport,
        Func<AuditRunArtifact, string> buildTraceabilityCsv)
    {
        Directory.CreateDirectory(root);

        var folder = Path.Combine(root, $"{artifact.Metadata.StartedUtc[..19].Replace(':', '-')}_{AuditResultUtilities.SanitizeFileComponent(artifact.Metadata.CategoryName)}_{artifact.Metadata.RunId}");
        Directory.CreateDirectory(folder);

        var jsonPath = Path.Combine(folder, $"{artifact.Metadata.RunId}.audit.json");
        var ndjsonPath = Path.Combine(folder, $"{artifact.Metadata.RunId}.records.ndjson");
        var reportPath = Path.Combine(folder, $"{artifact.Metadata.RunId}.pci-report.md");
        var traceabilityPath = Path.Combine(folder, $"{artifact.Metadata.RunId}.traceability.csv");
        var manifestPath = Path.Combine(folder, $"{artifact.Metadata.RunId}.manifest.json");

        var options = new JsonSerializerOptions { WriteIndented = true };
        var artifactJson = JsonSerializer.Serialize(artifact, options);
        await File.WriteAllTextAsync(jsonPath, artifactJson);

        var ndjsonLines = artifact.Records.Select(r => JsonSerializer.Serialize(r));
        await File.WriteAllLinesAsync(ndjsonPath, ndjsonLines);
        await File.WriteAllTextAsync(reportPath, buildPciReport(artifact));
        await File.WriteAllTextAsync(traceabilityPath, buildTraceabilityCsv(artifact));

        var manifest = new
        {
            runId = artifact.Metadata.RunId,
            generatedUtc = DateTime.UtcNow.ToString("O"),
            files = new[]
            {
                new { path = jsonPath, sha256 = AuditResultUtilities.ComputeSha256Hex(await File.ReadAllTextAsync(jsonPath)) },
                new { path = ndjsonPath, sha256 = AuditResultUtilities.ComputeSha256Hex(await File.ReadAllTextAsync(ndjsonPath)) },
                new { path = reportPath, sha256 = AuditResultUtilities.ComputeSha256Hex(await File.ReadAllTextAsync(reportPath)) },
                new { path = traceabilityPath, sha256 = AuditResultUtilities.ComputeSha256Hex(await File.ReadAllTextAsync(traceabilityPath)) }
            }
        };
        await File.WriteAllTextAsync(manifestPath, JsonSerializer.Serialize(manifest, options));
        return jsonPath;
    }
}
