using System.Text;

namespace ApiTester.Core;

public static class RunReportUtilities
{
    public static bool IsTruthyEnvironment(string variableName)
    {
        var raw = Environment.GetEnvironmentVariable(variableName);
        return string.Equals(raw, "1", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(raw, "true", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(raw, "yes", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsCiExtrasEnabled() => IsTruthyEnvironment("API_TESTER_CI_EXTRAS");

    public static bool IsUnauthProfileName(string? value)
    {
        return value is not null &&
               (value.Equals("unauth", StringComparison.OrdinalIgnoreCase) ||
                value.Equals("unauthenticated", StringComparison.OrdinalIgnoreCase) ||
                value.Equals("no authentication", StringComparison.OrdinalIgnoreCase));
    }

    public static string GetAuthProfileDisplayName(string? value) =>
        IsUnauthProfileName(value) ? "No Authentication" : "Authenticated";

    public static string TryGetRoutePathKey(string endpoint)
    {
        return Uri.TryCreate(endpoint, UriKind.Absolute, out var uri) && uri is not null
            ? TryGetRoutePathKey(uri)
            : string.Empty;
    }

    public static string TryGetRoutePathKey(Uri uri)
    {
        if (uri is null)
        {
            return string.Empty;
        }

        var path = uri.AbsolutePath.Trim();
        if (string.IsNullOrWhiteSpace(path))
        {
            return "/";
        }

        return path.TrimEnd('/').ToLowerInvariant();
    }

    public static string BuildRouteDiscoverySummary(SpiderResult crawl)
    {
        var uniquePaths = crawl.DiscoveredEndpoints
            .Select(TryGetRoutePathKey)
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Count();

        var sb = new StringBuilder();
        sb.AppendLine("[Route Discovery Summary]");
        sb.AppendLine($"CI extras enabled: {IsCiExtrasEnabled()}");
        sb.AppendLine($"Visited pages: {crawl.Visited.Count}");
        sb.AppendLine($"Discovered endpoints: {crawl.DiscoveredEndpoints.Count}");
        sb.AppendLine($"Unique route paths: {uniquePaths}");
        sb.AppendLine($"Failures: {crawl.Failures.Count}");
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

    public static string BuildRoleDifferentialSummary(IReadOnlyList<TestEvidenceRecord> records)
    {
        var interesting = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "API1", "API3", "API5", "BOLA", "PRIVESC", "N53AC3", "N53AC6", "ASVSV4", "CMMCAC", "N171AC", "SOC2CC6"
        };

        var findings = new List<string>();
        var groups = records
            .Where(r => interesting.Contains(r.ControlId))
            .GroupBy(r => $"{r.FrameworkName}|{r.ControlId}|{r.TargetUri}", StringComparer.OrdinalIgnoreCase);

        foreach (var group in groups)
        {
            var unauthPass = group.Any(r => IsUnauthProfileName(r.AuthProfileName) && r.Verdict == "pass");
            var userPass = group.Any(r => string.Equals(r.AuthProfileName, "user", StringComparison.OrdinalIgnoreCase) && r.Verdict == "pass");
            var adminPass = group.Any(r => string.Equals(r.AuthProfileName, "admin", StringComparison.OrdinalIgnoreCase) && r.Verdict == "pass");

            if (unauthPass && (userPass || adminPass))
            {
                findings.Add($"{group.Key}: unauthenticated profile matched authenticated access results.");
            }
            else if (userPass && adminPass)
            {
                findings.Add($"{group.Key}: user and admin profiles produced equivalent privileged-access outcomes.");
            }
        }

        return findings.Count == 0
            ? "Role differential: no suspicious cross-role parity detected."
            : $"Role differential: {findings.Count} suspicious parity case(s) detected. {string.Join(" | ", findings.Take(4))}";
    }

    public static string BuildFrameworkPackReport(
        string categoryName,
        IReadOnlyList<string> frameworks,
        Uri uri,
        string scopeLabel,
        int targetCount,
        IReadOnlyList<string> sections,
        IReadOnlyList<TestEvidenceRecord> records,
        string artifactPath)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"=== {categoryName} ===");
        sb.AppendLine(scopeLabel == "Single Target" ? $"Target: {uri}" : $"Base target: {uri}");
        if (scopeLabel != "Single Target")
        {
            sb.AppendLine($"Scope: {scopeLabel} ({targetCount} target(s))");
        }

        sb.AppendLine("Frameworks:");
        foreach (var framework in frameworks)
        {
            sb.AppendLine($"- {framework}");
        }

        var profileNames = records.Select(r => r.AuthProfileName).Where(n => !string.IsNullOrWhiteSpace(n)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        profileNames = profileNames
            .Select(GetAuthProfileDisplayName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (profileNames.Count > 0)
        {
            sb.AppendLine("Auth profiles:");
            foreach (var profile in profileNames)
            {
                sb.AppendLine($"- {profile}");
            }
        }

        var passCount = records.Count(r => r.Verdict == "pass");
        var failCount = records.Count(r => r.Verdict == "fail");
        var inconclusiveCount = records.Count(r => r.Verdict == "inconclusive");
        var avgCvss = records.Where(r => r.Verdict == "fail").Select(r => r.CvssScore).DefaultIfEmpty(0).Average();
        sb.AppendLine();
        sb.AppendLine("[Audit Summary]");
        sb.AppendLine($"- Evidence records: {records.Count}");
        sb.AppendLine($"- Pass: {passCount}");
        sb.AppendLine($"- Fail: {failCount}");
        sb.AppendLine($"- Inconclusive: {inconclusiveCount}");
        sb.AppendLine($"- Avg CVSS (failures): {avgCvss:F1}");
        sb.AppendLine($"- Artifact: {artifactPath}");
        sb.AppendLine("- Artifact integrity: SHA-256 manifest generated");
        sb.AppendLine($"- {BuildRoleDifferentialSummary(records)}");

        if (failCount > 0)
        {
            sb.AppendLine("- Remediation guidance:");
            foreach (var item in records
                .Where(r => r.Verdict == "fail")
                .Select(r => $"{r.ControlId}: {r.RemediationGuidance}")
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(12))
            {
                sb.AppendLine($"  - {item}");
            }
        }

        sb.AppendLine();
        sb.Append(string.Join($"{Environment.NewLine}{Environment.NewLine}", sections));
        return sb.ToString().TrimEnd();
    }
}
