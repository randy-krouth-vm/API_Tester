using API_Tester.SecurityCatalog;
using System.Text;
using System.Text.RegularExpressions;

namespace ApiTester.Core;

public static class ResultPresentation
{
    public static string BuildFunctionMapReport(
        CveFunctionMapPageResult? page,
        string selectedPriority,
        IReadOnlyList<CveFunctionMapPageRow> filteredRows)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== CVE Function Map Paged View ===");
        if (page is not null)
        {
            sb.AppendLine($"Page: {page.Page} of {page.TotalPages} | Page size: {page.PageSize} | Total mapped CVEs: {page.TotalRows}");
        }

        sb.AppendLine($"Priority filter: {selectedPriority}");
        var firstRow = filteredRows.Count == 0 ? 0 : filteredRows[0].RowNumber;
        var lastRow = filteredRows.Count == 0 ? 0 : filteredRows[^1].RowNumber;
        sb.AppendLine($"Showing rows {firstRow} to {lastRow}");
        sb.AppendLine();

        foreach (var row in filteredRows)
        {
            sb.AppendLine($"- [{row.RowNumber}] {row.CveId} | {row.Confidence} ({row.ConfidenceScore}) | EstimatedDefaultCoverage={row.RealWorldCoverageScore}/100");
            sb.AppendLine(FormatIndentedFunctions(row.FunctionsPreview));
            sb.AppendLine();
        }

        if (filteredRows.Count == 0)
        {
            sb.AppendLine("- No rows match this page/filter.");
        }

        return sb.ToString().TrimEnd();
    }

    public static string FormatIndentedFunctions(string functionsPreview)
    {
        var sb = new StringBuilder();
        sb.AppendLine("    Functions:");

        if (string.IsNullOrWhiteSpace(functionsPreview))
        {
            sb.Append("      - None");
            return sb.ToString();
        }

        var items = functionsPreview
            .Split(", ", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

        if (items.Length == 0)
        {
            sb.Append("      - None");
            return sb.ToString();
        }

        foreach (var item in items)
        {
            sb.AppendLine($"      - {item}");
        }

        return sb.ToString().TrimEnd();
    }

    public static string FormatSection(string sectionName, Uri uri, IEnumerable<string> findings)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"[{sectionName}]");
        sb.AppendLine($"Target: {uri}");
        foreach (var item in findings)
        {
            sb.AppendLine($"- {item}");
        }

        return sb.ToString().TrimEnd();
    }

    public static string FormatSharedCoreSection(string sectionName, Uri baseUri, Finding? finding)
    {
        if (finding is null)
        {
            return FormatSection(sectionName, baseUri, ["No finding returned from shared core engine."]);
        }

        return FormatSection(sectionName, baseUri, [$"Verdict: {finding.Verdict}", finding.Summary]);
    }

    public static string BuildCveTestReference()
    {
        var fileStatus = CveCorpusService.BuildLocalFileStatus();
        var lines = new[]
        {
            "Reference note: full CVE coverage is loaded from your local corpus and function-map files.",
            $"Today (local): {DateTime.Now:yyyy-MM-dd HH:mm:ss zzz}",
            $"Today (UTC): {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}Z",
            "",
            "Local file status:",
            fileStatus,
            "",
            "Built-in function coverage examples (CVE list):",
            "",
            "RunMITREATTampCKFrameworkSsrfTestsAsync / RunAdvancedSsrfEncodingTestsAsync / RunCloudMetadataImdsV2TestsAsync",
            "- CVE-2019-5418 (Rails file disclosure/SSRF-style path abuse)",
            "- CVE-2021-41773 (Apache path traversal + SSRF pivot context)",
            "",
            "RunSqlInjectionTestsAsync",
            "- CVE-2023-34362 (MOVEit SQL injection chain)",
            "",
            "RunXxeProbeTestsAsync / RunXmlEntityExpansionTestsAsync",
            "- CVE-2021-3918 (XXE in XML parsing flows)",
            "",
            "RunJwtNoneAlgorithmTestsAsync / RunJwtRsHsConfusionTestsAsync / RunJwtKidHeaderInjectionTestsAsync / RunJwksEndpointPoisoningTestsAsync",
            "- CVE-2015-9235 (JWT alg confusion class)",
            "- CVE-2018-0114 (JWT validation weakness class)",
            "",
            "RunOAuthRedirectUriValidationTestsAsync / RunOidcDiscoveryHijackingTestsAsync",
            "- CVE-2020-26870 (OAuth redirect validation weakness class)",
            "",
            "RunRequestSmugglingSignalTestsAsync / RunHttpClTeDesyncTestsAsync / RunHttpTeClDesyncTestsAsync / RunDualContentLengthTestsAsync",
            "- CVE-2023-25690 (request smuggling class)",
            "",
            "RunLogPoisoningTestsAsync / RunCrlfInjectionTestsAsync",
            "- CVE-2021-22096 (log injection class)",
            "",
            "RunGraphQlIntrospectionTestsAsync / RunGraphQlDepthBombTestsAsync / RunGraphQlComplexityTestsAsync",
            "- CVE-2022-37734 (GraphQL complexity abuse class)",
            "",
            "RunWebSocketAuthTestsAsync / RunWebSocketMessageInjectionTestsAsync / RunWebSocketFragmentationTestsAsync",
            "- CVE-2023-43622 (websocket auth/message handling class)",
            "",
            "RunGrpcReflectionTestsAsync / RunGrpcMetadataAbuseTestsAsync / RunGrpcProtobufFuzzingTestsAsync",
            "- CVE-2023-32731 (gRPC/protobuf parser handling class)",
            "",
            "RunNumericalOverflowUnderflowTestsAsync / RunCouponCreditExhaustionTestsAsync / RunDoubleSpendToctouTestsAsync",
            "- CVE-2020-28458 (business logic and transaction validation class)",
            "",
            "RunCertificateTrustChainTestsAsync / RunTlsPostureTestsAsync / RunTransportSecurityTestsAsync",
            "- CVE-2021-3449 (TLS/certificate handling class)",
            "",
            "RunSideChannelTimingTestsAsync",
            "- CVE-2021-27290 (timing side-channel class)",
            "",
            "RunFileUploadValidationTestsAsync",
            "- CVE-2021-22205 (unsafe file upload processing class)",
            "",
            "RunDockerContainerExposureTestsAsync",
            "- CVE-2019-13139 (Docker API exposure/auth bypass class)",
            "",
            "Headless commands:",
            "- PowerShell: $env:API_TESTER_HEADLESS='true'; $env:API_TESTER_TARGET_URL='https://api.example.com'; $env:API_TESTER_RUN_SCOPE='openapi'; $env:API_TESTER_TYPE_HANDLING='automatic'; $env:API_TESTER_OPENAPI_INPUT='https://api.example.com/openapi.json'; $env:API_TESTER_HEADLESS_REQUEST_DELAY_MS='250'; dotnet run --project API_Tester.csproj",
            "- Optional action: API_TESTER_HEADLESS_ACTION=run-everything|run-all|max-coverage|spider|validation",
            "- Scope values: single | spider | openapi",
            "- Type handling values: automatic | manual",
            "- Optional default delay (all modes): API_TESTER_REQUEST_DELAY_MS=250"
        };

        return string.Join(Environment.NewLine, lines);
    }

    public static string ExtractEmbeddedPageLabel(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return string.Empty;
        }

        var match = Regex.Match(text, @"Page:\s*(\d+)\s*(?:of|/)\s*(\d+)", RegexOptions.IgnoreCase);
        return match.Success ? $"Page {match.Groups[1].Value} of {match.Groups[2].Value}" : string.Empty;
    }

    public static string FilterResultText(string input, string? filterMode)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        var mode = (filterMode ?? string.Empty).Trim();
        if (mode.Contains("All", StringComparison.OrdinalIgnoreCase))
        {
            return input;
        }

        var blocks = Regex.Split(input, @"(?:\r?\n){2,}")
            .Where(block => !string.IsNullOrWhiteSpace(block))
            .ToList();

        if (blocks.Count == 0)
        {
            return input;
        }

        static bool IsFailedBlock(string block) =>
            block.Contains("Potential risk:", StringComparison.OrdinalIgnoreCase) ||
            block.Contains("verdict: fail", StringComparison.OrdinalIgnoreCase) ||
            block.Contains("| fail |", StringComparison.OrdinalIgnoreCase) ||
            block.Contains("- Fail:", StringComparison.OrdinalIgnoreCase) ||
            block.Contains("failures):", StringComparison.OrdinalIgnoreCase);

        static bool IsPassedBlock(string block) =>
            block.Contains("verdict: pass", StringComparison.OrdinalIgnoreCase) ||
            block.Contains("| pass |", StringComparison.OrdinalIgnoreCase) ||
            block.Contains("- Pass:", StringComparison.OrdinalIgnoreCase) ||
            block.Contains("No ", StringComparison.OrdinalIgnoreCase);

        List<string> filtered;
        if (mode.Contains("Failed", StringComparison.OrdinalIgnoreCase))
        {
            filtered = blocks.Where(IsFailedBlock).ToList();
        }
        else if (mode.Contains("Passed", StringComparison.OrdinalIgnoreCase))
        {
            filtered = blocks.Where(block => !IsFailedBlock(block) && IsPassedBlock(block)).ToList();
        }
        else
        {
            filtered = blocks;
        }

        return filtered.Count == 0 ? input : string.Join(Environment.NewLine + Environment.NewLine, filtered);
    }

    public static string NormalizeResultFormatting(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        var lines = input.Replace("\r\n", "\n").Split('\n');
        var sb = new StringBuilder(input.Length + 128);
        var previousNonEmpty = string.Empty;

        foreach (var rawLine in lines)
        {
            var line = rawLine.TrimEnd();
            if (line.Length == 0)
            {
                sb.AppendLine();
                continue;
            }

            var trimmed = line.TrimStart();
            var isSectionHeader =
                trimmed.StartsWith("===", StringComparison.Ordinal) ||
                (trimmed.StartsWith("[", StringComparison.Ordinal) &&
                 trimmed.EndsWith("]", StringComparison.Ordinal));
            if (isSectionHeader && !string.IsNullOrWhiteSpace(previousNonEmpty))
            {
                sb.AppendLine();
            }

            if (trimmed.StartsWith("-", StringComparison.Ordinal) || trimmed.StartsWith("\u2022", StringComparison.Ordinal))
            {
                sb.AppendLine("  " + trimmed);
            }
            else
            {
                sb.AppendLine(trimmed);
            }

            if (isSectionHeader)
            {
                sb.AppendLine();
            }
            previousNonEmpty = trimmed;
        }

        return sb.ToString().TrimEnd();
    }

    public static string BuildReadableResults(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return string.Empty;
        }

        var lines = input.Replace("\r\n", "\n").Split('\n')
            .SkipWhile(string.IsNullOrWhiteSpace)
            .ToArray();
        var nonEmptyLineCount = lines.Count(l => !string.IsNullOrWhiteSpace(l));
        var sectionCount = lines.Count(IsVisualSectionHeader);
        var riskCount = lines.Count(l => l.Contains("Potential risk:", StringComparison.OrdinalIgnoreCase));
        var noResponseCount = lines.Count(l => l.Contains("no response", StringComparison.OrdinalIgnoreCase));
        var executionErrorCount = lines.Count(l => l.Contains("Execution error:", StringComparison.OrdinalIgnoreCase));

        var sb = new StringBuilder(input.Length + 512);
        var previousWasHeader = false;
        var previousWasBlank = false;
        if (nonEmptyLineCount >= 24)
        {
            sb.AppendLine("=== Results Overview ===");
            sb.AppendLine($"Sections: {sectionCount} | Potential risks: {riskCount} | No-response signals: {noResponseCount} | Execution errors: {executionErrorCount}");
            sb.AppendLine();
            previousWasBlank = true;
        }

        foreach (var rawLine in lines)
        {
            var line = rawLine.TrimEnd();
            if (string.IsNullOrWhiteSpace(line))
            {
                if (sb.Length > 0 && !previousWasHeader && !previousWasBlank)
                {
                    sb.AppendLine();
                    previousWasBlank = true;
                }

                continue;
            }

            var trimmed = line.TrimStart();
            if (trimmed.StartsWith("[Execution]", StringComparison.Ordinal))
            {
                sb.AppendLine(FormatExecutionLine(trimmed));
                previousWasHeader = false;
                previousWasBlank = false;
                continue;
            }

            if (trimmed.StartsWith("- Artifact:", StringComparison.OrdinalIgnoreCase))
            {
                var baseIndent = new string(' ', line.Length - trimmed.Length);
                var marker = "- Artifact:";
                var value = trimmed.Length > marker.Length ? trimmed[marker.Length..].Trim() : string.Empty;
                sb.AppendLine(baseIndent + marker);
                foreach (var segment in WrapPathLikeText(value, 96))
                {
                    sb.AppendLine($"{baseIndent}  {segment}");
                }

                previousWasHeader = false;
                previousWasBlank = false;
                continue;
            }

            var payloadPrefix = trimmed.StartsWith("- Payload '", StringComparison.Ordinal) ? "- Payload '" :
                trimmed.StartsWith("Payload '", StringComparison.Ordinal) ? "Payload '" : string.Empty;
            if (!string.IsNullOrEmpty(payloadPrefix) && trimmed.Contains(": ", StringComparison.Ordinal))
            {
                var baseIndent = new string(' ', line.Length - trimmed.Length);
                var split = trimmed.Split(": ", 2, StringSplitOptions.None);
                sb.AppendLine(baseIndent + split[0] + ":");
                var parts = split[1].Split(" | ", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                foreach (var part in parts)
                {
                    sb.AppendLine($"{baseIndent}  - {part}");
                }

                previousWasHeader = false;
                previousWasBlank = false;
                continue;
            }

            if (IsVisualSectionHeader(trimmed))
            {
                if (sb.Length > 0 && !previousWasBlank)
                {
                    sb.AppendLine();
                    previousWasBlank = true;
                }

                sb.AppendLine(trimmed);
                sb.AppendLine(new string('-', 64));
                previousWasHeader = true;
                previousWasBlank = false;
                continue;
            }

            sb.AppendLine(line);
            previousWasHeader = false;
            previousWasBlank = false;
        }

        return sb.ToString().TrimEnd();
    }

    public static bool IsVisualSectionHeader(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return false;
        }

        var trimmed = line.Trim();
        return trimmed.StartsWith("===", StringComparison.Ordinal) ||
               (trimmed.StartsWith("[", StringComparison.Ordinal) &&
                trimmed.EndsWith("]", StringComparison.Ordinal));
    }

    public static string FormatExecutionLine(string line)
    {
        var match = Regex.Match(
            line,
            @"^\[Execution\]\s+Test\s+(\d+)/(\d+)\s+\|\s+Framework=(.*?)\s+\|\s+Key=(.*?)\s+\|\s+Profile=(.*?)\s+\|\s+Target=(.*)$",
            RegexOptions.CultureInvariant);

        if (!match.Success)
        {
            return line;
        }

        var index = match.Groups[1].Value;
        var total = match.Groups[2].Value;
        var framework = match.Groups[3].Value.Trim();
        var key = match.Groups[4].Value.Trim();
        var profile = match.Groups[5].Value.Trim();
        var target = match.Groups[6].Value.Trim();
        return $"[Execution {index}/{total}] {framework} | {key} | {profile} | {target}";
    }

    public static IEnumerable<string> WrapPathLikeText(string value, int maxWidth)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            yield break;
        }

        if (value.Length <= maxWidth)
        {
            yield return value;
            yield break;
        }

        var normalized = value.Replace('/', '\\');
        var parts = normalized.Split('\\', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
        {
            yield return value;
            yield break;
        }

        var current = new StringBuilder();
        foreach (var part in parts)
        {
            var candidate = current.Length == 0 ? part : $"{current}\\{part}";
            if (candidate.Length <= maxWidth)
            {
                current.Clear();
                current.Append(candidate);
                continue;
            }

            if (current.Length > 0)
            {
                yield return current.ToString();
            }

            current.Clear();
            current.Append(part);
        }

        if (current.Length > 0)
        {
            yield return current.ToString();
        }
    }
}
