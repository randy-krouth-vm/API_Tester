using System.Text;

namespace ApiTester.Core;

public static class AuditArtifactPresentation
{
    public static string BuildPciReportMarkdown(AuditRunArtifact artifact)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# PCI DSS API Security Assessment Report");
        sb.AppendLine();
        sb.AppendLine("## Executive Summary");
        sb.AppendLine($"- Run ID: `{artifact.Metadata.RunId}`");
        sb.AppendLine($"- Category: {artifact.Metadata.CategoryName}");
        sb.AppendLine($"- Base Target: {artifact.Metadata.BaseTarget}");
        sb.AppendLine($"- Scope Mode: {artifact.Metadata.ScopeMode}");
        sb.AppendLine($"- Targets Tested: {artifact.Metadata.ScopeTargetCount}");
        sb.AppendLine($"- Start (UTC): {artifact.Metadata.StartedUtc}");
        sb.AppendLine($"- End (UTC): {artifact.Metadata.FinishedUtc}");
        sb.AppendLine();

        sb.AppendLine("## Scope and Authorization");
        sb.AppendLine($"- Authorization Confirmed: {artifact.Metadata.ScopeAuthorizationConfirmed}");
        sb.AppendLine($"- Authorization Source: {artifact.Metadata.ScopeAuthorizationSource}");
        sb.AppendLine($"- Frameworks: {string.Join(", ", artifact.Metadata.Frameworks)}");
        sb.AppendLine($"- Business Logic Scenario Source: {artifact.Metadata.BusinessLogicScenarioSource}");
        sb.AppendLine();

        sb.AppendLine("## Methodology");
        sb.AppendLine($"- {artifact.Metadata.Methodology}");
        sb.AppendLine("- Testing includes unauthenticated and authenticated profile execution when configured.");
        sb.AppendLine("- Output includes control mapping, evidence exchanges, CVSS score, severity, remediation guidance, and retest delta.");
        sb.AppendLine("- See companion traceability CSV for control-to-specification mapping.");
        sb.AppendLine();

        sb.AppendLine("## Findings");
        sb.AppendLine("| Control | Framework | Profile | Verdict | CVSS | Severity | Summary |");
        sb.AppendLine("|---|---|---|---|---:|---|---|");
        foreach (var finding in artifact.Records
                     .OrderByDescending(r => r.CvssScore)
                     .ThenBy(r => r.FrameworkName, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(r => r.ControlId, StringComparer.OrdinalIgnoreCase)
                     .Take(300))
        {
            var summary = finding.ResultSummary.Replace("|", "/");
            sb.AppendLine($"| `{finding.ControlId}` | {finding.FrameworkName} | {finding.AuthProfileName} | {finding.Verdict} | {finding.CvssScore:F1} | {finding.CvssSeverity} | {summary} |");
        }

        sb.AppendLine();
        sb.AppendLine("## Remediation Recommendations");
        foreach (var item in artifact.Records
                     .Where(r => r.Verdict == "fail")
                     .Select(r => $"{r.ControlId}: {r.RemediationGuidance}")
                     .Distinct(StringComparer.OrdinalIgnoreCase)
                     .Take(80))
        {
            sb.AppendLine($"- {item}");
        }

        if (!artifact.Records.Any(r => r.Verdict == "fail"))
        {
            sb.AppendLine("- No failing findings in this run.");
        }

        sb.AppendLine();
        sb.AppendLine("## Retest / Delta");
        sb.AppendLine($"- {artifact.Metadata.DeltaSummary}");
        sb.AppendLine();

        sb.AppendLine("## Tester Attestation");
        sb.AppendLine($"- Tester: {artifact.Metadata.TesterName}");
        sb.AppendLine($"- Role: {artifact.Metadata.TesterRole}");
        sb.AppendLine($"- Qualification: {artifact.Metadata.TesterQualification}");
        sb.AppendLine($"- Attested UTC: {artifact.Metadata.AttestedUtc}");
        sb.AppendLine();

        sb.AppendLine("## Limitations");
        sb.AppendLine($"- {artifact.Metadata.LimitationsNote}");
        sb.AppendLine("- PCI DSS controls requiring policy/process/physical/network reviews remain out of scope for API probing evidence alone.");
        return sb.ToString().TrimEnd();
    }

    public static string BuildTraceabilityCsv(AuditRunArtifact artifact)
    {
        static string Esc(string value)
        {
            var v = value ?? string.Empty;
            if (v.Contains('"'))
            {
                v = v.Replace("\"", "\"\"");
            }

            if (v.Contains(',') || v.Contains('"') || v.Contains('\n') || v.Contains('\r'))
            {
                return $"\"{v}\"";
            }

            return v;
        }

        var sb = new StringBuilder();
        sb.AppendLine("traceability_id,framework,control_id,test_name,method_name,specification,compliance_mapping,profiles_seen,pass_count,fail_count,inconclusive_count");

        var groups = artifact.Records
            .GroupBy(r => r.TraceabilityId, StringComparer.OrdinalIgnoreCase)
            .OrderBy(g => g.First().FrameworkName, StringComparer.OrdinalIgnoreCase)
            .ThenBy(g => g.First().ControlId, StringComparer.OrdinalIgnoreCase);

        foreach (var g in groups)
        {
            var first = g.First();
            var framework = first.FrameworkName;
            var control = first.ControlId;
            var compliance = Mappings.GetComplianceMappings(framework, control);
            var spec = control.StartsWith("BUSLOGIC:", StringComparison.OrdinalIgnoreCase)
                ? "Business logic scenario (human-authored workflow test case)"
                : Mappings.GetSpecificationForTestKey(control);
            var complianceJoined = compliance.Count == 0 ? string.Empty : string.Join(" | ", compliance);
            var profiles = string.Join(";", g.Select(x => x.AuthProfileName).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x, StringComparer.OrdinalIgnoreCase));
            var pass = g.Count(x => x.Verdict.Equals("pass", StringComparison.OrdinalIgnoreCase));
            var fail = g.Count(x => x.Verdict.Equals("fail", StringComparison.OrdinalIgnoreCase));
            var inconclusive = g.Count(x => x.Verdict.Equals("inconclusive", StringComparison.OrdinalIgnoreCase));

            sb.AppendLine(string.Join(",",
                Esc(first.TraceabilityId),
                Esc(framework),
                Esc(control),
                Esc(first.TestName),
                Esc(first.MethodName),
                Esc(spec),
                Esc(complianceJoined),
                Esc(profiles),
                pass.ToString(),
                fail.ToString(),
                inconclusive.ToString()));
        }

        return sb.ToString().TrimEnd();
    }
}
