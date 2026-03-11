using System.Text.Json;

namespace ApiTester.Core;

public static class FrameworkPackExecutionWorkflowUtilities
{
    public static async Task<string> BuildControlDrivenFrameworkPackReportAsync(
        string categoryName,
        IReadOnlyList<string> frameworkList,
        Uri uri,
        IReadOnlyList<Func<Uri, Task<string>>> fallbackTests,
        Func<Uri, Task<IReadOnlyList<Uri>>> resolveScopeTargetsAsync,
        Func<string, IReadOnlyList<string>, IReadOnlyList<Func<Uri, Task<string>>>, List<FrameworkTestDescriptor>> buildFrameworkTestDescriptors,
        Func<List<AuthProfile>> getExecutionAuthProfiles,
        Func<string?, string> getAuthProfileDisplayName,
        Action<bool, string?> setBusy,
        Action<AuditCaptureContext?> setAuditCaptureContext,
        Action<AuthProfile?> setActiveAuthProfile,
        Func<Uri, IReadOnlyList<AuthProfile>, string, List<string>, List<TestEvidenceRecord>, string, Task<(string Source, string PreviousHash)>> executeBusinessLogicScenariosAsync,
        Func<string?> getSelectedBaselinePath,
        Func<string, IReadOnlyList<TestEvidenceRecord>, string?, Task<string>> buildDeltaSummaryAsync,
        Func<IReadOnlyList<TestEvidenceRecord>, string> buildRoleDifferentialSummary,
        Func<string> getSelectedScopeLabel,
        Func<AuditRunArtifact, Task<string>> saveAuditArtifactAsync)
    {
        var targets = await resolveScopeTargetsAsync(uri);
        var descriptors = buildFrameworkTestDescriptors(categoryName, frameworkList, fallbackTests);
        var startedUtc = DateTime.UtcNow;
        var runId = $"{startedUtc:yyyyMMddTHHmmssZ}_{Guid.NewGuid():N}";
        var sections = new List<string>();
        var records = new List<TestEvidenceRecord>();
        var previousHash = string.Empty;

        var runProfiles = getExecutionAuthProfiles();
        var totalExecutions = Math.Max(1, targets.Count * descriptors.Count * runProfiles.Count);
        var executionIndex = 0;
        foreach (var target in targets)
        {
            foreach (var descriptor in descriptors)
            {
                foreach (var profile in runProfiles)
                {
                    executionIndex++;
                    var progressPrefix =
                        $"[Execution] Test {executionIndex}/{totalExecutions} | Framework={descriptor.FrameworkName} | Key={descriptor.TestKey} | Profile={getAuthProfileDisplayName(profile.Name)} | Target={target}";
                    setBusy(true, $"{categoryName}: Test {executionIndex}/{totalExecutions} ({descriptor.TestName} | {profile.Name})");
                    var capture = new AuditCaptureContext(new List<HttpExchangeEvidence>());
                    setAuditCaptureContext(capture);
                    setActiveAuthProfile(profile);
                    var testTimestamp = DateTime.UtcNow;
                    var hadException = false;
                    string output;
                    try
                    {
                        output = await descriptor.Execute(target);
                        sections.Add($"{progressPrefix}{Environment.NewLine}{output}");
                    }
                    catch (Exception ex)
                    {
                        hadException = true;
                        output = $"[{descriptor.TestName}] (profile: {getAuthProfileDisplayName(profile.Name)}){Environment.NewLine}Target: {target}{Environment.NewLine}- Execution error: {ex.Message}";
                        sections.Add($"{progressPrefix}{Environment.NewLine}{output}");
                    }
                    finally
                    {
                        setAuditCaptureContext(null);
                        setActiveAuthProfile(null);
                    }

                    var signalOnly = AuditResultUtilities.IsSignalOnlyKey(descriptor.TestKey);
                    var verdict = AuditResultUtilities.DetermineVerdict(descriptor.TestKey, output, hadException);
                    var cvss = AuditResultUtilities.GetCvssForResult(descriptor.TestKey, verdict);
                    var summary = AuditResultUtilities.BuildResultSummary(output);
                    var remediation = AuditResultUtilities.GetRemediationGuidance(descriptor.TestKey);
                    var methodName = descriptor.Execute.Method.Name;
                    var payload = new
                    {
                        descriptor.FrameworkName,
                        descriptor.TestKey,
                        descriptor.TestName,
                        MethodName = methodName,
                        AuthProfileName = profile.Name,
                        TargetUri = target.ToString(),
                        TimestampUtc = testTimestamp.ToString("O"),
                        Verdict = verdict,
                        CvssScore = cvss.Score,
                        CvssSeverity = cvss.Severity,
                        CvssVector = cvss.Vector,
                        Summary = summary,
                        Remediation = remediation,
                        SignalOnly = signalOnly,
                        Exchanges = capture.Exchanges
                    };
                    var payloadJson = JsonSerializer.Serialize(payload);
                    var recordHash = AuditResultUtilities.ComputeSha256Hex($"{previousHash}|{payloadJson}");

                    records.Add(new TestEvidenceRecord(
                        categoryName,
                        descriptor.FrameworkName,
                        descriptor.TestKey,
                        $"{descriptor.FrameworkName}|{descriptor.TestKey}",
                        descriptor.TestName,
                        methodName,
                        profile.Name,
                        target.ToString(),
                        testTimestamp.ToString("O"),
                        verdict,
                        cvss.Score,
                        cvss.Severity,
                        cvss.Vector,
                        summary,
                        remediation,
                        signalOnly,
                        capture.Exchanges,
                        previousHash,
                        recordHash));
                    previousHash = recordHash;
                }
            }
        }

        var businessScenarioResult = await executeBusinessLogicScenariosAsync(
            uri,
            runProfiles,
            categoryName,
            sections,
            records,
            previousHash);
        var businessScenarioSource = businessScenarioResult.Source;
        previousHash = businessScenarioResult.PreviousHash;

        var finishedUtc = DateTime.UtcNow;
        var (scopeAuthConfirmed, scopeAuthSource) = AuditResultUtilities.GetScopeAuthorizationState();
        var selectedBaseline = getSelectedBaselinePath();
        var deltaSummary = await buildDeltaSummaryAsync(categoryName, records, selectedBaseline);
        var roleDiff = buildRoleDifferentialSummary(records);
        var scopeLabel = getSelectedScopeLabel();
        var metadata = new AuditRunMetadata(
            runId,
            categoryName,
            frameworkList.ToList(),
            uri.ToString(),
            scopeLabel,
            targets.Count,
            scopeAuthConfirmed,
            scopeAuthSource,
            AuditResultUtilities.GetAuditMethodology(),
            AuditResultUtilities.GetTesterMetadata("API_TESTER_TESTER_NAME", "Unspecified Tester"),
            AuditResultUtilities.GetTesterMetadata("API_TESTER_TESTER_ROLE", "Security Engineer"),
            AuditResultUtilities.GetTesterMetadata("API_TESTER_TESTER_QUALIFICATION", "Not Declared"),
            AuditResultUtilities.GetTesterMetadata("API_TESTER_TESTER_ATTESTED_UTC", string.Empty),
            businessScenarioSource,
            startedUtc.ToString("O"),
            finishedUtc.ToString("O"),
            "1.0",
            AuditResultUtilities.GetAuditLimitationsNote(),
            $"{deltaSummary} {roleDiff}");
        var artifact = new AuditRunArtifact(metadata, records);
        var artifactPath = await saveAuditArtifactAsync(artifact);

        return RunReportUtilities.BuildFrameworkPackReport(
            categoryName,
            frameworkList,
            uri,
            scopeLabel,
            targets.Count,
            sections,
            records,
            artifactPath);
    }
}
