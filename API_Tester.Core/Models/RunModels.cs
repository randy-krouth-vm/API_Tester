namespace ApiTester.Core;

public sealed record SpiderResult(
    HashSet<string> Visited,
    HashSet<string> DiscoveredEndpoints,
    List<string> Failures);

public sealed record TestEvidenceRecord(
    string CategoryName,
    string FrameworkName,
    string ControlId,
    string TraceabilityId,
    string TestName,
    string MethodName,
    string AuthProfileName,
    string TargetUri,
    string TimestampUtc,
    string Verdict,
    double CvssScore,
    string CvssSeverity,
    string CvssVector,
    string ResultSummary,
    string RemediationGuidance,
    bool IsSignalOnly,
    List<HttpExchangeEvidence> Exchanges,
    string PreviousRecordHash,
    string RecordHash);

public sealed record AuditRunMetadata(
    string RunId,
    string CategoryName,
    List<string> Frameworks,
    string BaseTarget,
    string ScopeMode,
    int ScopeTargetCount,
    bool ScopeAuthorizationConfirmed,
    string ScopeAuthorizationSource,
    string Methodology,
    string TesterName,
    string TesterRole,
    string TesterQualification,
    string AttestedUtc,
    string BusinessLogicScenarioSource,
    string StartedUtc,
    string FinishedUtc,
    string ArtifactVersion,
    string LimitationsNote,
    string DeltaSummary);

public sealed record AuditRunArtifact(AuditRunMetadata Metadata, List<TestEvidenceRecord> Records);

public sealed record BusinessLogicScenario(
    string Id,
    string Name,
    string Description,
    string Endpoint,
    string Method,
    string? Body,
    Dictionary<string, string>? Headers,
    string AuthProfile,
    int? ExpectedStatus,
    List<int>? ForbiddenStatuses,
    bool RepeatRequest,
    bool ExpectStableStatus);

public sealed record ValidationScenario(
    string Name,
    string TargetUrl,
    List<string> TestKeys,
    List<string> ExpectedFailKeys,
    List<string> ExpectedPassKeys,
    List<string> ExpectedInconclusiveKeys,
    string? AuthProfile);

public sealed record ValidationScenarioSet(List<ValidationScenario> Scenarios);

public sealed record BusinessScenarioExecutionResult(
    string Output,
    string Verdict,
    DateTime TimestampUtc,
    string TargetUri,
    List<HttpExchangeEvidence> Exchanges,
    bool HadException);
