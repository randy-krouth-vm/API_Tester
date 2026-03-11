namespace API_Tester.SecurityCatalog;

public sealed record CveRecord(
string CveId,
string Published,
string LastModified,
string Source,
string Description,
string Severity,
double? Score,
string Cwe);

public sealed record CveCorpusMetadata(
string Source,
string SyncedAtUtc,
int Count,
int TotalResults,
string Notes);

public sealed record CveFunctionMapRecord(
string CveId,
string Cwe,
string Severity,
string[] Functions,
string Confidence,
double ConfidenceScore,
double DefaultSettingsPreventionScore,
double RealWorldCoverageScore,
string DefaultSettings,
string[] Signals);

public sealed record CveFunctionMapMetadata(
string Source,
string GeneratedAtUtc,
int Count,
int HighConfidence,
int MediumConfidence,
int LowConfidence,
int UniqueFunctionsCovered,
string Notes);

public sealed record CveCorpusPageRow(
int RowNumber,
string CveId,
string Severity,
string Score,
string Cwe);

public sealed record CveFunctionMapPageRow(
int RowNumber,
string CveId,
string Confidence,
string ConfidenceScore,
string PreventionScore,
string RealWorldCoverageScore,
string Cwe,
string FunctionsPreview);

public sealed record CveCorpusPageResult(
int Page,
int TotalPages,
int PageSize,
int TotalRows,
IReadOnlyList<CveCorpusPageRow> Rows);

public sealed record CveFunctionMapPageResult(
int Page,
int TotalPages,
int PageSize,
int TotalRows,
IReadOnlyList<CveFunctionMapPageRow> Rows);

public sealed class CveGridDisplayRow
{
    public string RowNumber { get; set; } = string.Empty;
    public string CveId { get; set; } = string.Empty;
    public string Severity { get; set; } = string.Empty;
    public string Score { get; set; } = string.Empty;
    public string Cwe { get; set; } = string.Empty;
    public string Confidence { get; set; } = string.Empty;
    public string Prevention { get; set; } = string.Empty;
    public string Functions { get; set; } = string.Empty;
}

