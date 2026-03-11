using System.Text;
using System.Text.Json;

namespace ApiTester.Core;

public static class BusinessScenarioWorkflowUtilities
{
    public static async Task<(string Source, string PreviousHash)> ExecuteBusinessLogicScenariosAsync(
        string? configuredSourcePath,
        Uri baseUri,
        IReadOnlyList<AuthProfile> runProfiles,
        string categoryName,
        List<string> sections,
        List<TestEvidenceRecord> records,
        string previousHash,
        Func<BusinessLogicScenario, AuthProfile, Uri, Task<BusinessScenarioExecutionResult>> executeScenarioAsync)
    {
        var sourcePath = configuredSourcePath?.Trim();
        if (string.IsNullOrWhiteSpace(sourcePath) || !File.Exists(sourcePath))
        {
            return (string.IsNullOrWhiteSpace(sourcePath) ? "not-configured" : $"missing:{sourcePath}", previousHash);
        }

        List<BusinessLogicScenario>? scenarios;
        try
        {
            var raw = await File.ReadAllTextAsync(sourcePath);
            scenarios = JsonSerializer.Deserialize<List<BusinessLogicScenario>>(raw);
        }
        catch
        {
            sections.Add("[Business Logic Scenarios]\n- Failed to parse scenario file.");
            return ($"parse-error:{sourcePath}", previousHash);
        }

        if (scenarios is null || scenarios.Count == 0)
        {
            sections.Add("[Business Logic Scenarios]\n- No scenarios found.");
            return ($"empty:{sourcePath}", previousHash);
        }

        sections.Add($"[Business Logic Scenarios]\n- Loaded: {scenarios.Count}\n- Source: {sourcePath}");

        foreach (var scenario in scenarios)
        {
            var profile = runProfiles.FirstOrDefault(p => p.Name.Equals(scenario.AuthProfile, StringComparison.OrdinalIgnoreCase))
                          ?? runProfiles.FirstOrDefault(p => p.Name.Equals("user", StringComparison.OrdinalIgnoreCase))
                          ?? runProfiles.First();

            var execution = await executeScenarioAsync(scenario, profile, baseUri);
            sections.Add(execution.Output);

            var verdict = execution.HadException ? "inconclusive" : execution.Verdict;
            var cvss = AuditResultUtilities.GetCvssForResult($"BUSLOGIC:{scenario.Id}", verdict);
            var summary = AuditResultUtilities.BuildResultSummary(execution.Output);
            var remediation = "Implement scenario-specific authorization and transactional integrity checks for this business workflow.";
            var payload = new
            {
                FrameworkName = "Business Logic Scenarios",
                TestKey = $"BUSLOGIC:{scenario.Id}",
                scenario.Name,
                MethodName = "ScenarioRunner",
                AuthProfileName = profile.Name,
                TargetUri = execution.TargetUri,
                TimestampUtc = execution.TimestampUtc.ToString("O"),
                Verdict = verdict,
                CvssScore = cvss.Score,
                CvssSeverity = cvss.Severity,
                CvssVector = cvss.Vector,
                Summary = summary,
                Remediation = remediation,
                SignalOnly = false,
                Exchanges = execution.Exchanges
            };

            var payloadJson = JsonSerializer.Serialize(payload);
            var recordHash = AuditResultUtilities.ComputeSha256Hex($"{previousHash}|{payloadJson}");
            records.Add(new TestEvidenceRecord(
                categoryName,
                "Business Logic Scenarios",
                $"BUSLOGIC:{scenario.Id}",
                $"Business Logic Scenarios|BUSLOGIC:{scenario.Id}",
                scenario.Name,
                "ScenarioRunner",
                profile.Name,
                execution.TargetUri,
                execution.TimestampUtc.ToString("O"),
                verdict,
                cvss.Score,
                cvss.Severity,
                cvss.Vector,
                summary,
                remediation,
                false,
                execution.Exchanges,
                previousHash,
                recordHash));
            previousHash = recordHash;
        }

        return (sourcePath, previousHash);
    }

    public static HttpRequestMessage BuildScenarioRequest(Uri baseUri, BusinessLogicScenario scenario)
    {
        var method = ParseHttpMethodOrDefault(scenario.Method);
        var uri = new Uri(baseUri, scenario.Endpoint ?? "/");
        var request = new HttpRequestMessage(method, uri);
        if (!string.IsNullOrWhiteSpace(scenario.Body))
        {
            request.Content = new StringContent(scenario.Body, Encoding.UTF8, "application/json");
        }

        if (scenario.Headers is not null)
        {
            foreach (var (key, value) in scenario.Headers)
            {
                request.Headers.TryAddWithoutValidation(key, value);
            }
        }

        return request;
    }

    public static HttpMethod ParseHttpMethodOrDefault(string? method)
    {
        return (method?.Trim().ToUpperInvariant()) switch
        {
            "GET" => HttpMethod.Get,
            "POST" => HttpMethod.Post,
            "PUT" => HttpMethod.Put,
            "PATCH" => HttpMethod.Patch,
            "DELETE" => HttpMethod.Delete,
            "HEAD" => HttpMethod.Head,
            "OPTIONS" => HttpMethod.Options,
            "TRACE" => HttpMethod.Trace,
            _ => HttpMethod.Get
        };
    }

    public static string EvaluateBusinessScenarioVerdict(
        BusinessLogicScenario scenario,
        HttpResponseMessage? first,
        HttpResponseMessage? second)
    {
        if (first is null)
        {
            return "inconclusive";
        }

        var code = (int)first.StatusCode;
        if (scenario.ForbiddenStatuses is { Count: > 0 } && scenario.ForbiddenStatuses.Contains(code))
        {
            return "fail";
        }

        if (scenario.ExpectedStatus.HasValue && scenario.ExpectedStatus.Value != code)
        {
            return "fail";
        }

        if (scenario.RepeatRequest && scenario.ExpectStableStatus && second is not null && (int)second.StatusCode != code)
        {
            return "fail";
        }

        return "pass";
    }

    public static async Task<BusinessScenarioExecutionResult> ExecuteBusinessScenarioAsync(
        BusinessLogicScenario scenario,
        AuthProfile profile,
        Uri baseUri,
        Func<Func<HttpRequestMessage>, Task<HttpResponseMessage?>> safeSendAsync,
        Action<AuditCaptureContext?> setAuditCaptureContext,
        Action<AuthProfile?> setActiveAuthProfile,
        Func<string?, string> getAuthProfileDisplayName)
    {
        var capture = new AuditCaptureContext(new List<HttpExchangeEvidence>());
        setAuditCaptureContext(capture);
        setActiveAuthProfile(profile);
        var timestamp = DateTime.UtcNow;
        var targetUri = new Uri(baseUri, scenario.Endpoint ?? "/");
        try
        {
            var responseA = await safeSendAsync(() => BuildScenarioRequest(baseUri, scenario));
            HttpResponseMessage? responseB = null;
            if (scenario.RepeatRequest)
            {
                responseB = await safeSendAsync(() => BuildScenarioRequest(baseUri, scenario));
            }

            var verdict = EvaluateBusinessScenarioVerdict(scenario, responseA, responseB);
            var codeA = responseA is null ? "No response" : $"{(int)responseA.StatusCode} {responseA.StatusCode}";
            var codeB = responseB is null ? "N/A" : $"{(int)responseB.StatusCode} {responseB.StatusCode}";
            var output =
                $"[BusinessLogic:{scenario.Id}] {scenario.Name}{Environment.NewLine}" +
                $"Target: {new Uri(baseUri, scenario.Endpoint)}{Environment.NewLine}" +
                $"- Profile: {getAuthProfileDisplayName(profile.Name)}{Environment.NewLine}" +
                $"- Method: {scenario.Method}{Environment.NewLine}" +
                $"- Response-1: {codeA}{Environment.NewLine}" +
                $"- Response-2: {codeB}{Environment.NewLine}" +
                $"- Verdict: {verdict}{Environment.NewLine}" +
                $"- Description: {scenario.Description}";

            return new BusinessScenarioExecutionResult(
                output,
                verdict,
                timestamp,
                new Uri(baseUri, scenario.Endpoint).ToString(),
                capture.Exchanges,
                false);
        }
        catch (Exception ex)
        {
            var output =
                $"[BusinessLogic:{scenario.Id}] {scenario.Name}{Environment.NewLine}" +
                $"- Profile: {getAuthProfileDisplayName(profile.Name)}{Environment.NewLine}" +
                $"- Execution error: {ex.Message}";
            return new BusinessScenarioExecutionResult(
                output,
                "inconclusive",
                timestamp,
                targetUri.ToString(),
                capture.Exchanges,
                true);
        }
        finally
        {
            setAuditCaptureContext(null);
            setActiveAuthProfile(null);
        }
    }
}
