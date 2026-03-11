using System.Text;

namespace ApiTester.Core;

public sealed class ScanWorkflowCoordinator
{
    public ScanWorkflowState State { get; } = new();

    private static async Task<string> RunSectionAsync(
        string sectionName,
        Uri baseUri,
        Func<Uri, ScanOptions> buildOptions,
        Func<string, Uri, Finding?, string> formatSection,
        Func<CoreScanEngine, ScanOptions, Task<Finding?>> executeAsync)
    {
        var engine = new CoreScanEngine();
        return formatSection(sectionName, baseUri, await executeAsync(engine, buildOptions(baseUri)));
    }

    public async Task OnSyncCveCorpusClickedAsync(
        Action<bool, string?> setBusy,
        Action<string> setProgressResult,
        Action setTextSummaryMode,
        Action<string> showCveText,
        Action<string> setResult,
        Func<IProgress<string>, Task<(int Count, int TotalResults, string SummaryText)>> executeSyncAsync)
    {
        setBusy(true, "Syncing complete CVE corpus from NVD... this can take a long time.");
        try
        {
            var progress = new Progress<string>(setProgressResult);
            var result = await executeSyncAsync(progress);
            setTextSummaryMode();
            showCveText(result.SummaryText);
            setResult($"CVE corpus sync complete. Stored {result.Count} CVEs (NVD total at sync: {result.TotalResults}).");
        }
        catch (Exception ex)
        {
            setResult($"CVE corpus sync failed: {ex.Message}");
        }
        finally
        {
            setBusy(false, null);
        }
    }

    public async Task OnLoadCveCorpusClickedAsync(
        Action<bool, string?> setBusy,
        Action setTextSummaryMode,
        Action<string> showCveText,
        Action<string> announceStatus,
        Action<string> setResult,
        Func<Task<string>> buildSummaryAsync)
    {
        setBusy(true, "Loading Local CVE Corpus Summary...");
        try
        {
            var summary = await buildSummaryAsync();
            setTextSummaryMode();
            showCveText(summary);
            announceStatus("Loaded local CVE corpus summary.");
        }
        catch (Exception ex)
        {
            setResult($"Failed to load local CVE corpus summary: {ex.Message}");
        }
        finally
        {
            setBusy(false, null);
        }
    }

    public async Task OnBuildFunctionMapClickedAsync(
        Action<bool, string?> setBusy,
        Action<string> setProgressResult,
        Action setTextSummaryMode,
        Action<string> showCveText,
        Action<string> announceStatus,
        Action<string> setResult,
        Func<IProgress<string>, Task<(int Count, int UniqueFunctionsCovered, string SummaryText)>> executeBuildAsync)
    {
        setBusy(true, "Building CVE Function Map (all local CVEs)...");
        try
        {
            var progress = new Progress<string>(setProgressResult);
            var result = await executeBuildAsync(progress);
            setTextSummaryMode();
            showCveText(result.SummaryText);
            announceStatus($"CVE function map complete. Processed {result.Count} CVEs. Unique mapped functions: {result.UniqueFunctionsCovered}.");
        }
        catch (Exception ex)
        {
            setResult($"Failed to build CVE function map: {ex.Message}");
        }
        finally
        {
            setBusy(false, null);
        }
    }

    public async Task OnLoadFunctionMapSummaryClickedAsync(
        Action<bool, string?> setBusy,
        Action setTextSummaryMode,
        Action<string> showCveText,
        Action<string> announceStatus,
        Action<string> setResult,
        Func<Task<string>> buildSummaryAsync)
    {
        setBusy(true, "Loading Function Map Summary...");
        try
        {
            var summary = await buildSummaryAsync();
            setTextSummaryMode();
            showCveText(summary);
            announceStatus("Loaded CVE function map summary.");
        }
        catch (Exception ex)
        {
            setResult($"Failed to load function-map summary: {ex.Message}");
        }
        finally
        {
            setBusy(false, null);
        }
    }

    public async Task OnFindCveClickedAsync(
        string? query,
        Action<bool, string?> setBusy,
        Action setTextSummaryMode,
        Action<string> showCveText,
        Action<string> announceStatus,
        Action<string> setResult,
        Func<string, Task<string>> buildLookupAsync)
    {
        var trimmedQuery = query?.Trim();
        setBusy(true, $"Searching local CVE files for '{trimmedQuery}'...");
        try
        {
            var lookup = await buildLookupAsync(trimmedQuery ?? string.Empty);
            setTextSummaryMode();
            showCveText(lookup);
            announceStatus("CVE lookup complete.");
        }
        catch (Exception ex)
        {
            setResult($"CVE lookup failed: {ex.Message}");
        }
        finally
        {
            setBusy(false, null);
        }
    }

    public async Task OnFindInResultsClickedAsync(
        ScanWorkflowState state,
        Func<Task<(bool Accepted, string Query, bool CaseSensitive)>> promptAsync,
        Func<Task> findForwardAsync)
    {
        if (state.SuppressFindPromptOnNextInvoke && !string.IsNullOrWhiteSpace(state.ResultsFindQuery))
        {
            state.SuppressFindPromptOnNextInvoke = false;
            await findForwardAsync();
            return;
        }

        state.SuppressFindPromptOnNextInvoke = false;
        var prompt = await promptAsync();
        if (!prompt.Accepted)
        {
            return;
        }

        var query = prompt.Query.Trim();
        if (string.IsNullOrWhiteSpace(query))
        {
            return;
        }

        state.ResultsFindCaseSensitive = prompt.CaseSensitive;
        state.ResultsFindQuery = query;
        state.ResultsFindIndex = -1;
        await findForwardAsync();
    }

    public async Task FindInResultsAsync(
        ScanWorkflowState state,
        bool forward,
        Func<string> getResultsText,
        Func<Task<string?>> promptQueryAsync,
        Func<string, string, string, Task> showAlertAsync,
        Action<int, int> applySelection)
    {
        var text = getResultsText() ?? string.Empty;
        if (string.IsNullOrEmpty(text))
        {
            await showAlertAsync("Find", "Results are empty.", "OK");
            return;
        }

        if (string.IsNullOrWhiteSpace(state.ResultsFindQuery))
        {
            var query = await promptQueryAsync();
            if (query is null)
            {
                return;
            }

            query = query.Trim();
            if (string.IsNullOrWhiteSpace(query))
            {
                return;
            }

            state.ResultsFindQuery = query;
            state.ResultsFindIndex = -1;
        }

        var needle = state.ResultsFindQuery!;
        var matchIndex = ResultFindWorkflowUtilities.FindMatchIndex(
            text,
            needle,
            state.ResultsFindIndex,
            state.ResultsFindCaseSensitive,
            forward);

        if (matchIndex < 0)
        {
            await showAlertAsync("Find", $"No matches for \"{needle}\".", "OK");
            return;
        }

        state.ResultsFindIndex = matchIndex;
        applySelection(matchIndex, needle.Length);
    }

    public async Task OnShowCatalogClickedAsync(
        Action<bool, string?> setBusy,
        Func<Task<object?>> loadCatalogAsync,
        Func<object, string> buildCatalogReport,
        Func<string?> getLastLoadError,
        Action<string> setResult)
    {
        setBusy(true, "Loading dynamic catalog...");
        try
        {
            var catalog = await loadCatalogAsync();
            if (catalog is null)
            {
                var details = string.IsNullOrWhiteSpace(getLastLoadError())
                    ? "Unknown load failure."
                    : getLastLoadError();
                setResult($"Unable to load security-tests.json catalog. {details}");
                return;
            }

            setResult(buildCatalogReport(catalog));
        }
        finally
        {
            setBusy(false, null);
        }
    }

    public async Task OnSpiderSiteClickedAsync(
        Func<bool> tryPrepareTarget,
        Func<Uri> getCurrentTarget,
        Action<bool, string?> setBusy,
        Func<Uri, Task<string>> runSpiderAsync,
        Action<string> setResult)
    {
        if (!tryPrepareTarget())
        {
            return;
        }

        var uri = getCurrentTarget();
        setBusy(true, "Spidering target (same-origin, safe crawl)...");
        try
        {
            setResult(await runSpiderAsync(uri));
        }
        finally
        {
            setBusy(false, null);
        }
    }

    public async Task OnRunMaxCoverageClickedAsync(
        Func<bool> tryPrepareTarget,
        Func<Uri> getCurrentTarget,
        Action<bool, string?> setBusy,
        Action<string> setProgressResult,
        Func<Uri, IProgress<string>, Task<string>> runAssessmentAsync,
        Action<string> setResult)
    {
        if (!tryPrepareTarget())
        {
            return;
        }

        var uri = getCurrentTarget();
        setBusy(true, "Running maximum static + dynamic coverage assessment...");
        try
        {
            var progress = new Progress<string>(setProgressResult);
            var report = await runAssessmentAsync(uri, progress);
            setResult(report);
        }
        finally
        {
            setBusy(false, null);
        }
    }

    public async Task OnRunCompositeReportClickedAsync(
        Func<bool> tryPrepareTarget,
        Func<Uri> getCurrentTarget,
        Action resetRunLog,
        Action<bool> setCaptureRunProgress,
        Action setTextSummaryMode,
        Action<bool, string?> setBusy,
        string busyMessage,
        string sectionTitle,
        string errorPrefix,
        Func<Uri, Task<string>> buildReportAsync,
        Action<string, string> appendRunLogSection)
    {
        if (!tryPrepareTarget())
        {
            return;
        }

        var uri = getCurrentTarget();
        resetRunLog();
        setCaptureRunProgress(true);
        setTextSummaryMode();
        setBusy(true, busyMessage);
        try
        {
            var runReport = await buildReportAsync(uri);
            appendRunLogSection(sectionTitle, runReport);
        }
        catch (Exception ex)
        {
            appendRunLogSection(sectionTitle, $"{errorPrefix}: {ex.Message}");
        }
        finally
        {
            setCaptureRunProgress(false);
            setBusy(false, null);
        }
    }

    public async Task OnRunValidationHarnessClickedAsync(
        Action resetRunLog,
        Action<bool, string?> setBusy,
        Func<Task<string>> runValidationHarnessAsync,
        Action<string> setResult)
    {
        resetRunLog();
        setBusy(true, "Running validation sequence scenarios...");
        try
        {
            var report = await runValidationHarnessAsync();
            setResult(report);
        }
        catch (Exception ex)
        {
            setResult($"Validation harness failed: {ex.Message}");
        }
        finally
        {
            setBusy(false, null);
        }
    }

    public async Task OnRunFrameworkClickedAsync(
        string? frameworkName,
        Func<string, (string Category, Func<Uri, Task<string>>[] Tests)?> getFrameworkPackFor,
        Action<string> setResult,
        Func<string, string[], IReadOnlyList<Func<Uri, Task<string>>>, string, Task> executeFrameworkPackAsync)
    {
        if (string.IsNullOrWhiteSpace(frameworkName))
        {
            setResult("Framework button is not configured correctly.");
            return;
        }

        var pack = getFrameworkPackFor(frameworkName);
        if (pack is null)
        {
            setResult($"No test pack mapping found for: {frameworkName}");
            return;
        }

        await executeFrameworkPackAsync(
            pack.Value.Category,
            new[] { frameworkName },
            pack.Value.Tests,
            $"Running {frameworkName} checks...");
    }

    public async Task OnRunFrameworkTestClickedAsync(
        string? parameter,
        Func<string, (string TestName, Func<Uri, Task<string>>? Test)> resolveTestByKey,
        Func<string, string> getFrameworkCategory,
        Func<string, string, List<string>> getComplianceMappings,
        Func<string, string> getSpecificationForTestKey,
        Func<string, Func<Uri, Task<string>>, Func<Uri, Task<string>>> wrapWithStandardContext,
        Action<string> setResult,
        Func<string, string[], IReadOnlyList<Func<Uri, Task<string>>>, string, Task> executeFrameworkPackAsync)
    {
        if (string.IsNullOrWhiteSpace(parameter) || !parameter.Contains('|'))
        {
            setResult("Framework test button is not configured correctly.");
            return;
        }

        var parts = parameter.Split('|', 2);
        var frameworkName = parts[0].Trim();
        var testKey = parts[1].Trim();

        var resolved = resolveTestByKey(testKey);
        if (resolved.Test is null)
        {
            setResult($"Unknown test key: {testKey}");
            return;
        }

        var category = getFrameworkCategory(frameworkName);
        var compliance = getComplianceMappings(frameworkName, testKey);
        var mappingLine = compliance.Count == 0
            ? $"Specification: {getSpecificationForTestKey(testKey)}"
            : $"Specification: {string.Join(" | ", compliance)}";

        await executeFrameworkPackAsync(
            category,
            new[] { frameworkName, $"Individual Test: {resolved.TestName}", mappingLine },
            new[] { wrapWithStandardContext(testKey, resolved.Test) },
            $"Running {frameworkName} - {resolved.TestName}...");
    }

    public async Task OnSaveLogClickedAsync(
        string text,
        Action<string> setResult,
        Action<bool, string?> setBusy,
        Func<string> getLogsDirectory,
        Func<DateTime> getUtcNow,
        Func<string, string, Task> writeAllTextAsync,
        Action<string> announceStatus)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            setResult("No in-memory log content to save.");
            return;
        }

        setBusy(true, "Saving log...");
        try
        {
            var logsDir = getLogsDirectory();
            Directory.CreateDirectory(logsDir);
            var fileName = $"api-tester-log-{getUtcNow():yyyyMMdd-HHmmss}.txt";
            var filePath = Path.Combine(logsDir, fileName);
            await writeAllTextAsync(filePath, text);
            announceStatus($"Log saved: {fileName}");
        }
        catch (Exception ex)
        {
            setResult($"Save log failed: {ex.Message}");
        }
        finally
        {
            setBusy(false, null);
        }
    }

    public Task<string> RunSecurityHeadersSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("Security Headers", baseUri, buildOptions, formatSection, (engine, options) => engine.RunSecurityHeadersAsync(options));

    public Task<string> RunCorsSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("CORS", baseUri, buildOptions, formatSection, (engine, options) => engine.RunCorsAsync(options));

    public Task<string> RunHttpMethodsSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("HTTP Methods", baseUri, buildOptions, formatSection, (engine, options) => engine.RunHttpMethodsAsync(options));

    public Task<string> RunSqlInjectionSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("SQL Injection", baseUri, buildOptions, formatSection, (engine, options) => engine.RunSqlInjectionAsync(options));

    public Task<string> RunXssSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("XSS", baseUri, buildOptions, formatSection, (engine, options) => engine.RunXssAsync(options));

    public Task<string> RunSsrfSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("SSRF", baseUri, buildOptions, formatSection, (engine, options) => engine.RunSsrfAsync(options));

    public Task<string> RunRateLimitSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("Rate Limiting", baseUri, buildOptions, formatSection, (engine, options) => engine.RunRateLimitAsync(options));

    public Task<string> RunInformationDisclosureSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("Information Disclosure", baseUri, buildOptions, formatSection, (engine, options) => engine.RunInformationDisclosureAsync(options));

    public Task<string> RunTransportSecuritySectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("Transport Security", baseUri, buildOptions, formatSection, (engine, options) => engine.RunTransportSecurityAsync(options));

    public Task<string> RunErrorHandlingLeakageSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("Error Handling Leakage", baseUri, buildOptions, formatSection, (engine, options) => engine.RunErrorHandlingLeakageAsync(options));

    public Task<string> RunAuthAndAccessControlSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("Authentication and Access Control", baseUri, buildOptions, formatSection, (engine, options) => engine.RunAuthAndAccessControlAsync(options));

    public Task<string> RunBrokenAuthenticationSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("Broken Authentication", baseUri, buildOptions, formatSection, (engine, options) => engine.RunBrokenAuthenticationAsync(options));

    public Task<string> RunBrokenFunctionLevelAuthorizationSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("Broken Function Level Authorization", baseUri, buildOptions, formatSection, (engine, options) => engine.RunBrokenFunctionLevelAuthorizationAsync(options));

    public Task<string> RunBrokenObjectPropertyLevelAuthorizationSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("Broken Object Property Level Authorization", baseUri, buildOptions, formatSection, (engine, options) => engine.RunBrokenObjectPropertyLevelAuthorizationAsync(options));

    public Task<string> RunCrossTenantDataLeakageSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("Cross-Tenant Data Leakage", baseUri, buildOptions, formatSection, (engine, options) => engine.RunCrossTenantDataLeakageAsync(options));

    public Task<string> RunBolaSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("BOLA / Object ID Tampering", baseUri, buildOptions, formatSection, (engine, options) => engine.RunBolaAsync(options));

    public Task<string> RunCookieSecurityFlagsSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("Cookie Security Flags", baseUri, buildOptions, formatSection, (engine, options) => engine.RunCookieSecurityFlagsAsync(options));

    public Task<string> RunContentTypeValidationSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("Content-Type Validation", baseUri, buildOptions, formatSection, (engine, options) => engine.RunContentTypeValidationAsync(options));

    public Task<string> RunImproperInventoryManagementSectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("Improper Inventory Management", baseUri, buildOptions, formatSection, (engine, options) => engine.RunImproperInventoryManagementAsync(options));

    public Task<string> RunIdempotencyReplaySectionAsync(Uri baseUri, Func<Uri, ScanOptions> buildOptions, Func<string, Uri, Finding?, string> formatSection) =>
        RunSectionAsync("Idempotency Replay", baseUri, buildOptions, formatSection, (engine, options) => engine.RunIdempotencyReplayAsync(options));

    public async Task OnLoadLogClickedAsync(
        Func<Task<string?>> pickLogFilePathAsync,
        Func<string, Task<string>> readAllTextAsync,
        Action<string> setLoadedLogText,
        Action setRunLogPagedMode,
        Action resetResultsPage,
        Action applyResultView,
        Action<string> announceStatus,
        Action<string> setResult)
    {
        try
        {
            var path = await pickLogFilePathAsync();
            if (string.IsNullOrWhiteSpace(path))
            {
                return;
            }

            var text = await readAllTextAsync(path);
            setRunLogPagedMode();
            setLoadedLogText(text ?? string.Empty);
            resetResultsPage();
            applyResultView();
            announceStatus($"Loaded log: {Path.GetFileName(path)}");
        }
        catch (Exception ex)
        {
            setResult($"Load log failed: {ex.Message}");
        }
    }

    public async Task OnLoadCorpusPagedClickedAsync(Action setCorpusPagedMode, Action resetCvePage, Func<Task> loadPagedViewAsync)
    {
        setCorpusPagedMode();
        resetCvePage();
        await loadPagedViewAsync();
    }

    public async Task OnLoadFunctionMapPagedClickedAsync(Action setFunctionMapPagedMode, Action resetCvePage, Func<Task> loadPagedViewAsync)
    {
        setFunctionMapPagedMode();
        resetCvePage();
        await loadPagedViewAsync();
    }

    public async Task OnPrevPageClickedAsync(
        Func<bool> isFunctionMapPaged,
        Func<bool> isCorpusPaged,
        Func<bool> isResultsPagingActive,
        Func<int> getCvePage,
        Action<int> setCvePage,
        Func<Task> loadFunctionMapPageAsync,
        Func<Task> loadCorpusPageAsync,
        Func<int> getResultsPage,
        Action<int> setResultsPage,
        Action applyResultsPageView,
        Action<string> announceStatus)
    {
        if (isFunctionMapPaged())
        {
            if (getCvePage() > 1)
            {
                setCvePage(getCvePage() - 1);
            }

            await loadFunctionMapPageAsync();
            return;
        }

        if (isCorpusPaged())
        {
            if (getCvePage() > 1)
            {
                setCvePage(getCvePage() - 1);
            }

            await loadCorpusPageAsync();
            return;
        }

        if (isResultsPagingActive())
        {
            if (getResultsPage() > 1)
            {
                setResultsPage(getResultsPage() - 1);
                applyResultsPageView();
            }

            return;
        }

        announceStatus("No paged view is active.");
    }

    public async Task OnNextPageClickedAsync(
        Func<bool> isFunctionMapPaged,
        Func<bool> isCorpusPaged,
        Func<bool> isResultsPagingActive,
        Func<int> getCvePage,
        Action<int> setCvePage,
        Func<Task> loadFunctionMapPageAsync,
        Func<Task> loadCorpusPageAsync,
        Func<int> getResultsPage,
        Action<int> setResultsPage,
        Action applyResultsPageView,
        Action<string> announceStatus)
    {
        if (isFunctionMapPaged())
        {
            setCvePage(getCvePage() + 1);
            await loadFunctionMapPageAsync();
            return;
        }

        if (isCorpusPaged())
        {
            setCvePage(getCvePage() + 1);
            await loadCorpusPageAsync();
            return;
        }

        if (isResultsPagingActive())
        {
            setResultsPage(getResultsPage() + 1);
            applyResultsPageView();
            return;
        }

        announceStatus("No paged view is active.");
    }

    public async Task OnGoToPageClickedAsync(
        string? rawPage,
        Action<string> setResult,
        Action<int> setCvePage,
        Func<bool> isFunctionMapPaged,
        Func<bool> isCorpusPaged,
        Func<Task> loadFunctionMapPageAsync,
        Func<Task> loadCorpusPageAsync)
    {
        var raw = rawPage?.Trim();
        if (!int.TryParse(raw, out var targetPage) || targetPage < 1)
        {
            setResult("Enter a valid page number (1 or greater).");
            return;
        }

        setCvePage(targetPage);
        if (isFunctionMapPaged())
        {
            await loadFunctionMapPageAsync();
            return;
        }

        if (isCorpusPaged())
        {
            await loadCorpusPageAsync();
            return;
        }

        setResult("Select a paged view first, then use Go To Page.");
    }

    public async Task OnApplyPriorityFilterClickedAsync(
        Func<bool> isFunctionMapPaged,
        Action resetCvePage,
        Func<Task> loadFunctionMapPageAsync,
        Action<string> announceStatus)
    {
        if (isFunctionMapPaged())
        {
            resetCvePage();
            await loadFunctionMapPageAsync();
            return;
        }

        announceStatus("Priority filter is applied when viewing function-map pages.");
    }

    public void OnPriorityFilterChanged(Func<bool> isFunctionMapPaged, Action<string> announceStatus)
    {
        if (isFunctionMapPaged())
        {
            announceStatus("Priority changed. Click 'Apply Priority Filter' to load.");
        }
    }

    public async Task ExecuteSingleTestAsync(
        string name,
        Func<bool> tryPrepareTarget,
        Func<Uri> getCurrentTarget,
        Action resetRunLog,
        Action<bool, string?> setBusy,
        Func<string> getSelectedScopeLabel,
        Action<bool, Uri?> setStrictSingleTargetMode,
        Func<Uri, Task<string>> test,
        Func<Uri, Task<IReadOnlyList<Uri>>> resolveScopeTargetsAsync,
        Action<string, string> appendRunLogSection)
    {
        if (!tryPrepareTarget())
        {
            return;
        }

        var uri = getCurrentTarget();
        resetRunLog();
        setBusy(true, $"Running {name} test...");
        try
        {
            var scopeLabel = getSelectedScopeLabel();
            if (scopeLabel == "Single Target")
            {
                setStrictSingleTargetMode(true, uri);
                try
                {
                    var result = await test(uri);
                    appendRunLogSection(name, result);
                }
                finally
                {
                    setStrictSingleTargetMode(false, null);
                }

                return;
            }

            var targets = await resolveScopeTargetsAsync(uri);
            var sb = new StringBuilder();
            sb.AppendLine($"=== {name} ===");
            sb.AppendLine($"Base target: {uri}");
            sb.AppendLine($"Scope: {scopeLabel} ({targets.Count} target(s))");
            sb.AppendLine();

            foreach (var target in targets)
            {
                try
                {
                    sb.AppendLine(await test(target));
                }
                catch (Exception ex)
                {
                    sb.AppendLine($"[{name}]");
                    sb.AppendLine($"Target: {target}");
                    sb.AppendLine($"- Execution error: {ex.Message}");
                }

                sb.AppendLine();
            }

            appendRunLogSection(name, sb.ToString().TrimEnd());
        }
        catch (Exception ex)
        {
            appendRunLogSection(name, $"{name} test failed: {ex.Message}");
        }
        finally
        {
            setBusy(false, null);
        }
    }

    public async Task ExecuteFrameworkPackAsync(
        string categoryName,
        string runMessage,
        Func<bool> tryPrepareTarget,
        Func<Uri> getCurrentTarget,
        Action resetRunLog,
        Action<bool, string?> setBusy,
        Func<Task<string>> buildReportAsync,
        Action<string> setResult)
    {
        if (!tryPrepareTarget())
        {
            return;
        }

        _ = getCurrentTarget();
        resetRunLog();
        setBusy(true, runMessage);
        try
        {
            var report = await buildReportAsync();
            setResult(report);
        }
        catch (Exception ex)
        {
            setResult($"{categoryName} failed: {ex.Message}");
        }
        finally
        {
            setBusy(false, null);
        }
    }

    public async Task<string> BuildSingleTargetFrameworkPackReportAsync(
        string categoryName,
        IReadOnlyList<string> frameworks,
        Uri uri,
        IReadOnlyList<Func<Uri, Task<string>>> tests,
        Func<string, IReadOnlyList<string>, Uri, string, int, IReadOnlyList<string>, string> buildFrameworkPackReport)
    {
        var sections = new List<string>();
        foreach (var test in tests)
        {
            try
            {
                sections.Add(await test(uri));
            }
            catch (Exception ex)
            {
                sections.Add($"[{test.Method.Name}]{Environment.NewLine}Target: {uri}{Environment.NewLine}- Execution error: {ex.Message}");
            }
        }

        return buildFrameworkPackReport(
            categoryName,
            frameworks,
            uri,
            "Single Target",
            1,
            sections);
    }
}
