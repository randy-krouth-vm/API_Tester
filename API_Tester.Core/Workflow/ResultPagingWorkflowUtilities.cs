namespace ApiTester.Core;

public enum ResultPagingMode
{
    TextSummary,
    CorpusPaged,
    FunctionMapPaged,
    RunLogPaged
}

public sealed record ResultPageView(
    string Text,
    string Label,
    bool PrevEnabled,
    bool NextEnabled,
    int CurrentPage);

public static class ResultPagingWorkflowUtilities
{
    public static (string RunLog, int ResultsPage) AppendRunLogSection(
        string existingLog,
        string title,
        string body,
        int pageLineCount,
        DateTime utcNow)
    {
        var normalizedExisting = existingLog ?? string.Empty;
        var sectionStartLine = 0;
        if (!string.IsNullOrWhiteSpace(normalizedExisting))
        {
            sectionStartLine = normalizedExisting.Replace("\r\n", "\n").Split('\n').Length + 2;
        }

        var timestampUtc = utcNow.ToString("yyyy-MM-dd HH:mm:ssZ");
        var section = $"=== {title} ==={Environment.NewLine}Timestamp (UTC): {timestampUtc}{Environment.NewLine}{Environment.NewLine}{(body ?? string.Empty).TrimEnd()}";
        var updatedLog = string.IsNullOrWhiteSpace(normalizedExisting)
            ? section.TrimEnd()
            : $"{normalizedExisting.TrimEnd()}{Environment.NewLine}{Environment.NewLine}{section}".TrimEnd();
        var targetPage = (sectionStartLine / pageLineCount) + 1;
        return (updatedLog, targetPage);
    }

    public static string AppendRunProgress(string existingLog, string message)
    {
        var entry = message ?? string.Empty;
        if (string.IsNullOrWhiteSpace(entry))
        {
            return existingLog ?? string.Empty;
        }

        if (string.IsNullOrWhiteSpace(existingLog))
        {
            return entry;
        }

        return $"{existingLog}{Environment.NewLine}{entry}";
    }

    public static ResultPageView BuildResultsPageView(
        ResultPagingMode pagingMode,
        string renderedResultsText,
        string inMemoryRunLog,
        int requestedPage,
        int pageLineCount)
    {
        var source = renderedResultsText ?? string.Empty;
        if (source.Length == 0 && pagingMode != ResultPagingMode.RunLogPaged)
        {
            return new ResultPageView(string.Empty, string.Empty, false, false, 1);
        }

        if (pagingMode == ResultPagingMode.CorpusPaged || pagingMode == ResultPagingMode.FunctionMapPaged)
        {
            return new ResultPageView(
                source,
                ResultPresentation.ExtractEmbeddedPageLabel(source),
                PrevEnabled: true,
                NextEnabled: true,
                CurrentPage: requestedPage);
        }

        if (pagingMode == ResultPagingMode.RunLogPaged)
        {
            return BuildLinePagedView(inMemoryRunLog ?? string.Empty, requestedPage, pageLineCount);
        }

        return BuildLinePagedView(source, requestedPage, pageLineCount);
    }

    public static bool IsResultsPagingActive(
        ResultPagingMode pagingMode,
        string renderedResultsText,
        string inMemoryRunLog,
        int pageLineCount)
    {
        if (pagingMode == ResultPagingMode.RunLogPaged)
        {
            var totalRunLogLines = (inMemoryRunLog ?? string.Empty).Replace("\r\n", "\n").Split('\n').Length;
            return totalRunLogLines > pageLineCount;
        }

        if (pagingMode != ResultPagingMode.TextSummary)
        {
            return false;
        }

        var source = renderedResultsText ?? string.Empty;
        if (source.Length == 0)
        {
            return false;
        }

        var totalLines = source.Replace("\r\n", "\n").Split('\n').Length;
        return totalLines > pageLineCount;
    }

    private static ResultPageView BuildLinePagedView(string source, int requestedPage, int pageLineCount)
    {
        if (source.Length == 0)
        {
            return new ResultPageView(string.Empty, string.Empty, false, false, 1);
        }

        var lines = source.Replace("\r\n", "\n").Split('\n');
        var totalPages = Math.Max(1, (int)Math.Ceiling(lines.Length / (double)pageLineCount));
        var clampedPage = Math.Clamp(requestedPage, 1, totalPages);
        var start = (clampedPage - 1) * pageLineCount;
        var count = Math.Min(pageLineCount, lines.Length - start);
        var pageText = string.Join(Environment.NewLine, lines.Skip(start).Take(count));
        var pageLabel = $"Page {clampedPage} of {totalPages}";
        return new ResultPageView(
            pageText,
            pageLabel,
            PrevEnabled: clampedPage > 1,
            NextEnabled: clampedPage < totalPages,
            CurrentPage: clampedPage);
    }
}
