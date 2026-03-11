using System.Text;
using API_Tester.SecurityCatalog;

namespace ApiTester.Core;

public static class PagingDiagnosticsUtilities
{
    public static async Task<string> RunPagingSelfTestAsync(int pageSize = 250)
    {
        var sb = new StringBuilder();
        sb.AppendLine("[Paging Self-Test]");
        sb.AppendLine($"Page size: {pageSize}");

        var corpusExists = await CveCorpusService.HasCorpusAsync();
        if (!corpusExists)
        {
            sb.AppendLine("- Corpus file: missing");
        }
        else
        {
            var p1 = await CveCorpusService.GetCorpusPageAsync(1, pageSize);
            var p2 = await CveCorpusService.GetCorpusPageAsync(2, pageSize);
            var plast = await CveCorpusService.GetCorpusPageAsync(int.MaxValue, pageSize);

            var corpusContiguous = p1.Rows.Count == 0 ||
                                   p2.Rows.Count == 0 ||
                                   p1.Rows[^1].RowNumber + 1 == p2.Rows[0].RowNumber;
            var corpusLastInRange = plast.Page >= 1 && plast.Page <= plast.TotalPages;

            sb.AppendLine($"- Corpus total rows: {p1.TotalRows}");
            sb.AppendLine($"- Corpus pages: {p1.TotalPages}");
            sb.AppendLine($"- Corpus page1 rows: {p1.Rows.Count}");
            sb.AppendLine($"- Corpus page2 rows: {p2.Rows.Count}");
            sb.AppendLine($"- Corpus last page: {plast.Page}/{plast.TotalPages} rows={plast.Rows.Count}");
            sb.AppendLine($"- Corpus contiguous page boundary: {(corpusContiguous ? "PASS" : "FAIL")}");
            sb.AppendLine($"- Corpus last-page clamp: {(corpusLastInRange ? "PASS" : "FAIL")}");
        }

        var mapExists = await CveCorpusService.HasFunctionMapAsync();
        if (!mapExists)
        {
            sb.AppendLine("- Function map file: missing");
        }
        else
        {
            var p1 = await CveCorpusService.GetFunctionMapPageAsync(1, pageSize);
            var p2 = await CveCorpusService.GetFunctionMapPageAsync(2, pageSize);
            var plast = await CveCorpusService.GetFunctionMapPageAsync(int.MaxValue, pageSize);

            var mapContiguous = p1.Rows.Count == 0 ||
                                p2.Rows.Count == 0 ||
                                p1.Rows[^1].RowNumber + 1 == p2.Rows[0].RowNumber;
            var mapLastInRange = plast.Page >= 1 && plast.Page <= plast.TotalPages;

            sb.AppendLine($"- Function-map total rows: {p1.TotalRows}");
            sb.AppendLine($"- Function-map pages: {p1.TotalPages}");
            sb.AppendLine($"- Function-map page1 rows: {p1.Rows.Count}");
            sb.AppendLine($"- Function-map page2 rows: {p2.Rows.Count}");
            sb.AppendLine($"- Function-map last page: {plast.Page}/{plast.TotalPages} rows={plast.Rows.Count}");
            sb.AppendLine($"- Function-map contiguous page boundary: {(mapContiguous ? "PASS" : "FAIL")}");
            sb.AppendLine($"- Function-map last-page clamp: {(mapLastInRange ? "PASS" : "FAIL")}");
        }

        return sb.ToString().TrimEnd();
    }
}
