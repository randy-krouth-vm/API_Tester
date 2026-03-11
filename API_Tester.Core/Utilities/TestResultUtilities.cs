using System.Text;

namespace ApiTester.Core;

public static class TestResultUtilities
{
    public static bool ContainsAny(string input, params string[] markers) =>
        markers.Any(m => input.Contains(m, StringComparison.OrdinalIgnoreCase));

    public static string TryGetHeader(HttpResponseMessage response, string headerName)
    {
        try
        {
            if (response.Headers.TryGetValues(headerName, out var values))
            {
                return string.Join(",", values);
            }
        }
        catch
        {
            // Continue to content header lookup.
        }

        try
        {
            if (response.Content.Headers.TryGetValues(headerName, out var values))
            {
                return string.Join(",", values);
            }
        }
        catch
        {
            // Ignore invalid header collection usage and return empty.
        }

        return string.Empty;
    }

    public static bool HasHeader(HttpResponseMessage response, string headerName) =>
        !string.IsNullOrWhiteSpace(TryGetHeader(response, headerName));

    public static Uri AppendQuery(Uri baseUri, IDictionary<string, string> additions)
    {
        var builder = new UriBuilder(baseUri);
        var query = UriMutationUtilities.ParseQuery(builder.Query);

        foreach (var kvp in additions)
        {
            query[kvp.Key] = kvp.Value;
        }

        builder.Query = UriMutationUtilities.BuildQuery(query);
        return builder.Uri;
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
}
