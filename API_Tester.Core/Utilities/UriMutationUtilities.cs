using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace ApiTester.Core;

public static class UriMutationUtilities
{
    public static Uri ApplyQueryOverride(Uri baseUri, string? keyOrRawQuery, string? value)
    {
        var builder = new UriBuilder(baseUri);
        var merged = ParseQuery(builder.Query);
        Dictionary<string, string> overrideValues;

        if (!string.IsNullOrWhiteSpace(keyOrRawQuery) && keyOrRawQuery.Contains('='))
        {
            var rawQuery = keyOrRawQuery.StartsWith("?", StringComparison.Ordinal) ? keyOrRawQuery : "?" + keyOrRawQuery;
            overrideValues = ParseQuery(rawQuery);
        }
        else if (!string.IsNullOrWhiteSpace(keyOrRawQuery))
        {
            overrideValues = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [keyOrRawQuery] = value ?? string.Empty
            };
        }
        else
        {
            var rawValue = value ?? string.Empty;
            overrideValues = ParseQuery(rawValue.StartsWith("?", StringComparison.Ordinal) ? rawValue : "?" + rawValue);
        }

        foreach (var kvp in overrideValues)
        {
            merged[kvp.Key] = kvp.Value;
        }

        builder.Query = BuildQuery(merged);
        return builder.Uri;
    }

    public static Uri AppendPathSegment(Uri baseUri, string segment)
    {
        var builder = new UriBuilder(baseUri);
        var safeSegment = Uri.EscapeDataString(segment ?? string.Empty);
        var path = builder.Path ?? "/";
        var trimmedPath = path.TrimEnd('/');
        var parts = trimmedPath.Split('/', StringSplitOptions.RemoveEmptyEntries).ToList();

        if (parts.Count == 0)
        {
            builder.Path = "/" + safeSegment;
            return builder.Uri;
        }

        if (TryReplacePlaceholderSegments(parts, safeSegment, out var placeholderPath))
        {
            builder.Path = placeholderPath;
            return builder.Uri;
        }

        if (ShouldReplaceTerminalPathSegment(parts))
        {
            parts[^1] = safeSegment;
            builder.Path = "/" + string.Join('/', parts);
            return builder.Uri;
        }

        builder.Path = $"{trimmedPath}/{safeSegment}";
        return builder.Uri;
    }

    public static bool IsRoutePlaceholderSegment(string segment)
    {
        if (string.IsNullOrWhiteSpace(segment))
        {
            return false;
        }

        var decoded = Uri.UnescapeDataString(segment);
        return decoded.Length >= 3 &&
               decoded[0] == '{' &&
               decoded[^1] == '}' &&
               decoded[1..^1].All(c => char.IsLetterOrDigit(c) || c is '_' or '-' or '.');
    }

    public static Dictionary<string, string> ParseQuery(string query)
    {
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(query))
        {
            return values;
        }

        var trimmed = query.TrimStart('?');
        foreach (var pair in trimmed.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var parts = pair.Split('=', 2);
            var key = Uri.UnescapeDataString(parts[0]);
            var parsedValue = parts.Length > 1 ? Uri.UnescapeDataString(parts[1]) : string.Empty;
            values[key] = parsedValue;
        }

        return values;
    }

    public static string BuildQuery(Dictionary<string, string> values)
    {
        if (values.Count == 0)
        {
            return string.Empty;
        }

        var sb = new StringBuilder();
        foreach (var kvp in values)
        {
            if (sb.Length > 0)
            {
                sb.Append('&');
            }

            sb.Append(Uri.EscapeDataString(kvp.Key));
            sb.Append('=');
            sb.Append(Uri.EscapeDataString(kvp.Value));
        }

        return sb.ToString();
    }

    private static bool TryReplacePlaceholderSegments(IReadOnlyList<string> parts, string safeSegment, out string path)
    {
        path = string.Empty;
        var replaced = false;
        var updated = new List<string>(parts.Count);

        foreach (var part in parts)
        {
            if (IsRoutePlaceholderSegment(part))
            {
                updated.Add(safeSegment);
                replaced = true;
            }
            else
            {
                updated.Add(part);
            }
        }

        if (!replaced)
        {
            return false;
        }

        path = "/" + string.Join('/', updated);
        return true;
    }

    private static bool ShouldReplaceTerminalPathSegment(IReadOnlyList<string> parts)
    {
        if (parts.Count < 2)
        {
            return false;
        }

        var last = parts[^1];
        if (string.IsNullOrWhiteSpace(last))
        {
            return false;
        }

        return int.TryParse(last, NumberStyles.Integer, CultureInfo.InvariantCulture, out _) ||
               Guid.TryParse(last, out _) ||
               Regex.IsMatch(last, "^[0-9a-f]{8,}$", RegexOptions.IgnoreCase) ||
               Regex.IsMatch(last, "^[A-Za-z0-9_-]{6,}$", RegexOptions.CultureInvariant);
    }
}
