using System.Net.Http;

namespace ApiTester.Core;

public static class HttpEvidenceUtilities
{
    public static async Task<string> ReadRequestBodyAsync(HttpRequestMessage request)
    {
        if (request.Content is null)
        {
            return string.Empty;
        }

        try
        {
            return await request.Content.ReadAsStringAsync();
        }
        catch
        {
            return string.Empty;
        }
    }

    public static string FormatRequestHeaders(HttpRequestMessage request)
    {
        var pairs = new List<string>();
        foreach (var header in request.Headers)
        {
            pairs.Add($"{header.Key}: {SanitizeHeaderValue(header.Key, string.Join(",", header.Value))}");
        }

        if (request.Content is not null)
        {
            foreach (var header in request.Content.Headers)
            {
                pairs.Add($"{header.Key}: {SanitizeHeaderValue(header.Key, string.Join(",", header.Value))}");
            }
        }

        return string.Join(" | ", pairs);
    }

    public static string FormatResponseHeaders(HttpResponseMessage response)
    {
        var pairs = new List<string>();
        foreach (var header in response.Headers)
        {
            pairs.Add($"{header.Key}: {SanitizeHeaderValue(header.Key, string.Join(",", header.Value))}");
        }

        foreach (var header in response.Content.Headers)
        {
            pairs.Add($"{header.Key}: {SanitizeHeaderValue(header.Key, string.Join(",", header.Value))}");
        }

        return string.Join(" | ", pairs);
    }

    public static string SanitizeHeaderValue(string headerName, string value)
    {
        return headerName.ToLowerInvariant() switch
        {
            "authorization" or "cookie" or "set-cookie" or "x-api-key" => "[redacted]",
            _ => TrimForEvidence(value, 400)
        };
    }

    public static string TrimForEvidence(string value, int maxLen)
    {
        if (string.IsNullOrEmpty(value) || value.Length <= maxLen)
        {
            return value ?? string.Empty;
        }

        return value[..maxLen] + "...(truncated)";
    }

    public static async Task<string> ReadBodyAsync(HttpResponseMessage? response)
    {
        if (response is null)
        {
            return string.Empty;
        }

        try
        {
            return await response.Content.ReadAsStringAsync();
        }
        catch
        {
            return string.Empty;
        }
    }
}
