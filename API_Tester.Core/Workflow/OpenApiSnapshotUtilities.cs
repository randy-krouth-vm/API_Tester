using System.Text.Json;

namespace ApiTester.Core;

public sealed record OpenApiSnapshot(Uri SourceUri, JsonDocument Document);

public static class OpenApiSnapshotUtilities
{
    public static Uri? ResolveOpenApiOverrideUri(Uri baseUri, string? rawInput)
    {
        var raw = rawInput?.Trim();
        if (string.IsNullOrWhiteSpace(raw))
        {
            return null;
        }

        if (Uri.TryCreate(raw, UriKind.Absolute, out var absolute) && absolute is not null)
        {
            return absolute;
        }

        if (Uri.TryCreate(baseUri, raw, out var relative) && relative is not null)
        {
            return relative;
        }

        return null;
    }

    public static IEnumerable<Uri> ExpandOpenApiCandidateUris(Uri candidate)
    {
        yield return candidate;

        var raw = candidate.AbsolutePath.TrimEnd('/');
        if (raw.EndsWith("/swagger", StringComparison.OrdinalIgnoreCase) ||
            raw.EndsWith("/swagger/index.html", StringComparison.OrdinalIgnoreCase))
        {
            yield return new Uri(candidate, "/swagger/v1/swagger.json");
            yield return new Uri(candidate, "/swagger.json");
        }

        if (raw.EndsWith("/openapi", StringComparison.OrdinalIgnoreCase))
        {
            yield return new Uri(candidate, "/openapi.json");
        }
    }

    public static async Task<OpenApiSnapshot?> TryFetchOpenApiSnapshotAsync(
        Uri baseUri,
        string? rawInput,
        Func<Func<HttpRequestMessage>, Task<HttpResponseMessage?>> safeSendAsync)
    {
        var candidates = new List<Uri>();
        var overrideUri = ResolveOpenApiOverrideUri(baseUri, rawInput);
        if (overrideUri is not null)
        {
            candidates.AddRange(ExpandOpenApiCandidateUris(overrideUri));
        }

        candidates.AddRange(
        [
            new Uri(baseUri, "/openapi.json"),
            new Uri(baseUri, "/swagger/v1/swagger.json"),
            new Uri(baseUri, "/swagger.json"),
            new Uri(baseUri, "/v1/openapi.json")
        ]);

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var candidate in candidates)
        {
            if (!seen.Add(candidate.ToString()))
            {
                continue;
            }

            var response = await safeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, candidate));
            if (response is null || !response.IsSuccessStatusCode)
            {
                continue;
            }

            var body = await HttpEvidenceUtilities.ReadBodyAsync(response);
            if (string.IsNullOrWhiteSpace(body))
            {
                continue;
            }

            try
            {
                var doc = JsonDocument.Parse(body);
                if (doc.RootElement.ValueKind == JsonValueKind.Object &&
                    (doc.RootElement.TryGetProperty("openapi", out _) || doc.RootElement.TryGetProperty("swagger", out _)))
                {
                    return new OpenApiSnapshot(candidate, doc);
                }

                doc.Dispose();
            }
            catch
            {
                // Not valid OpenAPI JSON.
            }
        }

        return null;
    }
}
