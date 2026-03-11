namespace ApiTester.Core;

public static class LegacyTestHarnessUtilities
{
    public static string GetScanDepthProfile()
    {
        return "deep";
    }

    public static T[] LimitByScanDepth<T>(T[] items, string profile, int fastCount, int balancedCount)
    {
        if (profile == "deep")
        {
            return items;
        }

        var count = profile == "fast" ? fastCount : balancedCount;
        if (count <= 0 || count >= items.Length)
        {
            return items;
        }

        return items.Take(count).ToArray();
    }

    public static string[] GetManualPayloadsOrDefault(
        IEnumerable<string> defaults,
        bool manualPayloadModeEnabled,
        string? uiRawPayloads,
        string? envRawPayloads,
        string? schemePreference = null)
    {
        var fallback = defaults
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim())
            .ToArray();
        fallback = ManualPayloadUtilities.ApplySchemePreference(fallback, schemePreference);
        if (!manualPayloadModeEnabled)
        {
            return fallback;
        }

        var raw = string.IsNullOrWhiteSpace(uiRawPayloads) ? envRawPayloads : uiRawPayloads;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return fallback;
        }

        var parsed = raw
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .ToArray();
        parsed = ManualPayloadUtilities.ApplySchemePreference(parsed, schemePreference);

        if (parsed.Length == 0)
        {
            return fallback;
        }

        var combined = fallback
            .Concat(parsed)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return combined.Length > 0 ? combined : fallback;
    }

    public static string ResolveOpenApiInputRaw(string? uiRaw, string? envRaw)
    {
        var trimmedUi = uiRaw?.Trim();
        if (!string.IsNullOrWhiteSpace(trimmedUi))
        {
            return trimmedUi;
        }

        return envRaw?.Trim() ?? string.Empty;
    }
}
