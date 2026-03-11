using System.Text.RegularExpressions;

namespace ApiTester.Core;

// Manual payload routing rules:
// - Lines starting with "xss://", "ssrf://", "redirect://", "cmd://", "sql://", "nosql://", "path://", or "generic://" are forced into that category.
// - Unprefixed lines are auto-classified for XSS/SQL/NoSQL/CMD/Path markers; SSRF/redirect requires an explicit prefix.
// - SSRF normalization turns bare hosts into "http://host" (then http->https expansion happens later).
// - Unprefixed http/https URLs are treated as direct request targets (not injected into payload lists).
public enum ManualPayloadCategory
{
    Generic,
    Xss,
    Ssrf,
    Redirect,
    Cmd,
    Sql,
    NoSql,
    Path
}

public static class ManualPayloadUtilities
{
    public static string[] ParseManualPayloads(bool enabled, string? uiRaw, string? envRaw)
    {
        if (!enabled)
        {
            return Array.Empty<string>();
        }

        var raw = string.IsNullOrWhiteSpace(uiRaw) ? envRaw : uiRaw;
        if (string.IsNullOrWhiteSpace(raw))
        {
            return Array.Empty<string>();
        }

        return raw
            .Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Where(x => !IsOverrideDirective(x))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    public static string[] ExtractDirectRequestUrls(IEnumerable<string> payloads, string? schemePreference = null)
    {
        return ApplySchemePreference(payloads, schemePreference)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(SanitizePrefixedPayload)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Where(x => !HasKnownPrefix(x))
            .Where(x => x.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
                        x.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static string[] MergePayloads(IEnumerable<string> defaults, IEnumerable<string> manual, string? schemePreference = null)
    {
        var baseSet = ApplySchemePreference(defaults, schemePreference)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        var manualSet = ApplySchemePreference(manual, schemePreference)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();

        if (manualSet.Length == 0)
        {
            return baseSet;
        }

        return baseSet
            .Concat(manualSet)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static string[] ExpandSecureSchemeVariants(IEnumerable<string> payloads)
        => ApplySchemePreference(payloads, "Both");

    public static string[] ApplySchemePreference(IEnumerable<string> payloads, string? schemePreference)
    {
        var mode = NormalizeSchemePreference(schemePreference);
        return payloads
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .SelectMany(payload => ApplySchemePreference(payload, mode))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static IEnumerable<string> ApplySchemePreference(string payload, string mode)
    {
        var trimmed = payload.Trim();
        if (trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var variant in SelectVariants(trimmed, "http://", "https://", mode))
            {
                yield return variant;
            }
            yield break;
        }

        if (trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var variant in SelectVariants(trimmed, "http://", "https://", mode))
            {
                yield return variant;
            }
            yield break;
        }

        if (trimmed.StartsWith("ws://", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var variant in SelectVariants(trimmed, "ws://", "wss://", mode))
            {
                yield return variant;
            }
            yield break;
        }

        if (trimmed.StartsWith("wss://", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var variant in SelectVariants(trimmed, "ws://", "wss://", mode))
            {
                yield return variant;
            }
            yield break;
        }

        if (trimmed.StartsWith("ftp://", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var variant in SelectVariants(trimmed, "ftp://", "ftps://", mode))
            {
                yield return variant;
            }
            yield break;
        }

        if (trimmed.StartsWith("ftps://", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var variant in SelectVariants(trimmed, "ftp://", "ftps://", mode))
            {
                yield return variant;
            }
            yield break;
        }

        if (trimmed.StartsWith("ldap://", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var variant in SelectVariants(trimmed, "ldap://", "ldaps://", mode))
            {
                yield return variant;
            }
            yield break;
        }

        if (trimmed.StartsWith("ldaps://", StringComparison.OrdinalIgnoreCase))
        {
            foreach (var variant in SelectVariants(trimmed, "ldap://", "ldaps://", mode))
            {
                yield return variant;
            }
            yield break;
        }

        yield return trimmed;
    }

    private static IEnumerable<string> SelectVariants(string payload, string insecurePrefix, string securePrefix, string mode)
    {
        var suffix = payload[insecurePrefix.Length..];
        if (payload.StartsWith(securePrefix, StringComparison.OrdinalIgnoreCase))
        {
            suffix = payload[securePrefix.Length..];
        }

        switch (mode)
        {
            case "HTTP":
                yield return insecurePrefix + suffix;
                break;
            case "BOTH":
                yield return insecurePrefix + suffix;
                yield return securePrefix + suffix;
                break;
            default:
                yield return securePrefix + suffix;
                break;
        }
    }

    private static string NormalizeSchemePreference(string? schemePreference)
    {
        var value = schemePreference?.Trim();
        if (string.IsNullOrWhiteSpace(value))
        {
            return "HTTPS";
        }

        return value.ToUpperInvariant() switch
        {
            "HTTP" => "HTTP",
            "BOTH" => "BOTH",
            _ => "HTTPS"
        };
    }

    public static string[] FilterManualPayloads(IEnumerable<string> payloads, ManualPayloadCategory category)
    {
        return category switch
        {
            ManualPayloadCategory.Xss => FilterXssPayloads(payloads),
            ManualPayloadCategory.Ssrf => NormalizeSsrfTargets(FilterSsrfPayloads(payloads)),
            ManualPayloadCategory.Redirect => NormalizeSsrfTargets(FilterRedirectPayloads(payloads)),
            ManualPayloadCategory.Cmd => FilterPrefixedPayloads(payloads, ManualPayloadCategory.Cmd, IsLikelyCmdPayload),
            ManualPayloadCategory.Sql => FilterPrefixedPayloads(payloads, ManualPayloadCategory.Sql, IsLikelySqlPayload),
            ManualPayloadCategory.NoSql => FilterPrefixedPayloads(payloads, ManualPayloadCategory.NoSql, IsLikelyNoSqlPayload),
            ManualPayloadCategory.Path => FilterPrefixedPayloads(payloads, ManualPayloadCategory.Path, IsLikelyPathPayload),
            _ => payloads
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Select(SanitizePrefixedPayload)
                .Where(x => !string.IsNullOrWhiteSpace(x))
                .Where(x => !IsLikelyXssPayload(x))
                .Where(x => !HasKnownPrefix(x))
                .Where(x => !LooksLikeUrl(x))
                .Where(x => !LooksLikeHost(x))
                .ToArray()
        };
    }

    private static bool IsOverrideDirective(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return value.StartsWith("override:", StringComparison.OrdinalIgnoreCase) ||
               value.StartsWith("route:", StringComparison.OrdinalIgnoreCase);
    }

    private static string[] FilterXssPayloads(IEnumerable<string> payloads)
    {
        return payloads
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(SanitizePrefixedPayload)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Where((value) =>
            {
                if (TryStripCategoryPrefix(value, out var category, out _))
                {
                    return category == ManualPayloadCategory.Xss;
                }

                return IsLikelyXssPayload(value);
            })
            .Select(StripPrefixIfNeeded)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    private static string[] FilterSsrfPayloads(IEnumerable<string> payloads)
    {
        return payloads
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(SanitizePrefixedPayload)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Where((value) =>
            {
                if (TryStripCategoryPrefix(value, out var category, out _))
                {
                    return category == ManualPayloadCategory.Ssrf || category == ManualPayloadCategory.Redirect;
                }

                return false;
            })
            .Select(StripPrefixIfNeeded)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    private static string[] FilterRedirectPayloads(IEnumerable<string> payloads)
    {
        return payloads
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(SanitizePrefixedPayload)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Where((value) =>
            {
                if (TryStripCategoryPrefix(value, out var category, out _))
                {
                    return category == ManualPayloadCategory.Redirect;
                }

                return false;
            })
            .Select(StripPrefixIfNeeded)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    private static string[] FilterPrefixedPayloads(
        IEnumerable<string> payloads,
        ManualPayloadCategory category,
        Func<string, bool>? autoDetect = null)
    {
        return payloads
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(SanitizePrefixedPayload)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Where((value) =>
            {
                if (TryStripCategoryPrefix(value, out var mappedCategory, out _))
                {
                    return mappedCategory == category;
                }

                return autoDetect?.Invoke(value) == true;
            })
            .Select(StripPrefixIfNeeded)
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Distinct(StringComparer.Ordinal)
            .ToArray();
    }

    private static string[] NormalizeSsrfTargets(IEnumerable<string> payloads)
    {
        var normalized = new List<string>();
        foreach (var payload in payloads)
        {
            if (string.IsNullOrWhiteSpace(payload))
            {
                continue;
            }

            var trimmed = payload.Trim();
            if (LooksLikeUrl(trimmed))
            {
                normalized.Add(trimmed);
                continue;
            }

            if (LooksLikeHost(trimmed))
            {
                var host = trimmed.TrimStart('/');
                normalized.Add("http://" + host);
            }
        }

        return normalized
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    private static bool LooksLikeUrl(string value)
        => value.Contains("://", StringComparison.OrdinalIgnoreCase);

    private static bool IsLikelySsrfTarget(string value)
    {
        if (LooksLikeUrl(value))
        {
            return true;
        }

        if (LooksLikeHost(value))
        {
            return true;
        }

        return false;
    }

    private static string SanitizePrefixedPayload(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        return value.Trim();
    }

    private static string StripPrefixIfNeeded(string value)
    {
        if (TryStripCategoryPrefix(value, out _, out var payload))
        {
            return payload;
        }

        return value;
    }

    private static bool TryStripCategoryPrefix(string value, out ManualPayloadCategory? category, out string payload)
    {
        category = null;
        payload = value;

        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        var trimmed = value.Trim();
        if (trimmed.StartsWith("xss://", StringComparison.OrdinalIgnoreCase))
        {
            category = ManualPayloadCategory.Xss;
            payload = trimmed["xss://".Length..].Trim();
            return true;
        }

        if (trimmed.StartsWith("ssrf://", StringComparison.OrdinalIgnoreCase))
        {
            category = ManualPayloadCategory.Ssrf;
            payload = trimmed["ssrf://".Length..].Trim();
            return true;
        }

        if (trimmed.StartsWith("redirect://", StringComparison.OrdinalIgnoreCase))
        {
            category = ManualPayloadCategory.Redirect;
            payload = trimmed["redirect://".Length..].Trim();
            return true;
        }

        if (trimmed.StartsWith("generic://", StringComparison.OrdinalIgnoreCase))
        {
            category = ManualPayloadCategory.Generic;
            payload = trimmed["generic://".Length..].Trim();
            return true;
        }

        if (trimmed.StartsWith("cmd://", StringComparison.OrdinalIgnoreCase))
        {
            category = ManualPayloadCategory.Cmd;
            payload = trimmed["cmd://".Length..].Trim();
            return true;
        }

        if (trimmed.StartsWith("sql://", StringComparison.OrdinalIgnoreCase))
        {
            category = ManualPayloadCategory.Sql;
            payload = trimmed["sql://".Length..].Trim();
            return true;
        }

        if (trimmed.StartsWith("nosql://", StringComparison.OrdinalIgnoreCase))
        {
            category = ManualPayloadCategory.NoSql;
            payload = trimmed["nosql://".Length..].Trim();
            return true;
        }

        if (trimmed.StartsWith("path://", StringComparison.OrdinalIgnoreCase))
        {
            category = ManualPayloadCategory.Path;
            payload = trimmed["path://".Length..].Trim();
            return true;
        }

        return false;
    }

    private static bool HasKnownPrefix(string value)
        => TryStripCategoryPrefix(value, out _, out _);

    private static bool IsLikelyXssPayload(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        if (LooksLikeUrl(value))
        {
            return false;
        }

        var markers = new[]
        {
            "<script",
            "onerror",
            "onload",
            "<svg",
            "javascript:",
            "<img",
            "<iframe",
            "alert(",
            "prompt(",
            "confirm("
        };

        return markers.Any(marker => value.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsLikelySqlPayload(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || LooksLikeUrl(value))
        {
            return false;
        }

        var markers = new[]
        {
            "' or ",
            "\" or ",
            " union ",
            " select ",
            "--",
            "/*",
            "*/",
            "benchmark(",
            "sleep(",
            "information_schema",
            "xp_"
        };

        return markers.Any(marker => value.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsLikelyNoSqlPayload(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || LooksLikeUrl(value))
        {
            return false;
        }

        var markers = new[]
        {
            "\"$ne\"",
            "\"$gt\"",
            "\"$where\"",
            "\"$regex\"",
            "\"$or\"",
            "\"$and\""
        };

        return markers.Any(marker => value.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsLikelyPathPayload(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || LooksLikeUrl(value))
        {
            return false;
        }

        var markers = new[]
        {
            "../",
            "..\\",
            "%2f",
            "%5c",
            "/etc/passwd",
            "windows\\",
            "win.ini",
            "boot.ini"
        };

        return markers.Any(marker => value.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    private static bool IsLikelyCmdPayload(string value)
    {
        if (string.IsNullOrWhiteSpace(value) || LooksLikeUrl(value))
        {
            return false;
        }

        var markers = new[]
        {
            "&&",
            ";",
            "|",
            "$(",
            "`",
            "whoami",
            "id",
            "cat ",
            "ping "
        };

        return markers.Any(marker => value.Contains(marker, StringComparison.OrdinalIgnoreCase));
    }

    private static bool LooksLikeHost(string value)
    {
        var trimmed = value.Trim();
        if (string.IsNullOrWhiteSpace(trimmed))
        {
            return false;
        }

        if (trimmed.StartsWith("/", StringComparison.Ordinal))
        {
            return false;
        }

        if (trimmed.Contains("localhost", StringComparison.OrdinalIgnoreCase) ||
            trimmed.Contains("metadata", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (Regex.IsMatch(trimmed, @"^\[?[0-9a-fA-F:]+\]?$"))
        {
            return true;
        }

        if (Regex.IsMatch(trimmed, @"^\d{1,3}(\.\d{1,3}){3}(\:\d+)?(/.*)?$"))
        {
            return true;
        }

        if (Regex.IsMatch(trimmed, @"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}(\:\d+)?(/.*)?$"))
        {
            return true;
        }

        return false;
    }
}
