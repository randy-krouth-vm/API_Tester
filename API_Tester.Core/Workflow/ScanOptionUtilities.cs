using ApiTester.Shared;

namespace ApiTester.Core;

public enum RunScopeMode
{
    SingleTarget,
    SpiderRoutes,
    OpenApiRoutes
}

public static class ScanOptionUtilities
{
    public static RunScopeMode GetRunScopeMode(string? envScope, int selectedIndex, string? selectedScopeText)
    {
        var normalizedEnv = envScope?.Trim();
        if (!string.IsNullOrWhiteSpace(normalizedEnv))
        {
            if (normalizedEnv.Equals("openapi", StringComparison.OrdinalIgnoreCase) ||
                normalizedEnv.Equals("openapi-routes", StringComparison.OrdinalIgnoreCase))
            {
                return RunScopeMode.OpenApiRoutes;
            }

            if (normalizedEnv.Equals("spider", StringComparison.OrdinalIgnoreCase) ||
                normalizedEnv.Equals("spider-routes", StringComparison.OrdinalIgnoreCase))
            {
                return RunScopeMode.SpiderRoutes;
            }

            if (normalizedEnv.Equals("single", StringComparison.OrdinalIgnoreCase) ||
                normalizedEnv.Equals("single-target", StringComparison.OrdinalIgnoreCase))
            {
                return RunScopeMode.SingleTarget;
            }
        }

        if (selectedIndex == 2)
        {
            return RunScopeMode.SpiderRoutes;
        }

        if (selectedIndex == 3)
        {
            return RunScopeMode.OpenApiRoutes;
        }

        if (selectedIndex == 1)
        {
            return RunScopeMode.SingleTarget;
        }

        if (!string.IsNullOrWhiteSpace(selectedScopeText))
        {
            if (selectedScopeText.Contains("OpenAPI Routes", StringComparison.OrdinalIgnoreCase))
            {
                return RunScopeMode.OpenApiRoutes;
            }

            if (selectedScopeText.Contains("Spider Routes", StringComparison.OrdinalIgnoreCase))
            {
                return RunScopeMode.SpiderRoutes;
            }
        }

        return RunScopeMode.SingleTarget;
    }

    public static bool IsTypeAwareModeEnabled(string? envTypeHandling, string? envTypeAware, string? pickerMode)
    {
        var normalizedHandling = envTypeHandling?.Trim();
        if (!string.IsNullOrWhiteSpace(normalizedHandling))
        {
            return normalizedHandling.Equals("automatic", StringComparison.OrdinalIgnoreCase) ||
                   normalizedHandling.Equals("auto", StringComparison.OrdinalIgnoreCase) ||
                   normalizedHandling.Equals("type-aware", StringComparison.OrdinalIgnoreCase);
        }

        var normalizedTypeAware = envTypeAware?.Trim();
        if (!string.IsNullOrWhiteSpace(normalizedTypeAware))
        {
            return !normalizedTypeAware.Equals("0", StringComparison.OrdinalIgnoreCase) &&
                   !normalizedTypeAware.Equals("false", StringComparison.OrdinalIgnoreCase) &&
                   !normalizedTypeAware.Equals("no", StringComparison.OrdinalIgnoreCase);
        }

        if (string.IsNullOrWhiteSpace(pickerMode))
        {
            return true;
        }

        return pickerMode.Contains("Automatic", StringComparison.OrdinalIgnoreCase);
    }

    public static string GetScopeLabel(RunScopeMode scopeMode)
    {
        return scopeMode switch
        {
            RunScopeMode.OpenApiRoutes => "OpenAPI Routes",
            RunScopeMode.SpiderRoutes => "Spider Routes",
            _ => "Single Target"
        };
    }

    public static int GetEffectiveRequestDelayMs(string? uiDelayText, string? defaultDelayEnv, bool isHeadless, string? headlessDelayEnv)
    {
        var uiDelay = ParseDelayMs(uiDelayText);
        var defaultDelay = uiDelay > 0 ? uiDelay : ParseDelayMs(defaultDelayEnv);

        if (isHeadless)
        {
            var headlessDelay = ParseDelayMs(headlessDelayEnv);
            if (headlessDelay > 0)
            {
                return headlessDelay;
            }
        }

        return defaultDelay;
    }

    public static int ParseDelayMs(string? raw)
    {
        if (!int.TryParse(raw?.Trim(), out var parsed) || parsed < 0)
        {
            return 0;
        }

        return Math.Min(parsed, 60_000);
    }

    public static bool TryInferTargetUriFromOpenApiInput(string? openApiRaw, out Uri uri)
    {
        uri = null!;
        var raw = openApiRaw?.Trim();
        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        if (!TryParseHttpUri(raw, out var openApiUri))
        {
            return false;
        }

        uri = InferBaseTargetFromOpenApiUri(openApiUri);
        return true;
    }

    public static Uri InferBaseTargetFromOpenApiUri(Uri openApiUri)
    {
        var basePath = openApiUri.AbsolutePath;
        var normalizedPath = basePath.TrimEnd('/');
        var knownSpecSuffixes = new[]
        {
            "/openapi.json",
            "/swagger.json",
            "/swagger/index.html",
            "/swagger/v1/swagger.json",
            "/v1/openapi.json",
            "/openapi"
        };

        foreach (var suffix in knownSpecSuffixes)
        {
            if (normalizedPath.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
            {
                normalizedPath = normalizedPath[..^suffix.Length];
                break;
            }
        }

        if (normalizedPath.Length == 0 || normalizedPath.Contains('.', StringComparison.Ordinal))
        {
            normalizedPath = "/";
        }

        if (!normalizedPath.StartsWith("/", StringComparison.Ordinal))
        {
            normalizedPath = "/" + normalizedPath;
        }

        var builder = new UriBuilder(openApiUri)
        {
            Path = normalizedPath,
            Query = string.Empty,
            Fragment = string.Empty
        };
        return builder.Uri;
    }

    public static bool IsScopeAuthorizationEnforced(string? envValue)
    {
        return string.Equals(envValue?.Trim(), "1", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(envValue?.Trim(), "true", StringComparison.OrdinalIgnoreCase) ||
               string.Equals(envValue?.Trim(), "yes", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsManualPayloadModeEnabled(bool manualPayloadToggle, bool envManualPayloadMode)
    {
        return manualPayloadToggle || envManualPayloadMode;
    }

    public static PayloadLocation ResolvePayloadLocation(string? selectedPayloadLocation)
    {
        var selected = selectedPayloadLocation?.Trim();
        return selected?.ToUpperInvariant() switch
        {
            "PATH" => PayloadLocation.Path,
            "BODY" => PayloadLocation.Body,
            "HEADER" => PayloadLocation.Header,
            "COOKIE" => PayloadLocation.Cookie,
            _ => PayloadLocation.Query
        };
    }

    public static HttpMethod? ResolveOperationOverride(string? selectedOperation)
    {
        var selected = selectedOperation?.Trim();
        if (string.IsNullOrWhiteSpace(selected) ||
            selected.Contains("Automatic", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        return selected.ToUpperInvariant() switch
        {
            "GET" => HttpMethod.Get,
            "POST" => HttpMethod.Post,
            "PUT" => HttpMethod.Put,
            "PATCH" => HttpMethod.Patch,
            "DELETE" => HttpMethod.Delete,
            "HEAD" => HttpMethod.Head,
            "OPTIONS" => HttpMethod.Options,
            _ => null
        };
    }

    public static bool ShouldApplyManualSingleTargetPayloadOverrides(
        bool typeAwareModeEnabled,
        string? openApiInputRaw,
        bool openApiRouteScopeSelected)
    {
        if (!typeAwareModeEnabled)
        {
            return true;
        }

        return string.IsNullOrWhiteSpace(openApiInputRaw) && !openApiRouteScopeSelected;
    }

    public static bool TryResolveConfiguredTargetUriForOverrides(
        string? uiTargetUrl,
        string? envTargetUrl,
        string? envFallbackUrl,
        out Uri uri)
    {
        uri = null!;
        var raw = uiTargetUrl?.Trim();
        if (string.IsNullOrWhiteSpace(raw))
        {
            raw = envTargetUrl?.Trim();
        }

        if (string.IsNullOrWhiteSpace(raw))
        {
            raw = envFallbackUrl?.Trim();
        }

        if (string.IsNullOrWhiteSpace(raw))
        {
            return false;
        }

        return TryParseHttpUri(raw, out uri);
    }

    public static bool TryParseHttpUri(string? raw, out Uri uri)
    {
        uri = null!;
        if (!Uri.TryCreate(raw?.Trim(), UriKind.Absolute, out var parsedUri) || parsedUri is null)
        {
            return false;
        }

        if (parsedUri.Scheme != Uri.UriSchemeHttp && parsedUri.Scheme != Uri.UriSchemeHttps)
        {
            return false;
        }

        uri = parsedUri;
        return true;
    }
}
