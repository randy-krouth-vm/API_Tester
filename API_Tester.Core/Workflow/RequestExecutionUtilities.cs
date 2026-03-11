using System.Text;

namespace ApiTester.Core;

public static class RequestExecutionUtilities
{
    public static void EnsureBodyForWriteMethod(HttpRequestMessage request)
    {
        if (request.Content is not null)
        {
            return;
        }

        if (request.Method != HttpMethod.Post &&
            request.Method != HttpMethod.Put &&
            request.Method != HttpMethod.Patch)
        {
            return;
        }

        request.Content = new StringContent("{}", Encoding.UTF8, "application/json");
    }

    public static bool IsStrictSingleScopeViolation(
        bool strictSingleTargetMode,
        Uri? strictSingleBaseUri,
        Uri? requestUri,
        Func<Uri, Uri, bool> pathsMatchForScope,
        out string message)
    {
        message = string.Empty;
        if (!strictSingleTargetMode)
        {
            return false;
        }

        if (strictSingleBaseUri is null || requestUri is null)
        {
            return false;
        }

        var sameOrigin = requestUri.Scheme.Equals(strictSingleBaseUri.Scheme, StringComparison.OrdinalIgnoreCase) &&
                         requestUri.Host.Equals(strictSingleBaseUri.Host, StringComparison.OrdinalIgnoreCase) &&
                         requestUri.Port == strictSingleBaseUri.Port;
        var samePath = pathsMatchForScope(requestUri, strictSingleBaseUri);
        if (sameOrigin && samePath)
        {
            return false;
        }

        message = $"Blocked by single-target scope guard. Requested URI '{requestUri}' differs from base '{strictSingleBaseUri}'.";
        return true;
    }

    public static void ApplyAuthProfileToRequest(HttpRequestMessage request, AuthProfile? profile)
    {
        if (profile is null)
        {
            return;
        }

        if (!string.IsNullOrWhiteSpace(profile.BearerToken) && !request.Headers.Contains("Authorization"))
        {
            request.Headers.TryAddWithoutValidation("Authorization", $"Bearer {profile.BearerToken}");
        }

        if (!string.IsNullOrWhiteSpace(profile.ApiKey) && !request.Headers.Contains(profile.ApiKeyHeader))
        {
            request.Headers.TryAddWithoutValidation(profile.ApiKeyHeader, profile.ApiKey);
        }

        if (!string.IsNullOrWhiteSpace(profile.Cookie) && !request.Headers.Contains("Cookie"))
        {
            request.Headers.TryAddWithoutValidation("Cookie", profile.Cookie);
        }

        foreach (var (header, value) in profile.ExtraHeaders)
        {
            if (!request.Headers.Contains(header))
            {
                request.Headers.TryAddWithoutValidation(header, value);
            }
        }
    }
}
