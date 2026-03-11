namespace ApiTester.Core;

public sealed record TargetResolutionResult(
    bool Success,
    Uri? TargetUri,
    string? ErrorMessage,
    Uri? InferredTargetUri);

public static class TargetResolutionWorkflowUtilities
{
    public static TargetResolutionResult ResolveTargetUri(
        string? uiRawTarget,
        string? envTargetUrl,
        string? envUrl,
        Func<(bool Success, Uri? Uri)> tryInferTargetUri,
        bool enforceScopeAuthorization,
        Func<(bool Confirmed, string Source)> getScopeAuthorizationState)
    {
        var raw = uiRawTarget?.Trim();
        if (string.IsNullOrWhiteSpace(raw))
        {
            raw = envTargetUrl?.Trim();
        }

        if (string.IsNullOrWhiteSpace(raw))
        {
            raw = envUrl?.Trim();
        }

        Uri uri;
        Uri? inferred = null;
        if (string.IsNullOrWhiteSpace(raw))
        {
            var infer = tryInferTargetUri();
            if (!infer.Success || infer.Uri is null)
            {
                return new TargetResolutionResult(
                    false,
                    null,
                    "Enter a URL first, or provide an HTTP(S) OpenAPI URL. Local OpenAPI files still require a target URL.",
                    null);
            }

            uri = infer.Uri;
            inferred = infer.Uri;
        }
        else if (!ScanOptionUtilities.TryParseHttpUri(raw, out var parsedUri))
        {
            return new TargetResolutionResult(false, null, "Enter a valid http/https URL.", null);
        }
        else
        {
            uri = parsedUri;
        }

        if (enforceScopeAuthorization)
        {
            var (confirmed, source) = getScopeAuthorizationState();
            if (!confirmed)
            {
                return new TargetResolutionResult(
                    false,
                    null,
                    $"Scope authorization is required before testing. Set API_TESTER_SCOPE_AUTHORIZED=true (source checked: {source}).",
                    null);
            }
        }

        return new TargetResolutionResult(true, uri, null, inferred);
    }
}
