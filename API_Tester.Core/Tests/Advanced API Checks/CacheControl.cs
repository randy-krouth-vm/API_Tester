namespace API_Tester;

public partial class MainPage
{
    /*
    Cache-Control Header Security Test

    Purpose:
    Checks whether API responses include appropriate cache control headers
    to prevent sensitive data from being stored by browsers, proxies,
    or intermediary caching systems.

    Threat Model:
    If sensitive API responses are cached improperly, private information
    may be stored in shared caches or exposed to other users. Misconfigured
    cache headers can also enable cache poisoning or unintended data reuse.

    Test Strategy:
    The scanner inspects responses from API endpoints and evaluates the
    presence and configuration of caching headers such as:

        Cache-Control
        Expires
        Pragma

    It specifically looks for secure directives such as:

        Cache-Control: no-store
        Cache-Control: no-cache
        Cache-Control: private

    Potential Impact:
    Improper caching may result in exposure of sensitive information such as:
        user profiles
        authentication responses
        API tokens
        account data

    Shared caching environments (CDNs, proxies, or shared browsers) may
    serve cached responses to unintended users.

    Expected Behavior:
    Sensitive API responses should disable caching using directives such as:

        Cache-Control: no-store

    or otherwise ensure that responses are not stored in shared caches.
    */
    
    private async Task<string> RunCacheControlTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, baseUri));
        var cacheControl = response is null ? string.Empty : TryGetHeader(response, "Cache-Control");
        var pragma = response is null ? string.Empty : TryGetHeader(response, "Pragma");
        var expires = response is null ? string.Empty : TryGetHeader(response, "Expires");

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            string.IsNullOrWhiteSpace(cacheControl) ? "Missing: Cache-Control" : $"Cache-Control: {cacheControl}",
            string.IsNullOrWhiteSpace(pragma) ? "Missing: Pragma" : $"Pragma: {pragma}",
            string.IsNullOrWhiteSpace(expires) ? "Missing: Expires" : $"Expires: {expires}"
        };

        return FormatSection("Cache Control", baseUri, findings);
    }
}

