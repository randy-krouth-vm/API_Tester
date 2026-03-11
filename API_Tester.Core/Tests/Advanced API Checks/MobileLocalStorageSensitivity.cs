namespace API_Tester;

public partial class MainPage
{
    /*
    Mobile Local Storage Sensitivity Payloads

    Purpose:
    Defines payloads used to probe whether sensitive data may be exposed
    through mobile client storage mechanisms such as localStorage,
    sessionStorage, WebView storage, or other client-side persistence layers.

    Threat Model:
    Mobile applications (especially hybrid apps using WebViews) sometimes
    store authentication tokens, API keys, session identifiers, or user
    data in client-side storage. If sensitive data is written to these
    locations without proper protections, attackers with device access,
    debugging tools, or malicious apps may be able to extract the data.

    Examples of sensitive items that should never be stored in plain
    client storage include:

        - authentication tokens
        - refresh tokens
        - API keys
        - session identifiers
        - private user data

    Attack scenarios include:

        - device compromise or malware
        - reverse engineering mobile apps
        - WebView debugging or inspection
        - cross-site scripting in hybrid apps exposing stored values

    Test Strategy:
    These payload markers are submitted through input fields or API
    parameters that may later be written to client-side storage by the
    mobile application. Security testing tools can then inspect the device
    storage to determine whether these values were stored insecurely.

    Potential Impact:
    If sensitive information is stored in mobile client storage, attackers
    may be able to:

        - steal authentication tokens
        - hijack user sessions
        - impersonate users
        - access private user data

    Expected Behavior:
    Sensitive authentication data should be stored only in secure storage
    mechanisms provided by the mobile platform (such as the OS keychain
    or secure enclave) and should never be exposed in plaintext within
    WebView storage or browser-style localStorage.
    */
    
    private static string[] GetMobileLocalStorageSensitivityPayloads() =>
    [
        "/app-config.json",
        "/mobile/config",
        "/config",
        "/manifest.json",
        "/assets/manifest.json",
        "/mobile/configuration.json",
        "/settings/preferences.json",
        "/data/local_storage.json",
        "/local/settings.json",
        "/db/schema.json",
        "/local/configs.json",
        "/user/data.json",
        "/logs/app-logs.json",
        "/error/reports.json",
        "/temp/cache.json",
        "/local/cache/settings.json"
    ];

    private static HttpRequestMessage FormatMobileLocalStorageSensitivityRequest(Uri uri) =>
        new(HttpMethod.Get, uri);

    private async Task<string> RunMobileLocalStorageSensitivityTestsAsync(Uri baseUri)
    {
        var payloads = GetMobileLocalStorageSensitivityPayloads();

        var findings = new List<string>();
        foreach (var payload in payloads)
        {
            var uri = new Uri(baseUri, payload);
            var response = await SafeSendAsync(() => FormatMobileLocalStorageSensitivityRequest(uri));
            var body = await ReadBodyAsync(response);
            var secretSignal = ContainsAny(body, "apiKey", "clientSecret", "privateKey", "refreshToken", "authorization");
            findings.Add($"{uri.AbsolutePath}: {FormatStatus(response)}{(secretSignal ? " (sensitive config marker)" : string.Empty)}");
        }

        findings.Add("Review mobile config payloads for secrets that could be cached locally.");
        return FormatSection("Mobile Local Storage Sensitivity", baseUri, findings);
    }

}

