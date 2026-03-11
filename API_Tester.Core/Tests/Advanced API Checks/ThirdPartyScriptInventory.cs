namespace API_Tester;

public partial class MainPage
{
    /*
    Third-Party Script Inventory Test

    Purpose:
    Identifies third-party JavaScript resources loaded by the application
    that originate from external domains.

    Threat Model:
    Modern web applications frequently include scripts from external
    services such as analytics platforms, CDNs, advertising networks,
    payment providers, or UI libraries. These scripts execute in the
    browser with the same privileges as the application itself.

    If a third-party script is compromised, modified, or delivered from
    a malicious source, it may execute arbitrary code within the user's
    browser under the trusted origin of the application.

    Attack scenarios include:

        - supply chain compromise of third-party script providers
        - malicious updates pushed through external CDNs
        - injected tracking or credential harvesting scripts
        - data exfiltration through compromised analytics libraries

    Example risk:

        <script src="https://cdn.thirdparty.com/library.js"></script>

    If the third-party host is compromised, the script delivered to users
    may include malicious code.

    Test Strategy:
    The scanner retrieves application responses and inspects HTML content
    for <script> tags referencing external domains. It catalogs these
    resources to help identify dependencies that may expand the attack
    surface.

    Potential Impact:
    If third-party scripts are compromised, attackers may be able to:

        - steal user credentials or session tokens
        - intercept form submissions
        - perform malicious actions within the application context
        - inject unauthorized tracking or malware

    Expected Behavior:
    Applications should minimize reliance on external scripts where
    possible and ensure that trusted third-party resources are carefully
    managed. Security mechanisms such as Subresource Integrity (SRI),
    Content Security Policy (CSP), and dependency monitoring should be
    used to reduce supply chain risks.
    */
    
    private async Task<string> RunThirdPartyScriptInventoryTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, baseUri));
        var body = await ReadBodyAsync(response);

        var scriptRegex = new Regex("<script[^>]+src\\s*=\\s*[\"'](?<u>[^\"']+)[\"']", RegexOptions.IgnoreCase);
        var externalDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var totalScripts = 0;

        foreach (Match match in scriptRegex.Matches(body))
        {
            var raw = match.Groups["u"].Value;
            if (string.IsNullOrWhiteSpace(raw))
            {
                continue;
            }

            totalScripts++;
            if (!Uri.TryCreate(baseUri, raw, out var resolved) || resolved is null)
            {
                continue;
            }

            if (!string.Equals(resolved.Host, baseUri.Host, StringComparison.OrdinalIgnoreCase))
            {
                externalDomains.Add(resolved.Host);
            }
        }

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            $"Script tags with src: {totalScripts}",
            $"External script domains: {externalDomains.Count}"
        };

        foreach (var domain in externalDomains.Take(12))
        {
            findings.Add($"External: {domain}");
        }

        if (externalDomains.Count > 0)
        {
            findings.Add("Review SRI/CSP and vendor trust for third-party script supply-chain risk.");
        }

        return FormatSection("Third-Party Script Inventory", baseUri, findings);
    }

}

