namespace API_Tester;

public partial class MainPage
{
    /*
    Subdomain Takeover Signal Test

    Purpose:
    Checks for indicators that a subdomain associated with the target
    application may be vulnerable to subdomain takeover.

    Threat Model:
    Subdomain takeover occurs when a DNS record (usually CNAME or A record)
    points to an external service that is no longer configured or claimed.
    If the external service is abandoned but the DNS record remains active,
    an attacker may be able to register the resource and take control of
    the subdomain.

    Example scenario:

        DNS record:
        api.example.com → CNAME → example-app.azurewebsites.net

    If the Azure application is deleted but the DNS record remains,
    an attacker could create a new Azure service with the same name
    and gain control of api.example.com.

    Attack scenarios include:

        - hosting malicious content on a trusted domain
        - phishing attacks using legitimate company subdomains
        - cookie theft through shared domain scope
        - bypassing security filters that trust the domain

    Common services historically involved in takeover cases include
    cloud hosting platforms, object storage endpoints, and SaaS
    services that rely on custom domain mappings.

    Test Strategy:
    The scanner probes the target domain and related endpoints for
    signals such as:

        - DNS records pointing to unclaimed cloud services
        - HTTP responses indicating missing or unconfigured hosts
        - Error messages from hosting providers suggesting that
        a resource does not exist

    These signals may indicate a potential subdomain takeover risk.

    Potential Impact:
    If a subdomain takeover is possible, attackers may be able to:

        - control a trusted subdomain of the organization
        - distribute malware or phishing pages
        - intercept cookies scoped to the parent domain
        - damage brand reputation or user trust

    Expected Behavior:
    DNS records should be removed when services are decommissioned.
    Organizations should regularly audit DNS configurations and
    ensure that external service mappings remain valid and claimed.
    */

    private async Task<string> RunSubdomainTakeoverSignalTestsAsync(Uri baseUri)
    {
        var labels = baseUri.Host.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length < 2)
        {
            return FormatSection("Subdomain Takeover Signals", baseUri, new[] { "Host does not appear to be a DNS domain; skipped." });
        }

        var apex = $"{labels[^2]}.{labels[^1]}";
        var candidates = new[] { "dev", "staging", "old", "test", "uat" }
        .Select(prefix => $"{prefix}.{apex}")
        .ToArray();

        var takeoverMarkers = new[]
        {
            "NoSuchBucket",
            "There isn't a GitHub Pages site here",
            "The specified bucket does not exist",
            "No such app",
            "Unknown domain",
            "Domain not found"
        };

        var findings = new List<string>();
        foreach (var candidate in candidates)
        {
            HttpResponseMessage? response = null;
            try
            {
                var uri = new Uri($"https://{candidate}/");
                response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, uri));
            }
            catch
            {
                // Ignore malformed candidate failures.
            }

            var body = await ReadBodyAsync(response);
            var marker = takeoverMarkers.Any(m => body.Contains(m, StringComparison.OrdinalIgnoreCase));
            findings.Add($"{candidate}: {FormatStatus(response)}{(marker ? " (takeover marker)" : string.Empty)}");
        }

        findings.Add("Takeover markers with active DNS should be investigated.");
        return FormatSection("Subdomain Takeover Signals", baseUri, findings);
    }

}

