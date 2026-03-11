namespace API_Tester;

public partial class MainPage
{
    /*
    Cross-Tenant Data Leakage Test

    Purpose:
    Detects whether the application properly isolates data between tenants
    in a multi-tenant environment.

    Threat Model:
    Multi-tenant systems host data for multiple customers (tenants) within
    the same application instance. If tenant isolation controls are weak,
    attackers may manipulate identifiers or request parameters to access
    data belonging to other tenants.

    Test Strategy:
    The scanner attempts to access resources using altered tenant identifiers,
    such as:

        tenantId
        accountId
        organizationId
        customerId

    It observes whether the API returns data that appears to belong to a
    different tenant or organization.

    Potential Impact:
    If tenant boundaries are not enforced, attackers may gain access to:

        - other customers' records
        - financial data
        - private user information
        - internal configuration data

    This can result in significant data breaches affecting multiple
    organizations.

    Expected Behavior:
    The application should enforce strict authorization checks and ensure
    that all tenant identifiers are validated against the authenticated
    user's permissions before returning any data.
    */
    
    private async Task<string> RunCrossTenantDataLeakageTestsAsync(Uri baseUri)
    {
        var openApi = await GetOpenApiProbeContextAsync(baseUri);
        var scanDepth = GetScanDepthProfile();
        var endpoints = openApi.TargetEndpoints
        .Where(u => Regex.IsMatch(u.AbsolutePath, @"/\d+$") || u.AbsolutePath.Contains("/api/", StringComparison.OrdinalIgnoreCase))
        .Take(scanDepth == "fast" ? 2 : scanDepth == "balanced" ? 4 : 8)
        .ToList();
        if (endpoints.Count == 0)
        {
            endpoints.Add(baseUri);
        }

        var findings = new List<string>();
        var suspicious = 0;
        var attempts = 0;

        foreach (var endpoint in endpoints)
        {
            var a = AppendQuery(endpoint, new Dictionary<string, string> { ["id"] = "1", ["tenantId"] = "tenant-a" });
            var b = AppendQuery(endpoint, new Dictionary<string, string> { ["id"] = "2", ["tenantId"] = "tenant-b" });
            var ra = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, a));
            var rb = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, b));
            var ba = await ReadBodyAsync(ra);
            var bb = await ReadBodyAsync(rb);
            attempts += 2;

            if (ra is not null && rb is not null &&
            (int)ra.StatusCode is >= 200 and < 300 &&
            (int)rb.StatusCode is >= 200 and < 300 &&
            !string.Equals(ba, bb, StringComparison.Ordinal))
            {
                suspicious++;
            }
        }
        findings.Add(suspicious > 0
        ? $"Potential risk: cross-tenant differential data exposure signals observed on {suspicious} endpoint pairs."
        : "No obvious cross-tenant leakage differential observed.");
        return FormatSection("Cross-Tenant Data Leakage", baseUri, findings);
    }

}

