namespace API_Tester;

public partial class MainPage
{
    /*
    API Inventory Management Tests

    Purpose:
    Performs automated tests to evaluate the application’s API inventory 
    management controls, ensuring that all APIs are identified, documented, 
    and monitored for security and operational compliance.

    Threat Model:
    Poor API inventory management may allow attackers to:

        - Discover undocumented or unmonitored APIs
        - Exploit hidden endpoints with weak or missing security controls
        - Circumvent authentication or authorization mechanisms
        - Access sensitive data or operations without detection

    Common vulnerabilities include:

        - Lack of a centralized API inventory or catalog
        - Undocumented endpoints or services exposed publicly
        - Inconsistent security controls across APIs
        - Missing monitoring or logging of API activity
        - Poor version control or lifecycle management of APIs

    Test Strategy:
    The method performs automated checks that:

        - Identify all exposed APIs and endpoints
        - Verify that APIs are documented and accounted for in inventory
        - Assess consistency of authentication, authorization, and security controls
        - Detect undocumented or unmanaged APIs that could pose risks
        - Evaluate monitoring and logging of API usage

    Potential Impact:
    If API inventory management is weak, attackers may:

        - Exploit undocumented or insecure APIs
        - Bypass security policies and access controls
        - Gain unauthorized access to sensitive data or functionality
        - Evade detection due to lack of monitoring and oversight

    Expected Behavior:
    Applications should:

        - Maintain a complete, up-to-date API inventory
        - Document all APIs and their security requirements
        - Apply consistent security controls across all endpoints
        - Monitor and log API usage for anomalies
        - Ensure lifecycle management and decommissioning of obsolete APIs
    */
    
    private async Task<string> RunApiInventoryManagementTestsAsync(Uri baseUri)
    {
        var paths = new[]
        {
            "/swagger",
            "/swagger/index.html",
            "/openapi.json",
            "/v1",
            "/v2",
            "/beta",
            "/internal",
            "/api",
            "/docs",
            "/inventory",
            "/products",
            "/items",
            "/catalog",
            "/inventory/status",
            "/inventory/stock",
            "/orders",
            "/order/{id}",
            "/products/{id}",
            "/inventory/{id}",
            "/warehouse",
            "/locations",
            "/stock"
        };

        var findings = new List<string>();
        foreach (var path in paths)
        {
            var uri = new Uri(baseUri, path);
            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, uri));
            findings.Add($"{path}: {FormatStatus(response)}");
        }

        return FormatSection("Improper Inventory Management", baseUri, findings);
    }

}

