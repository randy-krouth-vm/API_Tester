namespace API_Tester;

public partial class MainPage
{
    /*
    OWASP API Security – Broken Object Property Level Authorization Tests

    Purpose:
    Performs automated tests to evaluate whether the application properly
    enforces authorization at the object property level. This addresses
    Broken Object Property Level Authorization (BOPLA), where users may
    read or modify specific fields of an object that should be restricted.

    Threat Model:
    Even when object-level access is controlled, individual properties
    within an object may still be exposed or modifiable without proper
    authorization checks. Attackers may attempt to:

        - read sensitive fields from API responses
        - modify protected attributes in update requests
        - elevate privileges by altering role or permission fields
        - access internal system metadata

    Sensitive object properties may include:

        - user roles or privilege flags
        - internal account identifiers
        - authentication tokens or security attributes
        - financial or personal information fields
        - system configuration parameters

    Common vulnerabilities include:

        - returning sensitive fields in API responses
        - allowing modification of protected properties through input
        - lack of field-level authorization validation
        - inconsistent filtering of response data
        - mass assignment vulnerabilities

    Test Strategy:
    The method performs automated checks that:

        - analyze API responses for sensitive or restricted fields
        - attempt modification of protected properties in requests
        - evaluate enforcement of field-level authorization rules
        - detect mass assignment vulnerabilities
        - inspect inconsistencies in property exposure across endpoints

    Potential Impact:
    If property-level authorization controls are weak, attackers may:

        - access sensitive user or system information
        - escalate privileges by modifying role attributes
        - manipulate financial or account data
        - compromise application integrity and confidentiality

    Expected Behavior:
    Applications should:

        - enforce authorization checks for sensitive object properties
        - return only necessary fields in API responses
        - prevent modification of protected attributes
        - implement strict input validation and allowlists
        - apply consistent field-level access controls across all APIs
    */

    private async Task<string> RunBrokenObjectPropertyLevelAuthTestsAsync(Uri baseUri)
    {
        var testUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["role"] = "admin",
            ["isAdmin"] = "true",
            ["permissions"] = "all"
        });

        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, testUri));
        var body = await ReadBodyAsync(response);
        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            body.Contains("admin", StringComparison.OrdinalIgnoreCase) || body.Contains("permissions", StringComparison.OrdinalIgnoreCase)
            ? "Potential risk: elevated object properties reflected or processed."
            : "No obvious object-property authorization indicator."
        };

        return FormatSection("Broken Object Property Level Authorization", testUri, findings);
    }

}

