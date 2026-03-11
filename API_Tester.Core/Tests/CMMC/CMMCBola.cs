namespace API_Tester;

public partial class MainPage
{
    /*
    CMMC BOLA (Broken Object Level Authorization) Test

    Purpose:
    Checks whether the API properly enforces object-level authorization
    controls as required by CMMC-style access control practices. The test
    focuses on detecting Broken Object Level Authorization (BOLA) issues
    where users can access objects that belong to other users or tenants.

    Threat Model:
    Many APIs expose resources through identifiers such as:

        /api/orders/{orderId}
        /api/users/{userId}
        /api/files/{fileId}

    If the application only verifies that the caller is authenticated but
    does not verify ownership or authorization for the specific object,
    an attacker may modify identifiers to access data belonging to other
    users.

    Example scenario:

        Authenticated user requests:
            GET /api/accounts/1001

        Attacker modifies identifier:
            GET /api/accounts/1002

    If the server does not validate ownership or permissions, the attacker
    may retrieve another user's data.

    Attack scenarios include:

        - accessing another user's profile or account data
        - downloading files belonging to other users
        - modifying or deleting resources owned by other tenants
        - bypassing tenant isolation in multi-tenant environments

    This vulnerability is commonly listed as one of the most critical API
    security risks.

    Test Strategy:
    The scanner attempts to access resources using modified identifiers
    or sequential object IDs and observes whether the API returns data
    that should belong to a different user or tenant.

    Potential Impact:
    If BOLA vulnerabilities exist, attackers may be able to:

        - access sensitive data belonging to other users
        - modify or delete other users' resources
        - bypass tenant boundaries in multi-tenant systems
        - escalate privileges within the application

    Expected Behavior:
    APIs should validate object ownership or permissions on every request.
    Access to resources must be verified against the authenticated user
    or service identity to ensure that only authorized principals can
    access specific objects.
    */

    private async Task<string> RunCMMCBolaTestsAsync(Uri baseUri)
    {
        var original = AppendQuery(baseUri, new Dictionary<string, string> { ["id"] = "1" });
        var tampered = AppendQuery(baseUri, new Dictionary<string, string> { ["id"] = "999999" });

        var originalResponse = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, original));
        var tamperedResponse = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, tampered));

        var findings = new List<string>
        {
            $"Original request status: {FormatStatus(originalResponse)}",
            $"Tampered request status: {FormatStatus(tamperedResponse)}"
        };

        if (originalResponse is not null && tamperedResponse is not null &&
        originalResponse.StatusCode == tamperedResponse.StatusCode &&
        originalResponse.StatusCode == HttpStatusCode.OK)
        {
            findings.Add("Potential risk: tampered object ID returned same success status.");
        }
        else
        {
            findings.Add("No obvious BOLA indicator from status comparison.");
        }

        return FormatSection("BOLA / Object ID Tampering", tampered, findings);
    }

}

