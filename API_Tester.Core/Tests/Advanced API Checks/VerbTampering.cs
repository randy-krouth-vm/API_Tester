namespace API_Tester;

public partial class MainPage
{
    /*
    HTTP Verb Tampering Test

    Purpose:
    Checks whether the API improperly enforces authorization or validation
    rules based on HTTP methods (verbs) such as GET, POST, PUT, DELETE,
    PATCH, or OPTIONS.

    Threat Model:
    HTTP verb tampering occurs when an application applies security checks
    to some request methods but not others. Attackers may attempt to use
    alternate HTTP methods to bypass access controls, authentication
    checks, or input validation logic.

    For example, an endpoint may properly restrict POST requests but fail
    to enforce the same controls for PUT, PATCH, or DELETE requests.

    Attack scenarios include:

        - accessing restricted functionality using alternate HTTP verbs
        - bypassing authentication checks applied only to specific methods
        - modifying or deleting resources through unintended request types
        - triggering unprotected endpoints through uncommon verbs

    Example scenario:

        Endpoint:
            POST /api/users/delete

        If authorization is checked only for POST, an attacker might try:

            DELETE /api/users/delete
            PUT /api/users/delete
            PATCH /api/users/delete

    If the application processes these methods differently or skips
    authorization logic, the attacker may gain unintended access.

    Test Strategy:
    The scanner sends requests to endpoints using a variety of HTTP
    methods beyond the expected one and observes whether the server
    accepts the request or returns unexpected responses.

    Potential Impact:
    If HTTP verb tampering is possible, attackers may be able to:

        - bypass access controls
        - perform unauthorized actions
        - manipulate resources using unintended methods
        - discover hidden or undocumented functionality

    Expected Behavior:
    Applications should strictly enforce allowed HTTP methods for each
    endpoint and ensure that authentication and authorization checks
    are consistently applied regardless of the request method.
    */

    private async Task<string> RunVerbTamperingTestsAsync(Uri baseUri)
    {
        var methods = new[] { HttpMethod.Put, HttpMethod.Delete, HttpMethod.Patch };
        var findings = new List<string>();

        foreach (var method in methods)
        {
            var response = await SafeSendAsync(() => new HttpRequestMessage(method, baseUri));
            findings.Add($"{method.Method}: {FormatStatus(response)}");
        }

        if (findings.Any(f => f.Contains("200 OK", StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add("Potential risk: sensitive verbs may be enabled unexpectedly.");
        }

        return FormatSection("HTTP Verb Tampering", baseUri, findings);
    }

}

