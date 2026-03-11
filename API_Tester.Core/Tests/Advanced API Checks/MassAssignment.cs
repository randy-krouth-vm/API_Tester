namespace API_Tester;

public partial class MainPage
{
    /*
    Mass Assignment Test

    Purpose:
    Checks whether the API improperly allows user-supplied input to bind
    directly to internal object properties that should not be modifiable
    by clients.

    Threat Model:
    Many frameworks automatically bind JSON request fields to server-side
    objects or models. If this binding is not restricted, attackers may
    include additional parameters in the request body that correspond to
    sensitive fields such as roles, permissions, account flags, or internal
    status properties.

    Example attack payload:

        {
            "username": "user1",
            "email": "user@example.com",
            "role": "admin",
            "isAdmin": true,
            "accountBalance": 1000000
        }

    If the server blindly maps these fields onto internal models, attackers
    may be able to escalate privileges or manipulate protected state.

    Test Strategy:
    The scanner submits requests containing extra parameters that are
    commonly associated with privileged or internal fields. It observes
    whether the server accepts the parameters, ignores them, or returns
    validation errors.

    Potential Impact:
    If mass assignment vulnerabilities exist, attackers may be able to:

        - escalate privileges (e.g., set "isAdmin": true)
        - modify protected account properties
        - bypass authorization checks
        - manipulate application state

    Expected Behavior:
    The server should explicitly control which fields are allowed to be
    bound from client input. Sensitive fields should never be writable
    through external requests and should be managed only by trusted
    server-side logic.
    */
    
    private async Task<string> RunMassAssignmentTestsAsync(Uri baseUri)
    {
        const string payload = "{\"email\":\"apitester@example.local\",\"role\":\"admin\",\"isAdmin\":true,\"tenantId\":\"other-tenant\"}";
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            return req;
        });
        var body = await ReadBodyAsync(response);

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            ContainsAny(body, "\"admin\"", "isAdmin", "role")
            ? "Potential risk: privileged object fields may be accepted/echoed."
            : "No obvious mass-assignment indicator."
        };

        return FormatSection("Mass Assignment", baseUri, findings);
    }

}

