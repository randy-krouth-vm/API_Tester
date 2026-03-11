namespace API_Tester;

public partial class MainPage
{
    /*
    HTTP Method Override Test

    Purpose:
    Checks whether the API improperly allows HTTP method overriding through
    headers or request parameters.

    Threat Model:
    Some frameworks support method overriding to allow browsers or limited
    clients to simulate HTTP verbs such as PUT, PATCH, or DELETE when only
    GET or POST requests are supported. This is commonly implemented using
    headers or parameters such as:

        X-HTTP-Method-Override
        X-Method-Override
        _method

    If method override is enabled without proper validation or restrictions,
    attackers may be able to bypass routing rules, security filters, or
    middleware that enforce permissions based on the original HTTP method.

    Example scenario:

        POST /resource
        X-HTTP-Method-Override: DELETE

    If the server honors the override, the request may be processed as a
    DELETE even though security controls expected a POST.

    Test Strategy:
    The scanner sends requests with method override headers or parameters
    while using a different base HTTP method. It observes whether the server
    interprets the request using the overridden method.

    Potential Impact:
    If method override is improperly handled, attackers may be able to:

        - bypass endpoint method restrictions
        - access unintended API routes
        - perform unauthorized state-changing actions
        - circumvent middleware security checks

    Expected Behavior:
    The server should either disable HTTP method override entirely or ensure
    that any override mechanism is strictly validated and does not bypass
    authorization or routing controls.
    */
    
    private async Task<string> RunMethodOverrideTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Headers.TryAddWithoutValidation("X-HTTP-Method-Override", "DELETE");
            req.Content = new StringContent("{\"action\":\"probe\"}", Encoding.UTF8, "application/json");
            return req;
        });

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.OK
            ? "Potential risk: method override may be accepted unexpectedly."
            : "No obvious method-override acceptance."
        };

        return FormatSection("Method Override Tampering", baseUri, findings);
    }

}

