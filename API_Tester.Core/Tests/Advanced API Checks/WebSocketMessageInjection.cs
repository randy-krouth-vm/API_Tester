namespace API_Tester;

public partial class MainPage
{
    /*
    WebSocket Message Injection Test

    Purpose:
    Checks whether the WebSocket endpoint properly validates and sanitizes
    incoming messages to prevent unauthorized command execution or data
    manipulation through injected payloads.

    Threat Model:
    WebSocket connections allow clients to send arbitrary messages to the
    server after the connection is established. If the server trusts or
    directly processes user-supplied messages without validation, attackers
    may inject malicious commands or manipulate application behavior.

    Because WebSocket communication is persistent and often bypasses
    traditional HTTP request validation layers, security controls may
    be weaker than those applied to normal REST endpoints.

    Attack scenarios include:

        - injecting unauthorized commands into real-time APIs
        - manipulating application state through crafted messages
        - triggering hidden administrative actions
        - exploiting message parsing or routing logic
        - abusing internal event or messaging systems

    Example risk:

        Client message:
            { "action": "deleteUser", "id": "123" }

    If the server processes this command without validating user
    permissions, an attacker may perform unauthorized operations.

    Test Strategy:
    The scanner establishes a WebSocket connection and sends crafted
    messages containing unexpected actions, manipulated parameters,
    or malformed message structures. Responses are analyzed to determine
    whether the server improperly accepts or processes injected messages.

    Potential Impact:
    If WebSocket message validation is weak, attackers may be able to:

        - execute unauthorized actions through real-time APIs
        - manipulate application state
        - access sensitive data streams
        - disrupt application functionality

    Expected Behavior:
    WebSocket servers should enforce authentication, authorization,
    and strict message validation for all incoming messages. Only
    allowed actions and properly structured messages should be
    processed, and all other inputs should be rejected.
    */
    
    private async Task<string> RunWebSocketMessageInjectionTestsAsync(Uri baseUri)
    {
        var wsUri = new Uri(baseUri, "/ws");
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Get, wsUri);
            req.Headers.TryAddWithoutValidation("Connection", "Upgrade");
            req.Headers.TryAddWithoutValidation("Upgrade", "websocket");
            req.Headers.TryAddWithoutValidation("Sec-WebSocket-Version", "13");
            req.Headers.TryAddWithoutValidation("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
            req.Headers.TryAddWithoutValidation("X-WS-Event", "{\"type\":\"admin\",\"action\":\"delete-all\"}");
            return req;
        });

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.SwitchingProtocols
            ? "Potential risk: websocket upgrade accepted with suspicious message-like metadata."
            : "No obvious websocket message injection acceptance signal."
        };

        return FormatSection("WebSocket Message Injection", wsUri, findings);
    }

}

