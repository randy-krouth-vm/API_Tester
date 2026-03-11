namespace API_Tester;

public partial class MainPage
{
    /*
    WebSocket Fragmentation Handling Test

    Purpose:
    Checks whether the WebSocket implementation properly handles fragmented
    frames and enforces message validation across fragments.

    Threat Model:
    The WebSocket protocol allows messages to be split into multiple
    fragments (frames) before being reassembled by the server. While this
    feature supports large messages and streaming data, it can introduce
    security risks if the server validates only individual fragments
    instead of the fully reconstructed message.

    Attackers may exploit fragmentation to bypass security controls,
    message validation logic, or input filters that assume a message
    arrives in a single frame.

    Attack scenarios include:

        - splitting malicious payloads across fragments to bypass filters
        - sending incomplete or malformed fragment sequences
        - injecting hidden data in continuation frames
        - bypassing size or content validation checks

    Example scenario:

        Fragment 1 → "admin"
        Fragment 2 → "=true"

    If validation occurs only on individual fragments, the full message
    "admin=true" may bypass input checks.

    Test Strategy:
    The scanner attempts to send WebSocket messages split across multiple
    frames or with unusual fragment sequences and observes how the server
    processes the reconstructed message.

    Potential Impact:
    If fragmentation handling is weak, attackers may be able to:

        - bypass message validation or filtering logic
        - inject unexpected commands into real-time systems
        - trigger parsing errors or protocol confusion
        - disrupt application behavior

    Expected Behavior:
    Servers should correctly reassemble fragmented WebSocket messages
    before applying validation, enforce proper frame sequencing, and
    reject malformed or unexpected fragment structures.
    */
    
    private async Task<string> RunWebSocketFragmentationTestsAsync(Uri baseUri)
    {
        var wsUri = new Uri(baseUri, "/ws");
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Get, wsUri);
            req.Headers.TryAddWithoutValidation("Connection", "Upgrade");
            req.Headers.TryAddWithoutValidation("Upgrade", "websocket");
            req.Headers.TryAddWithoutValidation("Sec-WebSocket-Version", "13");
            req.Headers.TryAddWithoutValidation("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==");
            req.Headers.TryAddWithoutValidation("Sec-WebSocket-Extensions", "permessage-deflate; client_max_window_bits=15; invalid_fragment=1");
            return req;
        });

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.SwitchingProtocols
            ? "Upgrade accepted; review fragmented-frame handling server-side."
            : "No obvious fragmented upgrade acceptance signal."
        };

        return FormatSection("WebSocket Fragmentation", wsUri, findings);
    }

}

