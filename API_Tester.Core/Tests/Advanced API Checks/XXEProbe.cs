namespace API_Tester;

public partial class MainPage
{
    /*
    XML External Entity (XXE) Probe Test

    Purpose:
    Checks whether the application’s XML parser is vulnerable to XML
    External Entity (XXE) attacks that allow attackers to access local
    files, internal network resources, or sensitive data through crafted
    XML input.

    Threat Model:
    XML supports entity declarations inside a DOCTYPE. These entities can
    reference external resources such as files or network locations.

    If the XML parser processes external entities without restrictions,
    an attacker can cause the server to fetch or include external data
    during XML parsing.

    Example malicious XML:

        <!DOCTYPE foo [
        <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <data>&xxe;</data>

    If the parser resolves the entity, the server may read and return the
    contents of the referenced file.

    Attack scenarios include:

        - reading sensitive files from the server
        - accessing internal services not exposed publicly
        - retrieving configuration files or credentials
        - triggering server-side request forgery (SSRF)
        - scanning internal networks

    Example internal resource access:

        <!ENTITY xxe SYSTEM "http://localhost:8080/admin">

    The parser may request internal resources that external attackers
    cannot normally reach.

    Test Strategy:
    The scanner submits XML payloads containing external entity references
    and observes whether the server resolves them, returns referenced data,
    or performs unexpected outbound requests.

    Potential Impact:
    If XXE vulnerabilities exist, attackers may be able to:

        - read local files from the server
        - access internal APIs or metadata services
        - retrieve sensitive configuration data
        - perform server-side request forgery
        - expose secrets stored on the system

    Expected Behavior:
    Applications should disable external entity resolution when parsing
    XML and configure parsers to reject DOCTYPE declarations or external
    entity references unless explicitly required.
    */
    
    private async Task<string> RunXxeProbeTestsAsync(Uri baseUri)
    {
        const string xml = "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/hosts\">]><r>&xxe;</r>";
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Content = new StringContent(xml, Encoding.UTF8, "application/xml");
            return req;
        });

        var body = await ReadBodyAsync(response);
        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            ContainsAny(body, "localhost", "127.0.0.1", "[extensions]", "root:")
            ? "Potential risk: XXE payload content may have been expanded."
            : "No obvious XXE expansion marker."
        };

        return FormatSection("XXE Probe", baseUri, findings);
    }

}

