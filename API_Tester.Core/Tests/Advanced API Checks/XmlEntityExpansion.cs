namespace API_Tester;

public partial class MainPage
{
    /*
    XML Entity Expansion Test (XXE / Billion Laughs)

    Purpose:
    Checks whether the application’s XML parser is vulnerable to XML
    Entity Expansion attacks, where specially crafted XML entities are
    expanded recursively and consume excessive memory or CPU resources.

    Threat Model:
    XML supports entity definitions that allow one value to reference
    another. If recursive entities are permitted, attackers can create
    exponentially expanding payloads that overwhelm the parser.

    This class of attack is commonly known as the "Billion Laughs" attack.

    Example malicious XML:

        <!DOCTYPE lolz [
        <!ENTITY lol "lol">
        <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
        <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
        ]>
        <data>&lol2;</data>

    When parsed, the entities expand recursively, potentially creating
    huge in-memory strings and exhausting system resources.

    Attack scenarios include:

        - denial-of-service through memory exhaustion
        - CPU exhaustion during entity expansion
        - application crashes caused by parser overload
        - service disruption in XML-processing endpoints

    Test Strategy:
    The scanner submits XML payloads containing nested or recursive
    entity definitions and observes whether the server processes them
    or rejects the request.

    Potential Impact:
    If entity expansion is not restricted, attackers may be able to:

        - crash the application
        - exhaust server memory
        - trigger denial-of-service conditions
        - degrade performance of XML processing services

    Expected Behavior:
    Applications should disable external entity processing and limit
    entity expansion when parsing XML. XML parsers should be configured
    to reject or safely handle recursive entity definitions to prevent
    resource exhaustion attacks.
    */
    
    private async Task<string> RunXmlEntityExpansionTestsAsync(Uri baseUri)
    {
        const string xml = "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY a \"1234567890\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\">]><root>&b;</root>";
        var started = DateTime.UtcNow;
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Content = new StringContent(xml, Encoding.UTF8, "application/xml");
            return req;
        });
        var elapsed = (DateTime.UtcNow - started).TotalMilliseconds;

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            $"Response time: {elapsed:F0} ms",
            elapsed > 5000 || response is not null && response.StatusCode == HttpStatusCode.InternalServerError
            ? "Potential risk: parser appears sensitive to XML entity expansion load."
            : "No obvious entity expansion DoS indicator."
        };

        return FormatSection("XML Entity Expansion", baseUri, findings);
    }
}

