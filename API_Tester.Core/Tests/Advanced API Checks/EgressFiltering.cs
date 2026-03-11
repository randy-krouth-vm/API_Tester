namespace API_Tester;

public partial class MainPage
{
    /*
    Egress Filtering Test

    Purpose:
    Evaluates whether the application or its hosting environment restricts
    outbound (egress) network requests to external or internal destinations.

    Threat Model:
    Applications that perform server-side HTTP requests using user-controlled
    input may be vulnerable to Server-Side Request Forgery (SSRF). Without
    proper egress filtering, attackers may force the application to connect
    to internal systems or sensitive infrastructure.

    Typical internal targets attackers attempt to reach include:

        - localhost services (127.0.0.1, ::1)
        - private network ranges (10.x.x.x, 172.16.x.x, 192.168.x.x)
        - cloud metadata endpoints (169.254.169.254)
        - internal administrative services
        - container management APIs

    Test Strategy:
    The scanner attempts outbound requests to known internal or restricted
    network ranges and observes whether the application is able to connect
    to them.

    Potential Impact:
    If egress controls are not enforced, attackers may be able to:

        - access internal services not exposed to the public internet
        - retrieve cloud instance metadata and credentials
        - interact with internal APIs or databases
        - perform lateral movement within internal networks

    Expected Behavior:
    Applications and infrastructure should enforce outbound network
    restrictions to prevent access to internal or sensitive destinations.
    Egress filtering, network segmentation, and allowlists should be used
    to limit outbound connections only to approved external services.
    */
    
    private async Task<string> RunEgressFilteringTestsAsync(Uri baseUri)
    {
        var targets = ExpandHttpToHttps(GetManualPayloadsOrDefault(new[]
        {
            "http://127.0.0.1:22/",
            "http://127.0.0.1:25/",
            "http://127.0.0.1:3306/",
            "http://127.0.0.1:6379/",
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:9200/",
            "http://127.0.0.1:11211/",
            "http://localhost:22/",
            "http://localhost:25/",
            "http://localhost:3306/",
            "http://localhost:6379/",
            "http://localhost:8080/",
            "http://10.0.0.1:22/",
            "http://10.0.0.1:3306/",
            "http://10.0.0.1:6379/",
            "http://10.0.0.1:8080/",
            "http://172.16.0.1:22/",
            "http://172.16.0.1:3306/",
            "http://172.16.0.1:6379/",
            "http://172.16.0.1:8080/",
            "http://192.168.1.1:22/",
            "http://192.168.1.1:3306/",
            "http://192.168.1.1:6379/",
            "http://192.168.1.1:8080/",
            "http://169.254.169.254/",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254:80/latest/meta-data/",
            "ldap://127.0.0.1:389/",
            "ldap://localhost:389/",
            "ldap://10.0.0.1:389/",
            "ftp://127.0.0.1:21/",
            "ftp://localhost:21/",
            "gopher://127.0.0.1:6379/",
            "gopher://127.0.0.1:11211/"
        }, ManualPayloadCategory.Ssrf));

        var findings = new List<string>();
        foreach (var target in targets)
        {
            var uri = AppendQuery(baseUri, new Dictionary<string, string> { ["url"] = target, ["callback"] = target });
            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, uri));
            findings.Add($"{target}: {FormatStatus(response)}");
        }

        return FormatSection("Egress Filtering", baseUri, findings);
    }

}

