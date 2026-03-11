namespace API_Tester;

public partial class MainPage
{
    /*
    TLS Security Posture Test

    Purpose:
    Evaluates the Transport Layer Security (TLS) configuration of the
    target service to identify weak encryption protocols, insecure
    cipher suites, or misconfigurations that could weaken the security
    of encrypted communications.

    Threat Model:
    TLS protects data in transit between clients and servers. If TLS
    is misconfigured or outdated protocols are enabled, attackers may
    be able to intercept, decrypt, or manipulate traffic using known
    cryptographic weaknesses.

    Common TLS risks include:

        - support for deprecated protocols (SSLv2, SSLv3, TLS 1.0, TLS 1.1)
        - weak or outdated cipher suites
        - missing certificate validation or trust chain issues
        - insecure renegotiation
        - lack of forward secrecy

    Example attack scenarios include:

        - man-in-the-middle interception of encrypted traffic
        - downgrade attacks forcing weaker protocols
        - exploitation of known weaknesses in outdated TLS versions
        - impersonation if certificate validation is misconfigured

    Test Strategy:
    The scanner connects to the target endpoint and analyzes the TLS
    handshake behavior, supported protocol versions, and certificate
    information to identify insecure configurations or outdated
    security settings.

    Potential Impact:
    If TLS is weak or misconfigured, attackers may be able to:

        - intercept or decrypt sensitive communications
        - manipulate data in transit
        - impersonate the server
        - exploit cryptographic weaknesses in legacy protocols

    Expected Behavior:
    Applications should enforce modern TLS configurations, including:

        - TLS 1.2 or TLS 1.3 only
        - strong cipher suites
        - properly configured certificate chains
        - forward secrecy support

    Deprecated protocols and weak cipher suites should be disabled
    to ensure secure encrypted communication.
    */
    
    private async Task<string> RunTlsPostureTestsAsync(Uri baseUri)
    {
        var findings = new List<string>();
        if (baseUri.Scheme != Uri.UriSchemeHttps)
        {
            findings.Add("Potential risk: target is not HTTPS.");
            return FormatSection("TLS Posture", baseUri, findings);
        }

        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, baseUri));
        findings.Add($"HTTP {FormatStatus(response)}");
        findings.Add(response is not null && response.Headers.Contains("Strict-Transport-Security")
        ? "HSTS present."
        : "Potential risk: HSTS missing.");

        var setCookie = response is null ? string.Empty : TryGetHeader(response, "Set-Cookie");
        if (!string.IsNullOrWhiteSpace(setCookie))
        {
            findings.Add(setCookie.Contains("Secure", StringComparison.OrdinalIgnoreCase)
            ? "Secure cookie attribute observed."
            : "Potential risk: Set-Cookie without Secure attribute.");
        }

        return FormatSection("TLS Posture", baseUri, findings);
    }

}

