using System.Net;

namespace API_Tester;

public partial class MainPage
{
    /*
    Kerberos / SPNEGO Negotiate Authentication Probe

    Purpose:
    Tests whether an endpoint properly handles the HTTP "Negotiate" authentication
    scheme (used for Kerberos and SPNEGO). The probe sends a request with an
    intentionally invalid Negotiate Authorization header and evaluates how the
    server responds.

    What the test checks:
    1. Whether the server incorrectly accepts a malformed Negotiate token
    (responses in the 2xx–3xx range may indicate a potential authentication issue).
    2. Whether the server advertises a "WWW-Authenticate: Negotiate" challenge,
    indicating support for Kerberos/SPNEGO authentication.
    3. Whether the server advertises "WWW-Authenticate: NTLM", which may signal
    a fallback to NTLM authentication. NTLM fallback can weaken authentication
    security in some enterprise environments.

    Expected behavior:
    A correctly configured Kerberos/SPNEGO endpoint should typically respond with:
        HTTP 401 Unauthorized
        WWW-Authenticate: Negotiate

    Notes:
    - This probe does NOT attempt a full Kerberos authentication exchange.
    - It is a lightweight diagnostic used to detect authentication configuration
    behavior and potential fallback mechanisms.
    - The request is read-only and should not modify server state.

    Used in:
    Security/authentication diagnostics within the automated testing pipeline.
    */
    
    private async Task<string> RunKerberosNegotiateAuthTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
            req.Headers.TryAddWithoutValidation("Authorization", "Negotiate not-a-valid-token");
            return req;
        });

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}"
        };

        if (response is null)
        {
            findings.Add("No response received.");
            return FormatSection("Kerberos/Negotiate Auth Probe", baseUri, findings);
        }

        var wwwAuth = response.Headers.TryGetValues("WWW-Authenticate", out var values)
            ? string.Join(", ", values)
            : string.Empty;

        if ((int)response.StatusCode is >= 200 and < 400)
        {
            findings.Add("Potential risk: Negotiate header may have been accepted.");
        }
        else if (!string.IsNullOrWhiteSpace(wwwAuth) && wwwAuth.Contains("Negotiate", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add("Negotiate challenge advertised.");
        }
        else
        {
            findings.Add("No Negotiate challenge observed.");
        }

        if (!string.IsNullOrWhiteSpace(wwwAuth) && wwwAuth.Contains("NTLM", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add("Potential risk: NTLM fallback advertised.");
        }

        return FormatSection("Kerberos/Negotiate Auth Probe", baseUri, findings);
    }
}
