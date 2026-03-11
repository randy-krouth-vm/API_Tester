namespace API_Tester;

public partial class MainPage
{
    /*
    Cookie Security Flag Test

    Purpose:
    Checks whether cookies set by the application include appropriate
    security attributes to protect them from interception and client-side
    script access.

    Threat Model:
    Cookies often contain session identifiers or authentication tokens.
    If security flags are missing, attackers may be able to steal or abuse
    these cookies through network interception or client-side attacks.

    Important cookie security attributes include:

        Secure
        HttpOnly
        SameSite

    Test Strategy:
    The scanner inspects Set-Cookie headers returned by the server and
    verifies whether the following flags are present:

        Secure   – ensures cookies are only transmitted over HTTPS
        HttpOnly – prevents JavaScript from accessing the cookie
        SameSite – restricts cross-site cookie transmission

    Potential Impact:
    Missing cookie security flags may enable attacks such as:

        - session hijacking
        - cross-site scripting (XSS) cookie theft
        - cross-site request forgery (CSRF)
        - network interception on insecure connections

    Expected Behavior:
    Sensitive cookies, especially session cookies, should include:

        Secure
        HttpOnly
        SameSite=Lax or SameSite=Strict

    to ensure they are protected against common web attacks.
    */
    
    private async Task<string> RunCookieSecurityFlagTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, baseUri));
        var findings = new List<string> { $"HTTP {FormatStatus(response)}" };

        if (response is null || !response.Headers.TryGetValues("Set-Cookie", out var setCookies))
        {
            findings.Add("No Set-Cookie headers found.");
            return FormatSection("Cookie Security Flags", baseUri, findings);
        }

        foreach (var cookie in setCookies)
        {
            findings.Add(cookie.Contains("Secure", StringComparison.OrdinalIgnoreCase) ? "Cookie has Secure" : "Cookie missing Secure");
            findings.Add(cookie.Contains("HttpOnly", StringComparison.OrdinalIgnoreCase) ? "Cookie has HttpOnly" : "Cookie missing HttpOnly");
            findings.Add(cookie.Contains("SameSite", StringComparison.OrdinalIgnoreCase) ? "Cookie has SameSite" : "Cookie missing SameSite");
        }

        return FormatSection("Cookie Security Flags", baseUri, findings);
    }

}

