namespace API_Tester;

public partial class MainPage
{
    /*
    Mobile Deep Link Hijacking Test

    Purpose:
    Checks whether API endpoints or associated mobile deep link mechanisms
    may allow attackers to hijack or abuse deep links used by mobile apps.

    Threat Model:
    Mobile applications often use deep links or universal links to open
    specific screens within the app. These links may contain tokens,
    session identifiers, reset codes, or other sensitive parameters.

    Example deep link:

        myapp://reset-password?token=abc123

    or

        https://example.com/app/open?token=abc123

    If the application does not properly validate these links, attackers
    may be able to manipulate or intercept them.

    Attack scenarios include:

        - registering a malicious app with the same deep link scheme
        - intercepting authentication or password reset links
        - manipulating deep link parameters
        - redirecting users to malicious content

    Test Strategy:
    The scanner probes endpoints commonly associated with deep link
    handlers and attempts to manipulate parameters that might appear
    in mobile deep link flows. It observes how the server responds to
    unexpected or modified values.

    Potential Impact:
    If deep link handling is insecure, attackers may be able to:

        - hijack login or password reset flows
        - intercept authentication tokens
        - redirect users to malicious apps or websites
        - bypass intended application routing

    Expected Behavior:
    Mobile applications should strictly validate deep link parameters
    and ensure that sensitive actions (such as authentication or account
    changes) require proper server-side verification. Deep link schemes
    should be protected using secure universal link configurations and
    server-side validation.
    */

    private async Task<string> RunMobileDeepLinkHijackingTestsAsync(Uri baseUri)
    {
        var mobileRedirects = new[]
        {
            // iOS Custom URL Scheme: Checks if deep links (e.g., myapp://callback) are vulnerable to hijacking.
            "myapp://callback?code=apitester",         
            "myapp://login?token=apitester",     
            "myapp://reset?token=apitester",      
            "myapp://open?path=dashboard",             

            // Android Intent URLs: Tests Android-specific intent-based deep links.
            "intent://callback#Intent;scheme=myapp;end",  
            "intent://login#Intent;scheme=myapp;end",     
            "intent://reset?token=apitester#Intent;scheme=myapp;end", 

            // Universal Links (iOS): Tests universal links for redirection within iOS apps.
            "https://myapp.com/callback?code=apitester", 
            "https://myapp.com/login?token=apitester",   
            "https://myapp.com/reset?token=apitester",   
            
            // Intent-based redirects on Android: Tests the ability of an intent-based deep link to redirect the user to another app or page.
            "intent://callback?token=apitester#Intent;scheme=myapp;end", 
            "intent://open?path=home#Intent;scheme=myapp;end",         
            
            // Custom Scheme for Other Apps: Tests redirecting to other apps to check for cross-app hijacking.
            "otherapp://open?user=apitester",        
            "otherapp://callback?code=apitester",  
            
            // Universal Link for Android: Tests if Android apps can open universal links.
            "https://myapp.com/intent/callback?code=apitester", 
            "https://myapp.com/intent/reset?token=apitester",   
            
            // Intent Redirection to Malicious App (Android): Tests if malicious apps can hijack the deep link.
            "intent://malicious-app.com#Intent;scheme=myapp;end", 
            
            // Deep link with various parameters for app hijacking: Tests for parameter manipulation in deep links.
            "myapp://redirect?url=http://malicious.com", 
            "myapp://redirect?path=/admin&user=admin",   
            "app://reset?token=malicious_token",          
        };

        var findings = new List<string>();
        foreach (var redirect in mobileRedirects)
        {
            var uri = AppendQuery(baseUri, new Dictionary<string, string>
            {
                ["redirect_uri"] = redirect,
                ["next"] = redirect,
                ["returnUrl"] = redirect
            });

            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, uri));
            var location = response is null ? string.Empty : TryGetHeader(response, "Location");
            var echoed = !string.IsNullOrWhiteSpace(location) &&
            location.Contains(redirect, StringComparison.OrdinalIgnoreCase);
            findings.Add($"{redirect}: {FormatStatus(response)}{(echoed ? " (redirect echoed)" : string.Empty)}");
        }

        var assetLinks = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, new Uri(baseUri, "/.well-known/assetlinks.json")));
        var aasa = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, new Uri(baseUri, "/.well-known/apple-app-site-association")));
        findings.Add($"/.well-known/assetlinks.json: {FormatStatus(assetLinks)}");
        findings.Add($"/.well-known/apple-app-site-association: {FormatStatus(aasa)}");

        return FormatSection("Mobile Deep-Link Hijacking", baseUri, findings);
    }

}

