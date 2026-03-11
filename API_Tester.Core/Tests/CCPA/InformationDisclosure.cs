namespace API_Tester;

public partial class MainPage
{
    /*
    Information Disclosure Test

    Purpose:
    Checks whether the application unintentionally exposes internal
    information through HTTP responses, headers, error messages,
    or debug output.

    Threat Model:
    Information disclosure vulnerabilities occur when an application
    reveals details about its internal implementation, environment,
    or infrastructure that should not be publicly visible.

    While the exposed data may not directly allow exploitation,
    it can significantly assist attackers during reconnaissance
    by revealing useful technical details.

    Common sources of information disclosure include:

        - verbose error messages or stack traces
        - server or framework version headers
        - debug output in API responses
        - configuration paths or file locations
        - internal service URLs or IP addresses

    Example response:

        HTTP/1.1 500 Internal Server Error
        X-Powered-By: ASP.NET Core
        Server: Kestrel
        StackTrace: at Application.Controllers.UserController...

    Such responses may reveal the technologies, frameworks, or
    internal structure of the application.

    Attack scenarios include:

        - identifying vulnerable software versions
        - discovering internal API endpoints
        - learning file paths or server structure
        - mapping backend technologies and frameworks

    Test Strategy:
    The scanner submits malformed or unexpected inputs and analyzes
    server responses for error messages, debug traces, internal paths,
    or technology identifiers that may reveal sensitive details.

    Potential Impact:
    If information disclosure occurs, attackers may be able to:

        - identify software components and versions
        - discover internal infrastructure details
        - gain insight into application architecture
        - improve targeting of further attacks

    Expected Behavior:
    Applications should return generic error messages and avoid
    exposing internal implementation details. Debug information,
    stack traces, and sensitive headers should be disabled in
    production environments.
    */
    
    private async Task<string> RunInformationDisclosureTestsAsync(Uri baseUri)
    {
        var findings = new List<string>();
        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, baseUri));

        if (response is null)
        {
            findings.Add("No response received.");
            return FormatSection("Information Disclosure", baseUri, findings);
        }

        findings.Add($"HTTP {(int)response.StatusCode} {response.StatusCode}");
        var disclosureHeaders = new[] { "Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version" };

        foreach (var header in disclosureHeaders)
        {
            var value = TryGetHeader(response, header);
            findings.Add(string.IsNullOrWhiteSpace(value)
            ? $"Not exposed: {header}"
            : $"Potential disclosure: {header}={value}");
        }

        return FormatSection("Information Disclosure", baseUri, findings);
    }

}

