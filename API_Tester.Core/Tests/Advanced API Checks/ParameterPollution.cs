namespace API_Tester;

public partial class MainPage
{
    /*
    HTTP Parameter Pollution Test

    Purpose:
    Checks whether the API improperly handles duplicate parameters in
    query strings, form data, or request bodies.

    Threat Model:
    HTTP Parameter Pollution (HPP) occurs when multiple parameters with
    the same name are supplied in a request. Different components in the
    request processing chain (such as proxies, frameworks, or application
    logic) may interpret these parameters differently.

    For example, some systems may process the first value while others
    use the last value.

    Example request:

        /api/resource?id=123&id=999

    One layer may interpret:

        id = 123

    While another layer may interpret:

        id = 999

    If validation logic checks one value but application logic uses
    another, attackers may bypass validation or manipulate application
    behavior.

    Attack scenarios include:

        - bypassing input validation rules
        - overriding trusted parameters
        - manipulating authorization checks
        - altering business logic conditions

    Test Strategy:
    The scanner sends requests containing duplicate parameters and
    observes how the API processes them. The responses are analyzed to
    determine whether inconsistent parameter handling occurs.

    Potential Impact:
    If HTTP parameter pollution is possible, attackers may be able to:

        - bypass validation mechanisms
        - override application parameters
        - manipulate request processing
        - access unauthorized resources

    Expected Behavior:
    Applications should enforce consistent parameter parsing and reject
    requests containing duplicate or ambiguous parameters when they
    could affect security-sensitive logic.
    */
    
    private async Task<string> RunParameterPollutionTestsAsync(Uri baseUri)
    {
        var pollutedUri = baseUri + (baseUri.Query.Length == 0 ? "?" : "&") + "role=user&role=admin&isAdmin=false&isAdmin=true";
        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, pollutedUri));
        var body = await ReadBodyAsync(response);

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            body.Contains("admin", StringComparison.OrdinalIgnoreCase)
            ? "Potential risk: parameter pollution may influence role resolution."
            : "No obvious parameter pollution indicator found."
        };

        return FormatSection("Parameter Pollution", new Uri(pollutedUri), findings);
    }

}

