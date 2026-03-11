namespace API_Tester;

public partial class MainPage
{
    /*
    Server-Side Template Injection (SSTI) Probe Test

    Purpose:
    Checks whether the application is vulnerable to Server-Side Template
    Injection (SSTI), where user-controlled input is interpreted and
    executed inside a server-side template engine.

    Threat Model:
    Many web frameworks use template engines to generate dynamic content.
    Examples include engines used in frameworks like Razor, Jinja2,
    Twig, Handlebars, or Freemarker.

    If user input is inserted directly into a template without proper
    sanitization or escaping, the template engine may evaluate the input
    as template code rather than treating it as plain text.

    Attackers can inject template expressions that the server evaluates
    during rendering.

    Example payloads may include expressions such as:

        {{7*7}}
        ${7*7}
        <%= 7*7 %>

    If the server evaluates these expressions and returns "49", it may
    indicate that template expressions are being executed.

    Attack scenarios include:

        - executing arbitrary code through the template engine
        - accessing server environment variables
        - reading application configuration or secrets
        - achieving remote code execution in severe cases

    Test Strategy:
    The scanner sends common template expression payloads to input
    parameters and observes whether the application evaluates them
    instead of rendering them as literal text.

    Potential Impact:
    If SSTI is present, attackers may be able to:

        - execute arbitrary commands on the server
        - access sensitive environment variables or secrets
        - retrieve application configuration files
        - fully compromise the application server

    Expected Behavior:
    Applications should treat user input as data only and should not
    evaluate or render user-controlled content as part of a template.
    Template engines should be configured with proper escaping and
    sandboxing where applicable.
    */

    private async Task<string> RunSstiProbeTestsAsync(Uri baseUri)
    {
        var testUri = AppendQuery(baseUri, new Dictionary<string, string>
        {
            ["q"] = "{{7*7}}",
            ["name"] = "${7*7}"
        });

        var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, testUri));
        var body = await ReadBodyAsync(response);

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            body.Contains("49", StringComparison.OrdinalIgnoreCase) &&
            !body.Contains("{{7*7}}", StringComparison.OrdinalIgnoreCase)
            ? "Potential risk: template expression appears evaluated."
            : "No obvious template-expression execution indicator."
        };

        return FormatSection("SSTI Probe", testUri, findings);
    }

}

