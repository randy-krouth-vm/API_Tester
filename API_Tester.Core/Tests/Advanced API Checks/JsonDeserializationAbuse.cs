namespace API_Tester;

public partial class MainPage
{
    /*
    JSON Deserialization Abuse Test

    Purpose:
    Checks whether the API safely handles JSON deserialization and whether
    user-supplied JSON data can trigger unsafe object creation or execution.

    Threat Model:
    Many frameworks automatically convert JSON request bodies into objects
    through deserialization. If deserialization settings allow type
    resolution or dynamic object creation based on user input, attackers
    may be able to manipulate the JSON payload to instantiate unexpected
    classes or trigger unsafe behavior.

    Risk scenarios include:

        - polymorphic type injection
        - unsafe deserialization settings
        - automatic binding to privileged object types
        - triggering dangerous constructors or setters

    Test Strategy:
    The scanner submits crafted JSON payloads that attempt to manipulate
    deserialization behavior, such as injecting unexpected properties or
    type indicators. It observes whether the server processes the request
    normally, returns errors, or behaves unexpectedly.

    Potential Impact:
    If deserialization protections are weak, attackers may be able to:

        - manipulate server-side object state
        - bypass validation logic
        - trigger application errors or crashes
        - potentially achieve remote code execution in vulnerable
        deserialization frameworks

    Expected Behavior:
    Applications should use strict deserialization settings, disable
    dangerous features such as arbitrary type resolution, and validate
    incoming JSON structures before binding them to application objects.
    */
    
    private async Task<string> RunJsonDeserializationAbuseTestsAsync(Uri baseUri)
    {
        const string payload = "{\"$type\":\"System.Diagnostics.Process, System\",\"StartInfo\":{\"FileName\":\"calc.exe\"}}";
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            return req;
        });
        var body = await ReadBodyAsync(response);

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            ContainsAny(body, "$type", "System.", "deserial", "serialization")
            ? "Deserializer behavior markers detected (review required)."
            : "No obvious unsafe deserialization indicator."
        };

        return FormatSection("JSON Deserialization Abuse", baseUri, findings);
    }

}

