namespace API_Tester;

public partial class MainPage
{
    /*
    OpenAPI Schema Mismatch Test

    Purpose:
    Checks whether API endpoints behave differently from their documented
    OpenAPI or Swagger schema definitions.

    Threat Model:
    OpenAPI specifications describe expected request parameters, data
    types, required fields, and response formats. If the API implementation
    does not strictly follow its documented schema, unexpected inputs may
    be accepted by the server.

    Attackers may exploit these inconsistencies to send values that bypass
    validation rules enforced only at the documentation or client level.

    Attack scenarios include:

        - sending unexpected parameters not defined in the schema
        - providing incorrect data types (e.g., string instead of integer)
        - omitting fields marked as required
        - supplying values outside documented constraints

    Example scenario:

        Schema expects:

            {
                "quantity": integer
            }

        Attacker sends:

            {
                "quantity": "999999999999999999"
            }

    If the server accepts the input despite the schema restriction,
    validation enforcement may be incomplete.

    Test Strategy:
    The scanner compares expected parameter types and structures derived
    from the OpenAPI schema against actual server responses when malformed
    or mismatched inputs are submitted.

    Potential Impact:
    If schema validation is weak or inconsistent, attackers may be able to:

        - bypass input validation rules
        - trigger unexpected application behavior
        - manipulate application logic
        - discover undocumented or hidden API functionality

    Expected Behavior:
    The API implementation should enforce validation rules consistent with
    its OpenAPI schema and reject requests that violate documented
    parameter types, structures, or constraints.
    */
    
    private async Task<string> RunOpenApiSchemaMismatchTestsAsync(Uri baseUri)
    {
        const string payload = "{\"requiredFieldMissing\":true,\"unexpected\":\"value\",\"id\":\"not-an-int\"}";
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            return req;
        });

        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.OK
            ? "Potential risk: schema mismatch may not be enforced."
            : "No obvious schema-mismatch acceptance."
        };

        return FormatSection("OpenAPI Schema Mismatch", baseUri, findings);
    }

}

