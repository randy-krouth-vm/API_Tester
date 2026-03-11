namespace API_Tester;

public partial class MainPage
{
    /*
    Numerical Overflow / Underflow Payloads

    Purpose:
    Defines payloads used to test how an API handles extremely large,
    extremely small, or otherwise abnormal numeric values.

    Threat Model:
    Applications that process numeric inputs such as counters, balances,
    IDs, quantities, or timestamps may be vulnerable to integer overflow,
    integer underflow, or floating-point precision issues if proper
    validation is not enforced.

    Overflow occurs when a numeric value exceeds the maximum value that the
    data type can represent. Underflow occurs when a value drops below the
    minimum representable value. In some programming environments this may
    cause values to wrap around, truncate, or produce unexpected results.

    Attack scenarios include:

        - submitting values larger than 32-bit or 64-bit integer limits
        - sending negative values where only positive values are expected
        - forcing wraparound in counters or balance calculations
        - triggering parsing errors or crashes through extreme numbers

    Test Strategy:
    These payload values represent boundary conditions and abnormal numeric
    inputs that are commonly used to test numeric validation logic. The
    scanner submits them in parameters or request bodies that accept numeric
    data and observes how the server processes them.

    Potential Impact:
    If numeric limits are not properly enforced, attackers may be able to:

        - manipulate counters or financial values
        - bypass validation rules
        - cause unexpected application behavior
        - trigger crashes or denial-of-service conditions

    Expected Behavior:
    Applications should validate numeric inputs against strict bounds,
    reject values outside allowed ranges, and ensure that arithmetic
    operations cannot overflow or underflow.
    */
    
    private static string[] GetNumericalOverflowUnderflowPayloads() =>
    [
        "{\"amount\":-1,\"quantity\":-999999}",
        "{\"amount\":9223372036854775807,\"quantity\":2147483647}",
        "{\"amount\":-9223372036854775808,\"quantity\":-2147483648}",
        "{\"amount\":2147483648,\"quantity\":-2147483649}",
        "{\"amount\":-2147483649,\"quantity\":2147483648}",
        "{\"amount\":10000000000,\"quantity\":-5000000000}",
        "{\"amount\":-10000000000,\"quantity\":5000000000}",
        "{\"amount\":1073741824,\"quantity\":1073741824}",
        "{\"amount\":-1073741824,\"quantity\":-1073741824}",
        "{\"amount\":1234567890123456789,\"quantity\":-9876543210}",
        "{\"amount\":-1234567890123456789,\"quantity\":9876543210}",
        "{\"amount\":10000000000000000000,\"quantity\":-10000000000000000000}"
    ];

    private HttpRequestMessage FormatNumericalOverflowUnderflowRequest(Uri baseUri, string payload)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
        req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
        return req;
    }

    private async Task<string> RunNumericalOverflowUnderflowTestsAsync(Uri baseUri)
    {
        var payloads = GetNumericalOverflowUnderflowPayloads();

        var findings = new List<string>();
        foreach (var payload in payloads)
        {
            var response = await SafeSendAsync(() => FormatNumericalOverflowUnderflowRequest(baseUri, payload));
            findings.Add($"{payload}: {FormatStatus(response)}");
        }

        return FormatSection("Numerical Overflow/Underflow", baseUri, findings);
    }

}

