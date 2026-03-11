namespace API_Tester;

public partial class MainPage
{
    /*
    Idempotency Replay Test

    Purpose:
    Checks whether API endpoints correctly handle repeated requests that
    should only be processed once, particularly for operations that modify
    state such as payments, orders, or account updates.

    Threat Model:
    Some APIs use idempotency keys or transaction identifiers to ensure
    that duplicate requests do not cause the same operation to execute
    multiple times. If idempotency protections are missing or improperly
    implemented, attackers or network retries may cause the same action
    to be processed repeatedly.

    Test Strategy:
    The scanner sends multiple identical requests to the same endpoint,
    sometimes including repeated idempotency keys or request identifiers.
    It observes whether the server processes each request independently
    or correctly treats duplicates as the same operation.

    Potential Impact:
    If replay protection is not enforced, attackers may be able to:

        - execute duplicate financial transactions
        - create multiple orders from one request
        - repeatedly trigger sensitive operations
        - exploit race conditions in transaction processing

    Expected Behavior:
    APIs that perform sensitive or state-changing operations should
    implement idempotency controls, such as idempotency keys, transaction
    IDs, or server-side deduplication logic, to ensure that repeated
    requests do not cause duplicate actions.
    */
    
    private async Task<string> RunIdempotencyReplayTestsAsync(Uri baseUri)
    {
        var payload = "{\"amount\":100,\"currency\":\"USD\"}";
        const string key = "api-tester-idempotency-key";

        var first = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Headers.TryAddWithoutValidation("Idempotency-Key", key);
            req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            return req;
        });

        var second = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Headers.TryAddWithoutValidation("Idempotency-Key", key);
            req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            return req;
        });

        var findings = new List<string>
        {
            $"First request: {FormatStatus(first)}",
            $"Replay request: {FormatStatus(second)}"
        };

        if (first is not null && second is not null && first.StatusCode == second.StatusCode && first.StatusCode == HttpStatusCode.OK)
        {
            findings.Add("Potential risk: replay with same idempotency key not differentiated.");
        }
        else
        {
            findings.Add("No obvious replay acceptance indicator.");
        }

        return FormatSection("Idempotency Replay", baseUri, findings);
    }

}

