namespace API_Tester;

public partial class MainPage
{
    /*
    Race Condition Replay Test

    Purpose:
    Checks whether the API is vulnerable to race condition attacks where
    multiple concurrent requests manipulate the same resource or operation
    before the system properly enforces state changes.

    Threat Model:
    Race conditions occur when an application processes multiple requests
    simultaneously without proper locking, atomic operations, or transaction
    controls. Attackers may exploit timing gaps between validation and
    execution to perform actions multiple times.

    Replay-style race attacks typically involve sending many identical
    requests in parallel to trigger unintended duplicate processing.

    Attack scenarios include:

        - submitting multiple payment or credit requests simultaneously
        - triggering duplicate transactions before balances update
        - repeatedly redeeming coupons or discounts
        - exploiting "check-then-act" logic flaws

    Example scenario:

        1. API checks account balance or token validity.
        2. Multiple concurrent requests pass the validation check.
        3. Each request executes the action before the state updates.

    If synchronization controls are missing, the action may be processed
    multiple times.

    Test Strategy:
    The scanner sends multiple concurrent requests targeting the same
    endpoint or action and observes whether duplicate operations succeed
    or inconsistent responses occur.

    Potential Impact:
    If race conditions are exploitable, attackers may be able to:

        - perform duplicate financial transactions
        - bypass usage limits or quotas
        - redeem resources multiple times
        - manipulate application state inconsistently

    Expected Behavior:
    Applications should enforce atomic operations, proper transaction
    handling, and concurrency controls to ensure that repeated or
    simultaneous requests cannot cause unintended duplicate actions.
    */
    
    private async Task<string> RunRaceConditionReplayTestsAsync(Uri baseUri)
    {
        const int parallelRequests = 8;
        const string payload = "{\"operation\":\"race-probe\",\"amount\":1}";
        var tasks = Enumerable.Range(0, parallelRequests)
        .Select(_ => SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            return req;
        }))
        .ToArray();

        var responses = await Task.WhenAll(tasks);
        var successCount = responses.Count(r => r is not null && (int)r.StatusCode is >= 200 and < 300);
        var findings = new List<string>
        {
            $"Parallel requests sent: {parallelRequests}",
            $"Successful responses (2xx): {successCount}",
            successCount > 1
            ? "Potential risk: concurrent duplicate operation acceptance detected."
            : "No obvious race/replay acceptance indicator."
        };

        return FormatSection("Race Condition Replay", baseUri, findings);
    }

}

