namespace API_Tester;

public partial class MainPage
{
    /*
    Workflow TOCTOU Race Condition Test

    Purpose:
    Checks whether the application is vulnerable to Time-of-Check to
    Time-of-Use (TOCTOU) race conditions within workflow or business
    logic operations.

    Threat Model:
    A TOCTOU vulnerability occurs when an application checks a condition
    (such as permissions, balance, or workflow state) and then performs
    an action later without ensuring that the checked condition remains
    valid.

    If multiple requests are processed concurrently, attackers may exploit
    the timing gap between the check and the action to bypass controls.

    Example scenario:

        1. Server checks if account balance >= withdrawal amount.
        2. Server approves the transaction.
        3. Multiple withdrawal requests are sent simultaneously.
        4. Each request passes the balance check before the balance is updated.

    This may allow the attacker to withdraw more funds than the account
    actually contains.

    Attack scenarios include:

        - performing duplicate financial transactions
        - redeeming the same coupon or credit multiple times
        - executing multiple workflow transitions simultaneously
        - bypassing usage limits or quotas

    Example race pattern:

        Request A → check balance → OK
        Request B → check balance → OK
        Request A → deduct balance
        Request B → deduct balance

    Both succeed even though only one should.

    Test Strategy:
    The scanner sends multiple concurrent requests targeting the same
    workflow operation and observes whether duplicate or inconsistent
    state changes occur.

    Potential Impact:
    If TOCTOU race conditions are exploitable, attackers may be able to:

        - perform duplicate transactions
        - bypass resource limits
        - manipulate business logic
        - create inconsistent system state

    Expected Behavior:
    Applications should enforce atomic operations using database
    transactions, locking mechanisms, or idempotency controls so that
    state checks and updates occur as a single indivisible operation.
    */
    
    private async Task<string> RunWorkflowToctouRaceTestsAsync(Uri baseUri)
    {
        var actionUri = new Uri(baseUri, "/execute");
        var tasks = Enumerable.Range(0, 10)
        .Select(_ => SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, actionUri);
            req.Content = new StringContent("{\"id\":\"12345\",\"action\":\"execute\"}", Encoding.UTF8, "application/json");
            return req;
        }))
        .ToArray();

        var responses = await Task.WhenAll(tasks);
        var success = responses.Count(r => r is not null && (int)r.StatusCode is >= 200 and < 300);

        var findings = new List<string>
        {
            "Concurrent execution attempts: 10",
            $"2xx responses: {success}",
            success > 1
            ? "Potential risk: TOCTOU/state race acceptance indicated by multiple successes."
            : "No obvious TOCTOU multi-success indicator."
        };

        return FormatSection("TOCTOU State Race", actionUri, findings);
    }

}

