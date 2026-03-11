namespace API_Tester;

public partial class MainPage
{
    /*
    Double Spend / TOCTOU (Time-of-Check to Time-of-Use) Test

    Purpose:
    Detects whether the application is vulnerable to race conditions that allow
    the same transaction, credit, or resource to be used multiple times.

    Threat Model:
    A TOCTOU vulnerability occurs when a system checks a condition (such as
    account balance or coupon validity) and then performs an action based on
    that check, but does not ensure the state remains unchanged between the
    check and the operation.

    Attackers may exploit this by sending multiple concurrent requests that
    attempt to perform the same operation simultaneously, such as:

        - redeeming the same coupon multiple times
        - withdrawing funds multiple times
        - placing duplicate orders
        - spending the same balance repeatedly

    If the system processes these requests concurrently without proper locking
    or transactional safeguards, it may allow multiple operations to succeed.

    Test Strategy:
    The scanner sends multiple parallel requests to the same endpoint to
    simulate concurrent transactions and observes whether the server accepts
    more than one request that should normally be processed only once.

    Potential Impact:
    Successful exploitation may allow attackers to:

        - duplicate payments or withdrawals
        - bypass transaction limits
        - redeem single-use credits multiple times
        - manipulate financial or inventory systems

    Expected Behavior:
    Applications should enforce atomic operations, database transactions,
    or locking mechanisms to ensure that critical operations cannot be
    executed multiple times concurrently.
    */

    private async Task<string> RunDoubleSpendToctouTestsAsync(Uri baseUri)
    {
        var endpoints = new[] { new Uri(baseUri, "/checkout"), new Uri(baseUri, "/withdraw") };
        var findings = new List<string>();

        foreach (var endpoint in endpoints)
        {
            var tasks = Enumerable.Range(0, 12).Select(_ => SafeSendAsync(() =>
            {
                var req = new HttpRequestMessage(HttpMethod.Post, endpoint);
                req.Content = new StringContent("{\"amount\":100,\"currency\":\"USD\",\"id\":\"tx-1001\"}", Encoding.UTF8, "application/json");
                return req;
            })).ToArray();

            var responses = await Task.WhenAll(tasks);
            var success = responses.Count(r => r is not null && (int)r.StatusCode is >= 200 and < 300);
            findings.Add($"{endpoint.AbsolutePath}: 2xx responses={success}/12");
            if (success > 1)
            {
                findings.Add($"Potential risk: possible double-spend acceptance on {endpoint.AbsolutePath}.");
            }
        }

        return FormatSection("Double-Spend TOCTOU", baseUri, findings);
    }

}

