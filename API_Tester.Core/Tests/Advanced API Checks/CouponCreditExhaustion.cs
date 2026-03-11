namespace API_Tester;

public partial class MainPage
{
    /*
    Coupon / Credit Exhaustion Payloads

    Purpose:
    Provides test inputs used to detect potential abuse of promotional credit
    or coupon systems within an API.

    Threat Model:
    Applications that implement coupons, promotional credits, or referral
    rewards may allow attackers to repeatedly apply or manipulate these
    values in order to gain unlimited discounts or system credits.

    If validation logic is weak, attackers may attempt to:

        - reuse single-use coupon codes
        - apply multiple coupons to the same transaction
        - submit extremely large credit values
        - send negative values to manipulate balance calculations
        - repeatedly redeem promotional codes

    Test Strategy:
    These payloads simulate common abuse patterns by submitting various
    coupon codes, credit values, and edge-case inputs that may reveal
    logic flaws in discount or credit handling mechanisms.

    Potential Impact:
    If protections are missing, attackers may be able to:

        - generate unlimited discounts
        - drain promotional credit pools
        - bypass payment requirements
        - manipulate account balances

    Expected Behavior:
    Applications should enforce strict validation including:

        - single-use coupon enforcement
        - rate limiting for coupon redemption
        - server-side validation of credit values
        - transaction integrity checks
    */
    
    private static string[] GetCouponCreditExhaustionPayloads() =>
    [
        "{\"coupon\":\"WELCOME100\",\"amount\":-1000,\"quantity\":-1}",
        "{\"coupon\":\"WELCOME100\",\"amount\":0.0000001,\"quantity\":999999}",
        "{\"coupon\":\"WELCOME100\",\"amount\":0,\"applyCount\":100}"
    ];

    private HttpRequestMessage FormatCouponCreditExhaustionRequest(Uri baseUri, string payload)
    {
        var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
        req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
        return req;
    }

    private async Task<string> RunCouponCreditExhaustionTestsAsync(Uri baseUri)
    {
        var payloads = GetCouponCreditExhaustionPayloads();

        var findings = new List<string>();
        foreach (var payload in payloads)
        {
            var response = await SafeSendAsync(() => FormatCouponCreditExhaustionRequest(baseUri, payload));

            findings.Add($"{payload}: {FormatStatus(response)}");
        }

        return FormatSection("Coupon/Credit Exhaustion", baseUri, findings);
    }

}

