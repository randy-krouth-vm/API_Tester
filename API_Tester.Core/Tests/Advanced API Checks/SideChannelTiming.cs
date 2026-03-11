namespace API_Tester;

public partial class MainPage
{
    /*
    Side Channel Timing Test

    Purpose:
    Checks whether the API leaks sensitive information through measurable
    differences in response timing.

    Threat Model:
    Side-channel timing vulnerabilities occur when an application takes
    different amounts of time to process requests depending on secret
    values such as authentication tokens, passwords, API keys, or
    cryptographic comparisons.

    If operations such as string comparison or authentication validation
    are implemented using non-constant-time logic, attackers may measure
    response times to infer secret data one character at a time.

    Attack scenarios include:

        - brute forcing API keys through timing differences
        - extracting authentication tokens character-by-character
        - discovering valid usernames during login checks
        - exploiting timing differences in cryptographic validation

    Example pattern:

        Request with incorrect token prefix → fast rejection
        Request with correct prefix → slightly longer processing time

    Repeated measurements may reveal how much of a secret value is correct 
    because characters are processed per character and can reveal a longer
    timeframe when comparing more characters.

    Test Strategy:
    The scanner sends multiple requests with varying inputs and measures
    response timing patterns to determine whether consistent timing
    differences occur that could indicate information leakage.

    Solution:
    Use constant-time comparisons when validating secrets
    such as API keys, tokens, signatures, or password hashes.

    Example (.NET):
    CryptographicOperations.FixedTimeEquals()

    Avoid direct equality comparisons such as ==, string.Equals(),
    or SequenceEqual() when verifying secret values, as they may
    exit early and leak timing information.

    Security-sensitive comparisons should use constant-time
    operations so execution time does not vary based on how
    much of the secret value matches.

    Additionally:
    • normalize authentication error responses
    • implement rate limiting on authentication endpoints
    • rely on established cryptographic libraries for validation

    Potential Impact:
    If timing side channels are present, attackers may be able to:

        - recover authentication secrets
        - brute force tokens more efficiently
        - enumerate valid user identifiers
        - weaken cryptographic validation mechanisms

    Expected Behavior:
    Security-sensitive comparisons should be implemented using
    constant-time operations and authentication responses should avoid
    revealing differences in processing time that depend on secret values.
    */

    private async Task<string> RunSideChannelTimingTestsAsync(Uri baseUri)
    {
        static async Task<double> MeasureMs(Func<Task<HttpResponseMessage?>> send)
        {
            var start = DateTime.UtcNow;
            await send();
            return (DateTime.UtcNow - start).TotalMilliseconds;
        }

        var knownLike = new List<double>();
        var unknownLike = new List<double>();

        for (var i = 0; i < 5; i++)
        {
            knownLike.Add(await MeasureMs(() => SafeSendAsync(() =>
            {
                var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
                req.Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["username"] = "admin",
                    ["password"] = "wrong-password"
                });
                return req;
            })));

            unknownLike.Add(await MeasureMs(() => SafeSendAsync(() =>
            {
                var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
                req.Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["username"] = "user-does-not-exist",
                    ["password"] = "wrong-password"
                });
                return req;
            })));
        }

        var avgKnown = knownLike.Average();
        var avgUnknown = unknownLike.Average();
        var delta = Math.Abs(avgKnown - avgUnknown);

        var findings = new List<string>
        {
            $"Avg known-like username: {avgKnown:F1} ms",
            $"Avg unknown-like username: {avgUnknown:F1} ms",
            $"Timing delta: {delta:F1} ms",
            delta > 120
            ? "Potential risk: response timing differential may leak account existence."
            : "No strong timing differential detected in this sample."
        };

        return FormatSection("Side-Channel Timing", baseUri, findings);
    }

}

