namespace API_Tester
{
    public partial class MainPage
    {
        /*
        NoSQL Injection Testing Payloads

        Purpose:
        Provides payloads used to test whether the application is vulnerable
        to NoSQL injection attacks. These payloads simulate malicious inputs
        designed to manipulate NoSQL database queries.

        Threat Model:
        NoSQL injection occurs when user-supplied input is improperly handled
        and incorporated into database queries without proper validation or
        sanitization. Attackers may attempt to:

            - bypass authentication checks
            - retrieve unauthorized records
            - modify or delete database entries
            - execute arbitrary database operations

        NoSQL databases such as MongoDB often use JSON-like query structures.
        If applications directly incorporate user input into these structures,
        attackers can inject operators or query logic.

        Common injection techniques include:

            - using comparison operators (e.g., $ne, $gt, $lt)
            - manipulating logical conditions
            - altering query structures with crafted JSON objects
            - bypassing authentication queries

        Test Strategy:
        The payloads returned by this method simulate common NoSQL injection
        attempts. They are used to determine whether the application improperly
        interprets malicious input as part of database query logic.

        Potential Impact:
        If NoSQL injection vulnerabilities exist, attackers may:

            - bypass login or authentication checks
            - retrieve sensitive database records
            - modify or delete stored data
            - compromise application integrity

        Expected Behavior:
        Applications should:

            - validate and sanitize all user input
            - avoid constructing database queries directly from user input
            - use parameterized queries or safe query builders
            - enforce strict schema validation
            - monitor and log suspicious query behavior
        */

        private static string[] GetNoSqlInjectionPayloads() =>
        [
            "{\"username\":{\"$ne\":null},\"password\":{\"$ne\":null}}",
            "{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}",
            "{\"$where\":\"this.password && this.password.length > 0\"}",
            "{\"username\":\"admin\",\"password\":{\"$regex\":\".*\"}}"
        ];

        private async Task<string> RunNoSqlInjectionTestsAsync(Uri baseUri)
        {
            var payloads = GetManualPayloadsOrDefault(GetNoSqlInjectionPayloads(), ManualPayloadCategory.NoSql);
            var findings = new List<string>();
            var accepted = 0;

            for (var i = 0; i < payloads.Length; i++)
            {
                var payload = payloads[i];
                var response = await SafeSendAsync(() =>
                {
                    var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
                    req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
                    return req;
                });

                findings.Add($"Payload {i + 1}: HTTP {FormatStatus(response)}");
                if (response is not null && (int)response.StatusCode is >= 200 and < 300)
                {
                    accepted++;
                }
            }

            findings.Insert(0, $"Payload variants: {payloads.Length}");
            findings.Add(accepted > 0
                ? $"Potential risk: NoSQL-style payloads accepted on {accepted}/{payloads.Length} probes."
                : "No obvious NoSQL injection acceptance from tested payloads.");

            return FormatSection("NoSQL Injection", baseUri, findings);
        }
    }
}
