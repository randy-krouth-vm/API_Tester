namespace API_Tester
{
    public partial class MainPage
    {
        /*
        SQL Injection Testing Payloads

        Purpose:
        Provides payloads used to test whether the application is vulnerable
        to SQL injection attacks. These payloads simulate malicious input
        intended to manipulate SQL queries executed by the backend database.

        Threat Model:
        SQL injection occurs when user-supplied input is incorporated into
        database queries without proper validation or parameterization.
        Attackers may attempt to:

            - bypass authentication checks
            - retrieve unauthorized database records
            - modify or delete stored data
            - execute administrative database commands

        SQL injection is one of the most critical web application
        vulnerabilities and can lead to full database compromise.

        Common injection techniques include:

            - boolean-based query manipulation (e.g., ' OR '1'='1)
            - UNION-based data extraction
            - stacked queries to execute multiple statements
            - time-based queries to infer database behavior

        Test Strategy:
        The payloads returned by this method simulate several common SQL
        injection techniques:

            - "' OR '1'='1" attempts authentication bypass
            - "' UNION SELECT NULL--" attempts data extraction
            - "1; DROP TABLE users--" simulates stacked query execution
            - "' AND SLEEP(5)--" tests time-based injection behavior

        These payloads are used to determine whether the application improperly
        incorporates user input into SQL queries.

        Potential Impact:
        If SQL injection vulnerabilities exist, attackers may:

            - bypass login authentication
            - extract sensitive data from the database
            - modify or delete critical records
            - execute administrative database operations
            - fully compromise the application backend

        Expected Behavior:
        Applications should:

            - use parameterized queries or prepared statements
            - avoid dynamic SQL built from user input
            - implement strict input validation and encoding
            - apply least privilege database access
            - monitor and log suspicious database query behavior
        */
        
        private static string[] GetSqlInjectionPayloads() =>
        [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--",
            "' AND SLEEP(5)--",
            "'; EXEC xp_cmdshell('dir') --",
            "' OR 'a'='a' --",
            "admin' --",
            "1' AND 1=1 UNION SELECT username, password FROM users --",
            "1' UNION SELECT null, username, password FROM users --",
            "' OR 1=1 LIMIT 1 --",
            "' AND 1=1 --",
            "1' UNION ALL SELECT NULL, NULL, NULL --",
            "'; SELECT * FROM information_schema.tables --",
            "'; SELECT * FROM users --",
            "'; EXEC xp_cmdshell('ping 127.0.0.1') --",
            "' OR 1=1; --",
            "'; DROP DATABASE test --",
            "'; SELECT @@version --",
            "' AND 1=1 GROUP BY users HAVING COUNT(*) > 0 --",
            "admin' --"
        ];

        private async Task<string> RunSqlInjectionTestsAsync(Uri baseUri)
        {
            var payloads = GetManualPayloadsOrDefault(GetSqlInjectionPayloads(), ManualPayloadCategory.Sql);
            var findings = new List<string>();
            var suspicious = 0;

            for (var i = 0; i < payloads.Length; i++)
            {
                var probeUri = AppendQuery(baseUri, new Dictionary<string, string>
                {
                    ["id"] = payloads[i]
                });

                var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, probeUri));
                var body = await ReadBodyAsync(response);

                findings.Add($"Payload {i + 1}: HTTP {FormatStatus(response)}");
                if (ContainsAny(body, "sql", "syntax", "database", "odbc", "mysql", "postgres", "sqlite"))
                {
                    suspicious++;
                }
            }

            findings.Insert(0, $"Payload variants: {payloads.Length}");
            findings.Add(suspicious > 0
                ? $"Potential risk: SQL error indicators observed on {suspicious}/{payloads.Length} probes."
                : "No obvious SQL error leakage detected.");

            return FormatSection("SQL Injection", baseUri, findings);
        }
    }
}
