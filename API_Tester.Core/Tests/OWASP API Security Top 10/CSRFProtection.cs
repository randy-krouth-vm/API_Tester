namespace API_Tester;

public partial class MainPage
{
    /*
    Cross-Site Request Forgery (CSRF) Protection Tests

    Purpose:
    Performs automated tests to evaluate whether the application properly
    protects against Cross-Site Request Forgery (CSRF) attacks. CSRF occurs
    when a malicious site tricks a user’s browser into performing unintended
    actions on a trusted application where the user is authenticated.

    Threat Model:
    Without proper CSRF protections, attackers may cause authenticated users
    to unknowingly perform actions such as:

        - changing account settings
        - submitting transactions
        - modifying data
        - performing administrative actions

    Because browsers automatically include session cookies with requests,
    attackers can exploit authenticated sessions if CSRF defenses are missing.

    Common vulnerabilities include:

        - missing CSRF tokens on state-changing requests
        - predictable or reusable CSRF tokens
        - lack of SameSite cookie protections
        - accepting cross-origin requests without validation
        - failure to validate request origin or referrer headers

    Test Strategy:
    The method performs automated checks that:

        - attempt state-changing requests without CSRF tokens
        - analyze server responses for token validation enforcement
        - inspect cookie attributes such as SameSite and Secure flags
        - evaluate origin and referrer validation
        - detect endpoints susceptible to CSRF exploitation

    Potential Impact:
    If CSRF protections are weak, attackers may:

        - perform unauthorized actions on behalf of authenticated users
        - manipulate account data or transactions
        - compromise user trust and system integrity
        - cause financial or operational damage

    Expected Behavior:
    Applications should:

        - require unpredictable CSRF tokens for state-changing requests
        - validate tokens server-side for every request
        - use SameSite cookies where appropriate
        - verify request origin or referrer headers
        - apply CSRF protections consistently across all relevant endpoints
    */
    
    private async Task<string> RunCsrfProtectionTestsAsync(Uri baseUri)
    {
        const string payload = "{\"action\":\"transfer\",\"amount\":1}";

        var noOrigin = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            return req;
        });

        var forgedOrigin = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Headers.TryAddWithoutValidation("Origin", "https://example.invalid");
            req.Headers.TryAddWithoutValidation("Referer", "https://example.invalid/test");
            req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            return req;
        });

        var tokenMismatch = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            req.Headers.TryAddWithoutValidation("Origin", $"{baseUri.Scheme}://{baseUri.Authority}");
            req.Headers.TryAddWithoutValidation("X-CSRF-Token", "invalid-csrf-token");
            req.Content = new StringContent(payload, Encoding.UTF8, "application/json");
            return req;
        });

        var findings = new List<string>
        {
            $"No-Origin POST: {FormatStatus(noOrigin)}",
            $"Forged-Origin POST: {FormatStatus(forgedOrigin)}",
            $"Invalid-CSRF-Token POST: {FormatStatus(tokenMismatch)}"
        };

        var suspicious = new[] { noOrigin, forgedOrigin, tokenMismatch }
        .Count(r => r is not null && (int)r.StatusCode is >= 200 and < 300);
        findings.Add(suspicious >= 2
        ? "Potential risk: CSRF protections are not clearly enforced for state-changing requests."
        : "No obvious CSRF bypass indicator.");

        return FormatSection("CSRF Protection", baseUri, findings);
    }

    private static (int Attempts, int BurstSize, HttpMethod[] Methods) GetRateLimitPlan(string? testKey)
    {
        var key = testKey?.Trim().ToUpperInvariant() ?? string.Empty;
        return key switch
        {
            "API4" or "N53SC5" or "FFIECDDOS" or "ZT207CDM" => (16, 4, [HttpMethod.Get, HttpMethod.Get, HttpMethod.Post]),
            "N61CONTAIN" or "CARTARISK" => (12, 3, [HttpMethod.Get, HttpMethod.Post]),
            _ => (6, 2, [HttpMethod.Get])
        };
    }

    private static IReadOnlyList<AuthProbeRequest> BuildAuthProbeRequests(Uri baseUri, string? testKey)
    {
        var key = testKey?.Trim().ToUpperInvariant() ?? string.Empty;
        var probes = new List<AuthProbeRequest>
        {
            new("Unauthenticated GET", () => new HttpRequestMessage(HttpMethod.Get, baseUri)),
            new("Forged role headers", () =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
                req.Headers.TryAddWithoutValidation("X-Role", "admin");
                req.Headers.TryAddWithoutValidation("X-User-Type", "superuser");
                return req;
            }),
            new("Invalid bearer token", () =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
                req.Headers.TryAddWithoutValidation("Authorization", "Bearer invalid.apitester.token");
                return req;
            })
        };

        if (key is "N63AAL" or "N53IA2" or "ASVSV2" or "MASVSAUTH")
        {
            probes.Add(new AuthProbeRequest("Weak basic credentials", () =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
                var weak = Convert.ToBase64String(Encoding.UTF8.GetBytes("admin:admin"));
                req.Headers.TryAddWithoutValidation("Authorization", $"Basic {weak}");
                return req;
            }));
        }

        if (key is "API5" or "N53AC6" or "MITRET1078")
        {
            probes.Add(new AuthProbeRequest("Privilege claim override", () =>
            {
                var req = new HttpRequestMessage(HttpMethod.Get, baseUri);
                req.Headers.TryAddWithoutValidation("X-Permissions", "all");
                req.Headers.TryAddWithoutValidation("X-Scope", "admin:*");
                return req;
            }));
        }

        return probes;
    }

    private static IReadOnlyList<string> BuildCommandJsonBodies(string payload, IReadOnlyList<string> bodyFields)
    {
        var primaryField = bodyFields.FirstOrDefault() ?? "cmd";
        var secondaryField = bodyFields.Skip(1).FirstOrDefault() ?? "action";

        var variants = new List<string>
        {
            JsonSerializer.Serialize(new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                [primaryField] = payload
            }),
            JsonSerializer.Serialize(new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
            {
                [primaryField] = payload,
                ["args"] = new[] { payload }
            }),
            JsonSerializer.Serialize(new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase)
            {
                [secondaryField] = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                {
                    ["value"] = payload
                }
            })
        };

        return variants;
    }
}

