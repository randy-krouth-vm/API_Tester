using System.Security.Cryptography;
using System.Text;

namespace ApiTester.Core;

public static class AuditResultUtilities
{
    public static bool IsSignalOnlyKey(string testKey)
    {
        var key = testKey?.Trim().ToUpperInvariant() ?? string.Empty;
        return key is
            "SMUGGLESIGNAL" or "DESYNCCLTE" or "DESYNCTECL" or "DESYNCDCL" or "HTTP2DOWNGRADE" or
            "TIMINGLEAK" or "DNSREBIND" or "SUBTAKEOVER" or "PORTFINGER" or "MOBILEPINNING" or
            "DOMXSSSIG" or "SCRIPTSUPPLY";
    }

    public static string DetermineVerdict(string testKey, string output, bool hadException)
    {
        if (hadException)
        {
            return "inconclusive";
        }

        var findings = ExtractFindingLines(output);
        if (findings.Count == 0)
        {
            return "inconclusive";
        }

        if (findings.Any(f => f.StartsWith("Potential risk:", StringComparison.OrdinalIgnoreCase) ||
                              f.StartsWith("Potential issue:", StringComparison.OrdinalIgnoreCase) ||
                              f.Contains("vulnerable", StringComparison.OrdinalIgnoreCase) ||
                              f.Contains("injection succeeded", StringComparison.OrdinalIgnoreCase)))
        {
            return "fail";
        }

        if (findings.Any(f => f.StartsWith("Execution error:", StringComparison.OrdinalIgnoreCase) ||
                              f.Contains("no response", StringComparison.OrdinalIgnoreCase) ||
                              f.Contains("timed out", StringComparison.OrdinalIgnoreCase) ||
                              f.Contains("unavailable", StringComparison.OrdinalIgnoreCase)))
        {
            return "inconclusive";
        }

        static bool IsExplicitPassLine(string line)
        {
            var text = line.Trim();
            if (string.IsNullOrWhiteSpace(text))
            {
                return false;
            }

            if (text.StartsWith("No ", StringComparison.OrdinalIgnoreCase) &&
                (text.Contains("detected", StringComparison.OrdinalIgnoreCase) ||
                 text.Contains("observed", StringComparison.OrdinalIgnoreCase) ||
                 text.Contains("found", StringComparison.OrdinalIgnoreCase)))
            {
                return !(text.Contains("no response", StringComparison.OrdinalIgnoreCase) ||
                         text.Contains("timed out", StringComparison.OrdinalIgnoreCase) ||
                         text.Contains("unavailable", StringComparison.OrdinalIgnoreCase));
            }

            return text.Contains("not accepted", StringComparison.OrdinalIgnoreCase) ||
                   text.Contains("present", StringComparison.OrdinalIgnoreCase) ||
                   text.Contains("enforced", StringComparison.OrdinalIgnoreCase) ||
                   text.Contains("secure", StringComparison.OrdinalIgnoreCase) ||
                   text.Contains("protected", StringComparison.OrdinalIgnoreCase);
        }

        if (IsSignalOnlyKey(testKey))
        {
            return "inconclusive";
        }

        return findings.Any(IsExplicitPassLine) ? "pass" : "inconclusive";
    }

    public static string BuildResultSummary(string output)
    {
        if (string.IsNullOrWhiteSpace(output))
        {
            return "No output generated.";
        }

        var lines = output
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(l => !l.StartsWith("[", StringComparison.Ordinal) && !l.StartsWith("Target:", StringComparison.OrdinalIgnoreCase))
            .Take(3);
        return string.Join(" | ", lines);
    }

    public static string GetRemediationGuidance(string testKey)
    {
        var key = testKey?.Trim().ToUpperInvariant() ?? string.Empty;
        return key switch
        {
            "API1" or "BOLA" or "ASVSV4" or "N53AC3" or "CMMCAC" or "N171AC" =>
                "Enforce object-level authorization on every resource lookup and deny-by-default across all object identifiers.",
            "FORCEDBROWSE" =>
                "Deny direct access to administrative/internal routes by default and enforce centralized authorization on every protected endpoint.",
            "API2" or "AUTH" or "N53IA2" or "CMMCIA" or "N171IA" =>
                "Harden authentication: MFA where applicable, secure session handling, lockout/rate limiting, and strong token validation.",
            "CSRFPROTECT" =>
                "Enforce anti-CSRF protections on all state-changing requests (token + origin/referer validation + SameSite cookies).",
            "NOSQLI" =>
                "Treat user input as data only: enforce strict schema/type validation, disallow query operators in untrusted fields, and parameterize database queries.",
            "TYPECONF" =>
                "Enforce strict JSON schema/type validation and reject coercion of strings/arrays/objects into privileged numeric or boolean fields.",
            "PARAMSHADOW" =>
                "Canonicalize duplicate parameter handling and enforce single authoritative value semantics before validation and authorization.",
            "JSONSMUGGLE" =>
                "Normalize JSON keys (case/whitespace/Unicode), reject duplicate or ambiguous keys, and enforce strict schema deserialization.",
            "AUTHHEADEROVR" =>
                "Never trust client-supplied identity headers without authenticated gateway guarantees; bind identity to validated tokens/session only.",
            "TENANTLEAK" =>
                "Enforce tenant scoping and ownership checks on every object lookup, including indirect references and pagination paths.",
            "ASYNCJOBINJ" =>
                "Authorize and validate job/task parameters server-side; constrain allowable job types and protect queue consumers from user-controlled actions.",
            "FILEPARSERABUSE" =>
                "Perform strict MIME/content sniffing, sandbox parsers, block active content (SVG/script), and sanitize archive extraction paths.",
            "VERSIONFALLBACK" =>
                "Disable deprecated API versions, require equivalent authz controls across versions, and enforce version-aware contract tests.",
            "CACHEKEYCONF" =>
                "Harden cache key normalization and ignore untrusted forwarding headers for cache decisions on sensitive responses.",
            "API4" or "RATELIMIT" or "N53SC5" or "MITRET1110" =>
                "Implement per-identity and per-IP throttling, request budget controls, and abuse detection with backoff and blocking.",
            "API7" or "SSRF" or "SSRFENCODED" or "IMDSV2" =>
                "Apply strict outbound allowlists, block link-local/internal metadata access, and normalize/validate URL parsers.",
            "TRANSPORT" or "TLSPOSTURE" or "N53SC8" or "N171SC" or "FEDRAMPSC" =>
                "Enforce modern TLS, disable weak ciphers/protocols, validate certificate chains, and apply HSTS where relevant.",
            "N53AU2" or "N53AU9" or "N53AU12" or "CMMCAU" or "N171AU" =>
                "Generate security-relevant audit events, protect logs from tampering, and centralize retention with integrity controls.",
            "N53CM6" or "N53CM7" or "CMMCCM" or "N171CM" =>
                "Baseline secure configuration, remove unnecessary functionality, and enforce configuration drift monitoring.",
            "ASVSV6" or "ISO27002824" =>
                "Use approved cryptographic primitives, rotate keys, protect key material, and avoid custom crypto.",
            "ASVSV7" or "ERROR" or "LOGPOISON" =>
                "Return generic client errors, prevent stack trace leakage, and sanitize log entries to prevent injection.",
            "ASVSV13" or "OPENAPIMISMATCH" =>
                "Validate requests/responses against API schema, reject unknown fields, and keep OpenAPI docs/version inventory current.",
            "SOC2CC8" or "SDLVERIFY" or "SAMMVERIFY" =>
                "Require change approval, testing evidence, and security gates in CI/CD before deployment.",
            _ => "Review the mapped specification/CWE and implement compensating controls, validation, and monitoring for this finding."
        };
    }

    public static (double Score, string Severity, string Vector) GetCvssForResult(string testKey, string verdict)
    {
        if (!string.Equals(verdict, "fail", StringComparison.OrdinalIgnoreCase))
        {
            return (0.0, "None", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
        }

        var key = testKey?.Trim().ToUpperInvariant() ?? string.Empty;
        return key switch
        {
            "API1" or "BOLA" or "API5" or "PRIVESC" => (9.1, "Critical", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:L"),
            "API3" or "MASSASSIGN" => (8.6, "High", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L"),
            "API2" or "N53IA2" or "CMMCIA" => (8.1, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            "API4" or "RATELIMIT" or "RATELIMITEVASION" => (7.5, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"),
            "API7" or "SSRF" or "SSRFENCODED" or "IMDSV2" => (8.8, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            "SQLI" or "NOSQLI" or "CMDINJ" or "XSS" or "SSTI" => (9.8, "Critical", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
            "FORCEDBROWSE" => (8.2, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            "TYPECONF" => (7.2, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:L"),
            "PARAMSHADOW" or "JSONSMUGGLE" => (8.1, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:H/A:N"),
            "AUTHHEADEROVR" or "TENANTLEAK" => (8.7, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            "ASYNCJOBINJ" => (8.4, "High", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
            "FILEPARSERABUSE" => (8.0, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L"),
            "VERSIONFALLBACK" => (7.4, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N"),
            "CACHEKEYCONF" => (7.8, "High", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N"),
            "TRANSPORT" or "TLSPOSTURE" or "N53SC8" => (7.4, "High", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N"),
            "LOGPOISON" or "N53AU9" => (6.5, "Medium", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N"),
            _ => (6.8, "Medium", "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:L")
        };
    }

    public static string GetAuditMethodology() =>
        "Aligned to OWASP API Security Top 10 and NIST SP 800-115; includes unauthenticated and authenticated role-based testing when profiles are configured.";

    public static string GetTesterMetadata(string envVar, string fallback)
    {
        var value = Environment.GetEnvironmentVariable(envVar)?.Trim();
        return string.IsNullOrWhiteSpace(value) ? fallback : value;
    }

    public static (bool Confirmed, string Source) GetScopeAuthorizationState()
    {
        var env = Environment.GetEnvironmentVariable("API_TESTER_SCOPE_AUTHORIZED");
        var confirmed =
            string.Equals(env, "1", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(env, "true", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(env, "yes", StringComparison.OrdinalIgnoreCase);
        return (confirmed, confirmed ? "env:API_TESTER_SCOPE_AUTHORIZED" : "unset");
    }

    public static string GetAuditLimitationsNote() =>
        "Black-box HTTP probing provides supporting evidence only. Policy/process/manual controls (for example account lifecycle governance, personnel controls, physical controls, and organizational policy compliance) require separate review artifacts.";

    public static string ComputeSha256Hex(string input)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(input ?? string.Empty));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static string SanitizeFileComponent(string value)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var sanitized = new string(value.Select(ch => invalid.Contains(ch) ? '_' : ch).ToArray());
        return string.IsNullOrWhiteSpace(sanitized) ? "run" : sanitized;
    }

    private static IReadOnlyList<string> ExtractFindingLines(string output)
    {
        if (string.IsNullOrWhiteSpace(output))
        {
            return Array.Empty<string>();
        }

        return output
            .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(l => l.StartsWith("- ", StringComparison.Ordinal))
            .Select(l => l[2..].Trim())
            .Where(l => !string.IsNullOrWhiteSpace(l))
            .ToList();
    }
}
