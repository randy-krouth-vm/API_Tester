using System.Text;
using System.Text.Json;

namespace ApiTester.Core;

public static class ValidationWorkflowUtilities
{
    public static async Task<string> RunValidationHarnessAsync(
        string? configuredScenariosPath,
        string appDataDirectory,
        Func<List<AuthProfile>> getExecutionAuthProfiles,
        Func<string?, bool> isUnauthProfileName,
        Func<string?, string?> normalizeAuthProfileSelection,
        Func<string?, string> getAuthProfileDisplayName,
        Func<string, (string TestName, Func<Uri, Task<string>>? Test)> resolveTestByKey,
        Func<string, AuthProfile, Uri, Func<Uri, Task<string>>, Task<(string Output, bool HadException)>> executeResolvedTestAsync)
    {
        var scenariosPath = configuredScenariosPath;
        if (string.IsNullOrWhiteSpace(scenariosPath))
        {
            scenariosPath = Path.Combine(appDataDirectory, "validation-scenarios.json");
        }

        if (!File.Exists(scenariosPath))
        {
            return
                "[Validation Sequence]\n" +
                $"- Scenario file not found: {scenariosPath}\n" +
                "- Set API_TESTER_VALIDATION_SCENARIOS to a JSON file path.\n" +
                "- Expected schema: { \"scenarios\": [ { \"name\": \"crAPI no-auth\", \"targetUrl\": \"https://...\", \"testKeys\": [\"API1\",\"SQLI\"], \"expectedFailKeys\": [\"API1\"], \"expectedPassKeys\": [\"SQLI\"], \"expectedInconclusiveKeys\": [], \"authProfile\": \"No Authentication\" } ] }";
        }

        var json = await File.ReadAllTextAsync(scenariosPath);
        var options = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };
        var set = JsonSerializer.Deserialize<ValidationScenarioSet>(json, options)
                  ?? new ValidationScenarioSet(new List<ValidationScenario>());
        if (set.Scenarios.Count == 0)
        {
            return $"[Validation Sequence]\n- No scenarios found in: {scenariosPath}";
        }

        var availableProfiles = getExecutionAuthProfiles();
        if (!availableProfiles.Any(p => isUnauthProfileName(p.Name)))
        {
            availableProfiles.Insert(0, new AuthProfile("No Authentication", string.Empty, string.Empty, "X-API-Key", string.Empty, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)));
        }

        var sb = new StringBuilder();
        sb.AppendLine("[Validation Sequence]");
        sb.AppendLine($"Scenario file: {scenariosPath}");

        var totalChecks = 0;
        var passedChecks = 0;
        var mismatches = 0;

        foreach (var scenario in set.Scenarios)
        {
            if (!Uri.TryCreate(scenario.TargetUrl, UriKind.Absolute, out var target) ||
                (target.Scheme != Uri.UriSchemeHttp && target.Scheme != Uri.UriSchemeHttps))
            {
                sb.AppendLine($"- {scenario.Name}: skipped (invalid target URL: {scenario.TargetUrl})");
                continue;
            }

            var desiredProfile = normalizeAuthProfileSelection(scenario.AuthProfile) ?? "No Authentication";
            var profile = availableProfiles.FirstOrDefault(p => p.Name.Equals(desiredProfile, StringComparison.OrdinalIgnoreCase))
                          ?? availableProfiles.FirstOrDefault(p => isUnauthProfileName(p.Name))
                          ?? availableProfiles.First();

            sb.AppendLine($"- Scenario: {scenario.Name}");
            sb.AppendLine($"  Target: {target}");
            sb.AppendLine($"  Profile: {getAuthProfileDisplayName(profile.Name)}");

            foreach (var rawKey in scenario.TestKeys.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var key = rawKey.Trim();
                var resolved = resolveTestByKey(key);
                if (resolved.Test is null)
                {
                    sb.AppendLine($"  - {key}: unresolved key");
                    continue;
                }

                var execution = await executeResolvedTestAsync(key, profile, target, resolved.Test);
                var actual = AuditResultUtilities.DetermineVerdict(key, execution.Output, execution.HadException);
                var expected = ResolveExpectedVerdict(scenario, key);
                if (string.IsNullOrWhiteSpace(expected))
                {
                    sb.AppendLine($"  - {key}: actual={actual} (no expected verdict defined)");
                    continue;
                }

                totalChecks++;
                if (actual.Equals(expected, StringComparison.OrdinalIgnoreCase))
                {
                    passedChecks++;
                    sb.AppendLine($"  - {key}: expected={expected}, actual={actual} [OK]");
                }
                else
                {
                    mismatches++;
                    sb.AppendLine($"  - {key}: expected={expected}, actual={actual} [MISMATCH]");
                }
            }
        }

        sb.AppendLine($"Summary: checks={totalChecks}, passed={passedChecks}, mismatches={mismatches}");
        return sb.ToString().TrimEnd();
    }

    public static string? ResolveExpectedVerdict(ValidationScenario scenario, string testKey)
    {
        if ((scenario.ExpectedFailKeys ?? new List<string>()).Any(k => k.Equals(testKey, StringComparison.OrdinalIgnoreCase)))
        {
            return "fail";
        }

        if ((scenario.ExpectedPassKeys ?? new List<string>()).Any(k => k.Equals(testKey, StringComparison.OrdinalIgnoreCase)))
        {
            return "pass";
        }

        if ((scenario.ExpectedInconclusiveKeys ?? new List<string>()).Any(k => k.Equals(testKey, StringComparison.OrdinalIgnoreCase)))
        {
            return "inconclusive";
        }

        return null;
    }
}
