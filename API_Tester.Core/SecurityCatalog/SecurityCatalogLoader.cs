using System.Text;
using System.Text.Json;

namespace API_Tester.SecurityCatalog;

public static class SecurityCatalogLoader
{
    private static string _lastLoadError = string.Empty;
    public static string LastLoadError => _lastLoadError;

    public static Task<SecurityTestCatalog?> LoadAsync() => LoadAsync(null);

    public static async Task<SecurityTestCatalog?> LoadAsync(Func<string, Task<Stream>>? openPackagedFileAsync)
    {
        _lastLoadError = string.Empty;

        if (openPackagedFileAsync is not null)
        {
            try
            {
                await using var stream = await openPackagedFileAsync("security-tests.json");
                using var reader = new StreamReader(stream, Encoding.UTF8);
                var json = await reader.ReadToEndAsync();
                var parsed = JsonSerializer.Deserialize<SecurityTestCatalog>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                if (parsed is not null)
                {
                    var normalized = NormalizeCatalog(parsed);
                    if (HasAnyTests(normalized))
                    {
                        return normalized;
                    }

                    _lastLoadError = "Packaged catalog loaded but contains zero tests.";
                }
            }
            catch (Exception ex)
            {
                _lastLoadError = $"Packaged asset load failed: {ex.Message}";
            }
        }

        return await LoadFromFallbacksAsync();
    }

    private static async Task<SecurityTestCatalog?> LoadFromFallbacksAsync()
    {
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "security-tests.json"),
            Path.Combine(AppContext.BaseDirectory, "Resources", "Raw", "security-tests.json"),
            Path.Combine(Directory.GetCurrentDirectory(), "security-tests.json"),
            Path.Combine(Directory.GetCurrentDirectory(), "Resources", "Raw", "security-tests.json")
        };

        foreach (var candidate in candidates)
        {
            try
            {
                if (!File.Exists(candidate))
                {
                    continue;
                }

                var json = await File.ReadAllTextAsync(candidate, Encoding.UTF8);
                var parsed = JsonSerializer.Deserialize<SecurityTestCatalog>(json, new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true
                });
                if (parsed is not null)
                {
                    var normalized = NormalizeCatalog(parsed);
                    if (HasAnyTests(normalized))
                    {
                        _lastLoadError = string.Empty;
                        return normalized;
                    }

                    _lastLoadError = $"Fallback catalog at '{candidate}' contains zero tests.";
                }
            }
            catch (Exception ex)
            {
                _lastLoadError = $"Fallback load failed at '{candidate}': {ex.Message}";
            }
        }

        if (string.IsNullOrWhiteSpace(_lastLoadError))
        {
            _lastLoadError = "security-tests.json was not found in package or fallback locations.";
        }

        // Final safety fallback so UI never shows an empty catalog.
        return BuildEmbeddedFallbackCatalog();
    }

    public static string BuildCatalogReport(SecurityTestCatalog catalog)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== Dynamic Test Catalog ===");
        sb.AppendLine($"Version: {catalog.Version}");
        sb.AppendLine($"Modes: {string.Join(", ", catalog.EngineModes)}");
        sb.AppendLine();

        foreach (var category in catalog.Categories ?? new List<SecurityTestCategory>())
        {
            sb.AppendLine($"[{category.Name}] {category.Description}");
            foreach (var test in category.Tests ?? new List<SecurityTestDefinition>())
            {
                var standards = (test.Standards ?? new Dictionary<string, List<string>>())
                .SelectMany(kvp => (kvp.Value ?? new List<string>()).Select(v => $"{kvp.Key}:{v}"))
                .ToList();
                sb.AppendLine($"- {test.Id} | {test.Name}");
                sb.AppendLine($"  Severity={test.Severity}; Destructive={test.Destructive}; Method={test.Method}");
                sb.AppendLine($"  Standards={string.Join(" | ", standards)}");
            }

            sb.AppendLine();
        }

        return sb.ToString().TrimEnd();
    }

    private static bool HasAnyTests(SecurityTestCatalog catalog) =>
    (catalog.Categories ?? new List<SecurityTestCategory>())
    .Any(c => (c.Tests?.Count ?? 0) > 0);

    private static SecurityTestCatalog BuildEmbeddedFallbackCatalog()
    {
        _lastLoadError = string.IsNullOrWhiteSpace(_lastLoadError)
        ? "Using embedded fallback catalog."
        : $"{_lastLoadError} Using embedded fallback catalog.";

        return new SecurityTestCatalog
        {
            Version = "fallback-1.0",
            EngineModes = new List<string> { "Safe", "Standard", "Aggressive" },
            Categories = new List<SecurityTestCategory>
            {
                new()
                {
                    Name = "Injection",
                    Description = "Core injection validation checks",
                    Tests = new List<SecurityTestDefinition>
                    {
                        new() { Id = "INJ-SQLI-BASE", Name = "Basic SQL Injection Probe", Method = "GET", Severity = "High", Standards = new Dictionary<string, List<string>> { ["CWE"] = new() { "CWE-89" } } },
                        new() { Id = "INJ-XSS-BASE", Name = "Basic XSS Probe", Method = "GET", Severity = "High", Standards = new Dictionary<string, List<string>> { ["CWE"] = new() { "CWE-79" } } }
                    }
                },
                new()
                {
                    Name = "Auth",
                    Description = "Token and session trust checks",
                    Tests = new List<SecurityTestDefinition>
                    {
                        new() { Id = "AUTH-JWT-NONE", Name = "JWT none-alg Probe", Method = "GET", Severity = "Critical", Standards = new Dictionary<string, List<string>> { ["CWE"] = new() { "CWE-347" } } }
                    }
                },
                new()
                {
                    Name = "Protocol",
                    Description = "HTTP/TLS boundary checks",
                    Tests = new List<SecurityTestDefinition>
                    {
                        new() { Id = "PROT-SMUGGLE", Name = "Request Smuggling Signal", Method = "RAW", Severity = "Critical", Standards = new Dictionary<string, List<string>> { ["CWE"] = new() { "CWE-444" } } }
                    }
                }
            }
        };
    }

    private static SecurityTestCatalog NormalizeCatalog(SecurityTestCatalog catalog)
    {
        catalog.EngineModes ??= new List<string>();
        catalog.Categories ??= new List<SecurityTestCategory>();

        foreach (var category in catalog.Categories)
        {
            category.Tests ??= new List<SecurityTestDefinition>();
            foreach (var test in category.Tests)
            {
                test.HeadersTemplate ??= new Dictionary<string, string>();
                test.Payloads ??= new List<JsonElement>();
                test.ExpectedIndicators ??= new List<string>();
                test.Standards ??= new Dictionary<string, List<string>>();
            }
        }

        return catalog;
    }
}

