using System.Text.Json;

namespace API_Tester.SecurityCatalog;

public sealed class SecurityTestCatalog
{
    public string Version { get; set; } = "1.0";
    public List<string> EngineModes { get; set; } = new();
    public List<SecurityTestCategory> Categories { get; set; } = new();
}

public sealed class SecurityTestCategory
{
    public string Name { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public List<SecurityTestDefinition> Tests { get; set; } = new();
}

public sealed class SecurityTestDefinition
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string Category { get; set; } = string.Empty;
    public string SubCategory { get; set; } = string.Empty;
    public string Severity { get; set; } = "Medium";
    public bool Destructive { get; set; }
    public string Method { get; set; } = "GET";
    public string? PathTemplate { get; set; }
    public Dictionary<string, string> HeadersTemplate { get; set; } = new();
    public JsonElement? BodyTemplate { get; set; }
    public List<JsonElement> Payloads { get; set; } = new();
    public List<string> ExpectedIndicators { get; set; } = new();
    public string? SuccessCriteria { get; set; }
    public Dictionary<string, List<string>> Standards { get; set; } = new();
}

