namespace ApiTester.Core;

public static class AuthProfileUtilities
{
    public static List<AuthProfile> GetExecutionProfiles(
        string? userBearer,
        string? userApiKey,
        string? userCookie,
        string? userHeaders,
        string? adminBearer,
        string? adminApiKey,
        string? adminCookie,
        string? adminHeaders,
        bool roleMatrixEnabled,
        string? selectedDefaultProfile,
        string? defaultProfileFromEnv)
    {
        var profiles = new List<AuthProfile>
        {
            new("No Authentication", string.Empty, string.Empty, "X-API-Key", string.Empty, new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase))
        };

        var user = CreateAuthProfileFromUiOrEnv(
            "user",
            userBearer,
            userApiKey,
            userCookie,
            userHeaders,
            "API_TESTER_AUTH_USER");
        if (user is not null)
        {
            profiles.Add(user);
        }

        var admin = CreateAuthProfileFromUiOrEnv(
            "admin",
            adminBearer,
            adminApiKey,
            adminCookie,
            adminHeaders,
            "API_TESTER_AUTH_ADMIN");
        if (admin is not null)
        {
            profiles.Add(admin);
        }

        if (roleMatrixEnabled)
        {
            return profiles;
        }

        var defaultName = string.IsNullOrWhiteSpace(selectedDefaultProfile)
            ? defaultProfileFromEnv?.Trim()
            : selectedDefaultProfile;
        defaultName = NormalizeAuthProfileSelection(defaultName);
        if (!string.IsNullOrWhiteSpace(defaultName))
        {
            var selected = profiles.FirstOrDefault(p => p.Name.Equals(defaultName, StringComparison.OrdinalIgnoreCase));
            if (selected is not null)
            {
                return new List<AuthProfile> { selected };
            }
        }

        return new List<AuthProfile> { profiles[0] };
    }

    public static string? NormalizeAuthProfileSelection(string? value)
    {
        var v = value?.Trim();
        if (string.IsNullOrWhiteSpace(v))
        {
            return v;
        }

        if (v.Equals("Run without credentials", StringComparison.OrdinalIgnoreCase))
        {
            return "No Authentication";
        }

        if (v.Equals("unauth", StringComparison.OrdinalIgnoreCase) ||
            v.Equals("unauthenticated", StringComparison.OrdinalIgnoreCase) ||
            v.Equals("no authentication", StringComparison.OrdinalIgnoreCase))
        {
            return "No Authentication";
        }

        if (v.Equals("User credentials", StringComparison.OrdinalIgnoreCase))
        {
            return "user";
        }

        if (v.Equals("Admin credentials", StringComparison.OrdinalIgnoreCase))
        {
            return "admin";
        }

        return v;
    }

    public static AuthProfile? CreateAuthProfileFromUiOrEnv(
        string name,
        string? uiBearer,
        string? uiApiKey,
        string? uiCookie,
        string? uiHeaders,
        string envPrefix)
    {
        var bearer = string.IsNullOrWhiteSpace(uiBearer)
            ? (Environment.GetEnvironmentVariable($"{envPrefix}_BEARER")?.Trim() ?? string.Empty)
            : uiBearer.Trim();
        var apiKey = string.IsNullOrWhiteSpace(uiApiKey)
            ? (Environment.GetEnvironmentVariable($"{envPrefix}_APIKEY")?.Trim() ?? string.Empty)
            : uiApiKey.Trim();
        var cookie = string.IsNullOrWhiteSpace(uiCookie)
            ? (Environment.GetEnvironmentVariable($"{envPrefix}_COOKIE")?.Trim() ?? string.Empty)
            : uiCookie.Trim();
        var headersRaw = string.IsNullOrWhiteSpace(uiHeaders)
            ? (Environment.GetEnvironmentVariable($"{envPrefix}_HEADERS")?.Trim() ?? string.Empty)
            : uiHeaders.Trim();
        var apiKeyHeader = Environment.GetEnvironmentVariable($"{envPrefix}_APIKEY_HEADER")?.Trim();

        var headers = ParseExtraHeaders(headersRaw);
        if (string.IsNullOrWhiteSpace(bearer) &&
            string.IsNullOrWhiteSpace(apiKey) &&
            string.IsNullOrWhiteSpace(cookie) &&
            headers.Count == 0)
        {
            return null;
        }

        return new AuthProfile(
            name,
            bearer,
            apiKey,
            string.IsNullOrWhiteSpace(apiKeyHeader) ? "X-API-Key" : apiKeyHeader,
            cookie,
            headers);
    }

    public static AuthProfile? CreateAuthProfileFromEnv(string name, string prefix)
    {
        var bearer = Environment.GetEnvironmentVariable($"{prefix}_BEARER")?.Trim() ?? string.Empty;
        var apiKey = Environment.GetEnvironmentVariable($"{prefix}_APIKEY")?.Trim() ?? string.Empty;
        var apiKeyHeader = Environment.GetEnvironmentVariable($"{prefix}_APIKEY_HEADER")?.Trim();
        var cookie = Environment.GetEnvironmentVariable($"{prefix}_COOKIE")?.Trim() ?? string.Empty;
        var headersRaw = Environment.GetEnvironmentVariable($"{prefix}_HEADERS")?.Trim() ?? string.Empty;

        var headers = ParseExtraHeaders(headersRaw);
        if (string.IsNullOrWhiteSpace(bearer) &&
            string.IsNullOrWhiteSpace(apiKey) &&
            string.IsNullOrWhiteSpace(cookie) &&
            headers.Count == 0)
        {
            return null;
        }

        return new AuthProfile(
            name,
            bearer,
            apiKey,
            string.IsNullOrWhiteSpace(apiKeyHeader) ? "X-API-Key" : apiKeyHeader,
            cookie,
            headers);
    }

    public static Dictionary<string, string> ParseExtraHeaders(string raw)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(raw))
        {
            return result;
        }

        var pairs = raw.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var pair in pairs)
        {
            var parts = pair.Split(':', 2);
            if (parts.Length != 2)
            {
                continue;
            }

            var key = parts[0].Trim();
            var value = parts[1].Trim();
            if (key.Length > 0)
            {
                result[key] = value;
            }
        }

        return result;
    }
}
