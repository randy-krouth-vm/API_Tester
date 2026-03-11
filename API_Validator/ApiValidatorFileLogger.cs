using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace ApiValidator;

public static class ApiValidatorFileLogger
{
    private static readonly object SyncLock = new();
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    public static void TryWrite(ApiTestAttachment attachment, ILogger logger)
    {
        if (!IsEnabled())
        {
            return;
        }

        try
        {
            var path = GetLogPath();
            var line = JsonSerializer.Serialize(attachment, JsonOptions);
            lock (SyncLock)
            {
                File.AppendAllText(path, line + Environment.NewLine);
            }
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "ApiValidator failed to write attachment to file.");
        }
    }

    private static bool IsEnabled()
    {
        var enabled = Environment.GetEnvironmentVariable("APIVALIDATOR_LOG_FILE_ENABLED");
        if (string.IsNullOrWhiteSpace(enabled))
        {
            return false;
        }

        return enabled.Equals("true", StringComparison.OrdinalIgnoreCase)
            || enabled.Equals("1", StringComparison.OrdinalIgnoreCase)
            || enabled.Equals("yes", StringComparison.OrdinalIgnoreCase);
    }

    private static string GetLogPath()
    {
        var configured = Environment.GetEnvironmentVariable("APIVALIDATOR_LOG_PATH");
        if (!string.IsNullOrWhiteSpace(configured))
        {
            return configured;
        }

        return Path.Combine(AppContext.BaseDirectory, "api-validator.log");
    }
}
