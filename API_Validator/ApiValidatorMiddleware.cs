using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using System.Text.Json;
using System.Runtime.ExceptionServices;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.Logging;

namespace ApiValidator;

public sealed class ApiValidatorMiddleware
{
    private readonly RequestDelegate _next;
    private readonly API_Validator _validator;
    private readonly ILogger<ApiValidatorMiddleware> _logger;

    public ApiValidatorMiddleware(
        RequestDelegate next,
        API_Validator validator,
        ILogger<ApiValidatorMiddleware> logger)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
        _validator = validator ?? throw new ArgumentNullException(nameof(validator));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public async Task Invoke(HttpContext context)
    {
        if (context is null)
        {
            return;
        }

        string? requestBody = await ReadRequestBodyAsync(context.Request).ConfigureAwait(false);

        var originalBody = context.Response.Body;
        await using var responseBuffer = new MemoryStream();
        context.Response.Body = responseBuffer;

        ExceptionDispatchInfo? capturedException = null;
        BadHttpRequestException? capturedBadRequest = null;
        try
        {
            await _next(context).ConfigureAwait(false);
        }
        catch (BadHttpRequestException badRequest)
        {
            capturedBadRequest = badRequest;
            if (!context.Response.HasStarted)
            {
                context.Response.Clear();
                context.Response.StatusCode = badRequest.StatusCode > 0
                    ? badRequest.StatusCode
                    : StatusCodes.Status400BadRequest;
                context.Response.ContentType = "application/json; charset=utf-8";
                var badRequestPayload = JsonSerializer.Serialize(new
                {
                    error = "Bad request",
                    detail = badRequest.Message
                });
                await context.Response.WriteAsync(badRequestPayload).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            capturedException = ExceptionDispatchInfo.Capture(ex);
        }
        finally
        {
            context.Response.Body = originalBody;
        }

        responseBuffer.Position = 0;
        string? responseBody = await ReadStreamAsync(responseBuffer).ConfigureAwait(false);
        responseBuffer.Position = 0;
        await responseBuffer.CopyToAsync(originalBody).ConfigureAwait(false);

        var requestHeaders = context.Request.Headers.ToDictionary(
            header => header.Key,
            header => header.Value.Select(value => value ?? string.Empty).ToArray(),
            StringComparer.OrdinalIgnoreCase);

        var responseHeaders = context.Response.Headers.ToDictionary(
            header => header.Key,
            header => header.Value.Select(value => value ?? string.Empty).ToArray(),
            StringComparer.OrdinalIgnoreCase);

        var endpoint = context.GetEndpoint();
        var routeTemplate = (endpoint as RouteEndpoint)?.RoutePattern.RawText
            ?? endpoint?.DisplayName;
        var endpointMetadata = ApiEndpointMetadata.FromEndpoint(endpoint);

        var (testKey, headerPayload) = GetMetadata(context, requestHeaders);
        var payloadExpected = IsPayloadExpected(context.Request.Method);
        var (resolvedPayload, payloadSource) = ResolvePayload(headerPayload, requestBody, context.Request.QueryString.Value, payloadExpected);

        var routeValues = context.Request.RouteValues.Count == 0
            ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            : context.Request.RouteValues
                .Where(kv => kv.Value is not null)
                .ToDictionary(kv => kv.Key, kv => kv.Value?.ToString() ?? string.Empty, StringComparer.OrdinalIgnoreCase);

        var attachment = new ApiTestAttachment(
            testKey,
            resolvedPayload,
            payloadExpected,
            payloadSource,
            routeTemplate,
            routeValues,
            endpointMetadata,
            context.Request.Method ?? string.Empty,
            context.Request.Path.HasValue ? context.Request.Path.Value! : string.Empty,
            context.Request.QueryString.HasValue ? context.Request.QueryString.Value! : string.Empty,
            requestHeaders,
            requestBody,
            context.Response.StatusCode,
            responseHeaders,
            AppendExceptionDetails(responseBody, capturedBadRequest ?? capturedException?.SourceException),
            DateTime.UtcNow);

        if (!ShouldSkipAttachment(attachment))
        {
            _validator.Store(attachment);
            LogAttachment(attachment, routeTemplate, routeValues);
            ApiValidatorFileLogger.TryWrite(attachment, _logger);
        }

        if (capturedException is not null)
        {
            capturedException.Throw();
        }
    }

    private static async Task<string?> ReadRequestBodyAsync(HttpRequest request)
    {
        if (request.Body is null || !request.Body.CanRead)
        {
            return null;
        }

        request.EnableBuffering();
        request.Body.Position = 0;
        var body = await ReadStreamAsync(request.Body).ConfigureAwait(false);
        request.Body.Position = 0;
        return body;
    }

    private static async Task<string?> ReadStreamAsync(Stream stream)
    {
        if (stream is null)
        {
            return null;
        }

        using var reader = new StreamReader(stream, Encoding.UTF8, detectEncodingFromByteOrderMarks: false, leaveOpen: true);
        var value = await reader.ReadToEndAsync().ConfigureAwait(false);
        return string.IsNullOrWhiteSpace(value) ? null : value;
    }

    private static (string? TestKey, string? Payload) GetMetadata(
        HttpContext context,
        IReadOnlyDictionary<string, string[]> requestHeaders)
    {
        if (API_Validator.IsValidationEnabled(context))
        {
            return API_Validator.GetMetadata(context);
        }

        requestHeaders.TryGetValue(ApiTestAttachmentHeaders.TestKey, out var testKey);
        requestHeaders.TryGetValue(ApiTestAttachmentHeaders.Payload, out var payload);

        return (testKey?.FirstOrDefault(), payload?.FirstOrDefault());
    }

    private void LogAttachment(
        ApiTestAttachment attachment,
        string? routeTemplate,
        IReadOnlyDictionary<string, string> routeValues)
    {
        var payloadExpected = attachment.PayloadExpected;
        var payloadLabel = string.IsNullOrWhiteSpace(attachment.Payload)
            ? (payloadExpected ? "(none)" : "N/A")
            : attachment.Payload!;

        var displayPath = Uri.UnescapeDataString(attachment.Path);
        var displayQuery = Uri.UnescapeDataString(attachment.QueryString);
        var responseBody = string.IsNullOrWhiteSpace(attachment.ResponseBody)
            ? null
            : TryPrettyPrintJson(attachment.ResponseBody);

        var lines = new List<string>
        {
            "ApiValidator captured",
            $"{attachment.Method} {displayPath}{displayQuery} (status {attachment.ResponseStatusCode}).",
            $"TestKey={attachment.TestKey}",
            $"Payload={payloadLabel}",
            $"Source={attachment.PayloadSource}",
            $"RouteTemplate={(string.IsNullOrWhiteSpace(routeTemplate) ? "(no match)" : routeTemplate)}"
        };

        if (attachment.EndpointMetadata?.HttpMethods.Count > 0)
        {
            lines.Add($"EndpointMethods={string.Join(", ", attachment.EndpointMetadata.HttpMethods)}");
        }

        if (attachment.EndpointMetadata?.RouteParameterNames.Count > 0)
        {
            lines.Add($"EndpointParams={string.Join(", ", attachment.EndpointMetadata.RouteParameterNames)}");
        }

        if (TryGetRouteValuesSummary(routeValues, out var routeValuesSummary))
        {
            lines.Add($"RouteValues={routeValuesSummary}");
        }

        if (!string.IsNullOrWhiteSpace(responseBody))
        {
            lines.Add("ResponseBody=");
            lines.Add(IndentLines(responseBody, string.Empty));
        }

        lines.Add(string.Empty);
        _logger.LogInformation("{Message}", string.Join(Environment.NewLine, lines));
    }

    private static bool IsPayloadExpected(string? method)
    {
        if (string.IsNullOrWhiteSpace(method))
        {
            return false;
        }

        return method.Equals("POST", StringComparison.OrdinalIgnoreCase)
            || method.Equals("PUT", StringComparison.OrdinalIgnoreCase)
            || method.Equals("PATCH", StringComparison.OrdinalIgnoreCase);
    }

    private static (string? Payload, string Source) ResolvePayload(
        string? headerPayload,
        string? requestBody,
        string? queryString,
        bool payloadExpected)
    {
        if (!string.IsNullOrWhiteSpace(headerPayload))
        {
            return (headerPayload, "header");
        }

        if (payloadExpected && !string.IsNullOrWhiteSpace(requestBody))
        {
            return (requestBody, "body");
        }

        if (payloadExpected && !string.IsNullOrWhiteSpace(queryString))
        {
            return (Uri.UnescapeDataString(queryString), "query");
        }

        return (null, payloadExpected ? "expected" : "none");
    }

    private static bool TryGetRouteValuesSummary(IReadOnlyDictionary<string, string> routeValues, out string summary)
    {
        summary = string.Empty;
        if (routeValues is null || routeValues.Count == 0)
        {
            return false;
        }

        summary = string.Join(", ", routeValues.Select(kv => $"{kv.Key}={kv.Value}"));
        return true;
    }

    private static bool ShouldSkipAttachment(ApiTestAttachment attachment)
    {
        var status = attachment.ResponseStatusCode;
        if (status is null)
        {
            return false;
        }

        var skipRaw = Environment.GetEnvironmentVariable("APIVALIDATOR_SKIP_STATUSES");
        if (!string.IsNullOrWhiteSpace(skipRaw))
        {
            var parts = skipRaw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            foreach (var part in parts)
            {
                if (int.TryParse(part, out var code) && code == status.Value)
                {
                    return true;
                }
            }
        }

        return status.Value is 400 or 404 or 405;
    }

    private static string? AppendExceptionDetails(string? responseBody, Exception? exception)
    {
        if (exception is null)
        {
            return responseBody;
        }

        var builder = new StringBuilder();
        if (!string.IsNullOrWhiteSpace(responseBody))
        {
            builder.AppendLine(responseBody);
            builder.AppendLine();
        }

        builder.Append("Exception=");
        builder.Append(exception.GetType().FullName);
        builder.Append(": ");
        builder.Append(exception.Message);

        return builder.ToString();
    }

    private static string TryPrettyPrintJson(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        var trimmed = value.TrimStart();
        if (trimmed.Length == 0)
        {
            return value;
        }

        if (trimmed[0] != '{' && trimmed[0] != '[')
        {
            return value;
        }

        try
        {
            using var doc = JsonDocument.Parse(value);
            return JsonSerializer.Serialize(doc.RootElement, new JsonSerializerOptions
            {
                WriteIndented = true
            });
        }
        catch
        {
            return value;
        }
    }

    private static string IndentLines(string value, string indent)
    {
        if (string.IsNullOrEmpty(value))
        {
            return value;
        }

        var normalized = value.Replace("\r\n", "\n").Replace("\r", "\n");
        var lines = normalized.Split('\n');
        return string.Join(Environment.NewLine, lines.Select(line => $"{indent}{line}"));
    }


    private static List<string> ExtractRoutePlaceholders(string path)
    {
        var placeholders = new List<string>();
        if (string.IsNullOrWhiteSpace(path))
        {
            return placeholders;
        }

        foreach (Match match in Regex.Matches(path, "\\{([^}]+)\\}"))
        {
            if (match.Groups.Count > 1)
            {
                var value = match.Groups[1].Value.Trim();
                if (!string.IsNullOrWhiteSpace(value))
                {
                    placeholders.Add(value);
                }
            }
        }

        return placeholders;
    }
}
