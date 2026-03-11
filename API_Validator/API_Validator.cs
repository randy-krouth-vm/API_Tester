using Microsoft.AspNetCore.Http;

namespace ApiValidator;

public sealed class API_Validator
{
    internal const string EnabledItemKey = "ApiValidator.Enabled";
    internal const string TestKeyItemKey = "ApiValidator.TestKey";
    internal const string PayloadItemKey = "ApiValidator.Payload";

    private readonly ApiTestAttachmentStore _store;

    public API_Validator(ApiTestAttachmentStore store)
    {
        _store = store;
    }

    public void Validate(HttpContext context, string? testKey = null, string? payload = null)
    {
        if (context is null)
        {
            return;
        }

        context.Items[EnabledItemKey] = true;
        if (!string.IsNullOrWhiteSpace(testKey))
        {
            context.Items[TestKeyItemKey] = testKey;
        }

        if (!string.IsNullOrWhiteSpace(payload))
        {
            context.Items[PayloadItemKey] = payload;
        }
    }

    internal static bool IsValidationEnabled(HttpContext context)
        => context.Items.TryGetValue(EnabledItemKey, out var value) && value is true;

    internal static (string? TestKey, string? Payload) GetMetadata(HttpContext context)
    {
        context.Items.TryGetValue(TestKeyItemKey, out var testKey);
        context.Items.TryGetValue(PayloadItemKey, out var payload);
        return (testKey as string, payload as string);
    }

    internal void Store(ApiTestAttachment attachment) => _store.Add(attachment);
}
