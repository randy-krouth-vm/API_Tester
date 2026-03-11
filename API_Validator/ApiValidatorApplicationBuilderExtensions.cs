using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

namespace ApiValidator;

public static class ApiValidatorApplicationBuilderExtensions
{
    public static IApplicationBuilder UseApiValidator(this IApplicationBuilder app)
    {
        if (app is null)
        {
            throw new ArgumentNullException(nameof(app));
        }

        var validator = app.ApplicationServices.GetRequiredService<API_Validator>();
        return app.UseApiValidator(validator);
    }

    public static IApplicationBuilder UseApiValidator(this IApplicationBuilder app, ApiTestAttachmentStore store)
    {
        if (app is null)
        {
            throw new ArgumentNullException(nameof(app));
        }

        if (store is null)
        {
            throw new ArgumentNullException(nameof(store));
        }

        var validator = new API_Validator(store);
        return app.UseApiValidator(validator);
    }

    public static IApplicationBuilder UseApiValidator(this IApplicationBuilder app, API_Validator validator)
    {
        if (app is null)
        {
            throw new ArgumentNullException(nameof(app));
        }

        if (validator is null)
        {
            throw new ArgumentNullException(nameof(validator));
        }

        return app.UseMiddleware<ApiValidatorMiddleware>(validator);
    }
}
