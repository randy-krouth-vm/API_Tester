using Microsoft.Extensions.DependencyInjection;

namespace ApiValidator;

public static class ApiValidatorServiceCollectionExtensions
{
    public static IServiceCollection AddApiValidator(this IServiceCollection services)
    {
        if (services is null)
        {
            throw new ArgumentNullException(nameof(services));
        }

        services.AddSingleton<ApiTestAttachmentStore>();
        services.AddSingleton<API_Validator>();
        return services;
    }
}
