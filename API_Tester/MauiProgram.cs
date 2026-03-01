using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace API_Tester
{
    public static class MauiProgram
    {
        public static MauiApp CreateMauiApp()
        {
            var builder = MauiApp.CreateBuilder();
            builder
                .UseMauiApp<App>()
                .ConfigureFonts(fonts =>
                {
                    fonts.AddFont("OpenSans-Regular.ttf", "OpenSansRegular");
                    fonts.AddFont("OpenSans-Semibold.ttf", "OpenSansSemibold");
                });

            builder.Services.AddHttpClient("ApiTesterRuntime", client =>
            {
                client.Timeout = TimeSpan.FromSeconds(20);
            });

            builder.Services.AddHttpClient("NvdApi", client =>
            {
                client.Timeout = TimeSpan.FromSeconds(60);
                client.DefaultRequestHeaders.UserAgent.ParseAdd("API_Tester/1.0");
            });

#if DEBUG
            builder.Logging.AddDebug();
#endif

            return builder.Build();
        }
    }
}
