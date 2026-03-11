namespace API_Tester;

public partial class MainPage
{
    /*
    Environment File Exposure Test

    Purpose:
    Checks whether environment configuration files are publicly accessible
    through the web server.

    Threat Model:
    Many applications store sensitive configuration values in environment
    files such as ".env". These files often contain secrets used by the
    application at runtime.

    If the web server is misconfigured and allows direct access to these
    files, attackers may retrieve sensitive information without
    authentication.

    Typical sensitive values stored in environment files include:

        - database connection strings
        - API keys
        - cloud service credentials
        - JWT signing secrets
        - SMTP credentials
        - internal service URLs

    Test Strategy:
    The scanner attempts to access common environment file paths such as:

        /.env
        /.env.local
        /.env.production
        /.env.development

    It checks whether the server returns readable content instead of
    blocking access.

    Potential Impact:
    If environment files are exposed, attackers may obtain credentials that
    allow access to databases, cloud services, or internal APIs. This can
    lead to full system compromise depending on the secrets contained in
    the file.

    Expected Behavior:
    Environment files should never be accessible from public web routes.
    Web servers should deny access to these files and ensure that secrets
    are stored securely outside publicly served directories.
    */
    
    private async Task<string> RunEnvFileExposureTestsAsync(Uri baseUri)
    {
        var paths = new[]
        {
            "/.env",
            "/.env.local",
            "/.env.dev",
            "/.env.development",
            "/.env.production",
            "/.env.stage",
            "/.env.staging",
            "/.env.backup",
            "/.env.old",
            "/.env.bak",
            "/.env.save",
            "/.env.tmp",
            "/config/.env",
            "/app/.env",
            "/backend/.env",
            "/api/.env",
            "/.git/config",
            "/.git/HEAD",
            "/.gitignore",
            "/.gitmodules",
            "/.aws/credentials",
            "/.aws/config",
            "/docker-compose.yml",
            "/docker-compose.yaml",
            "/Dockerfile",
            "/.npmrc",
            "/.yarnrc",
            "/.pypirc",
            "/config.json",
            "/settings.json",
            "/secrets.json",
            "/config/database.yml",
            "/config/secrets.yml",
            "/.htpasswd",
            "/.htaccess",
            "/actuator/env",
            "/actuator/configprops",
            "/actuator/health",
            "/actuator/beans",
            "/application.properties",
            "/application.yml",
            "/WEB-INF/web.xml",
            "/WEB-INF/applicationContext.xml"
        };

        var findings = new List<string>();
        foreach (var path in paths)
        {
            var uri = new Uri(baseUri, path);
            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, uri));
            var body = await ReadBodyAsync(response);
            var secretMarker = ContainsAny(body, "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "PRIVATE_KEY", "spring.datasource", "[core]");
            findings.Add($"{path}: {FormatStatus(response)}{(secretMarker ? " (sensitive marker)" : string.Empty)}");
        }

        return FormatSection("Exposed .env/Config", baseUri, findings);
    }

}

