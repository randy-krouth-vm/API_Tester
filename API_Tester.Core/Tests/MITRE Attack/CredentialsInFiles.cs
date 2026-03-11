namespace API_Tester
{
    public partial class MainPage
    {
        /*
        MITRE ATT&CK T1552.001 – Credentials in Files Tests

        Purpose:
        Performs automated tests to determine whether sensitive credentials
        are exposed in files that may be accessible through the application
        or web server. This aligns with MITRE ATT&CK technique T1552.001
        (Unsecured Credentials: Credentials in Files).

        Threat Model:
        Applications or servers sometimes store credentials in configuration
        files or environment files. If these files are accessible through the
        web root or exposed endpoints, attackers may retrieve secrets such as:

            - API keys
            - database credentials
            - cloud provider credentials
            - service tokens
            - internal configuration secrets

        Attackers frequently probe for well-known files such as:

            - .env or environment configuration files
            - Git configuration or repository metadata
            - cloud credential files (e.g., AWS credentials)
            - framework diagnostic endpoints exposing environment variables

        Test Strategy:
        The method performs requests against commonly exposed credential
        storage locations including:

            - /.env
            - /.env.local
            - /config/.env
            - /.git/config
            - /.aws/credentials
            - /actuator/env

        Responses are analyzed to determine whether sensitive configuration
        data or credentials are exposed.

        Potential Impact:
        If credentials are exposed in accessible files, attackers may:

            - Obtain database or API access
            - Compromise cloud infrastructure
            - Access internal services or administrative systems
            - Escalate privileges or pivot further into the environment

        Expected Behavior:
        Applications and servers should:

            - Never expose configuration or credential files through HTTP
            - Store secrets securely using secret management systems
            - Restrict file system access and web server mappings
            - Disable diagnostic endpoints that reveal sensitive environment data
            - Ensure repository and infrastructure files are not accessible publicly
        */
        
        private async Task<string> RunMitreT1552001CredentialsInFilesTestsAsync(Uri baseUri)
        {
            var paths = new[]
            {
                "/.env",
                "/.env.local",
                "/config/.env",
                "/.git/config",
                "/.aws/credentials",
                "/actuator/env",
                "/config/database.yml",
                "/config/secrets.yml",
                "/var/www/html/.env",
                "/wp-config.php",
                "/etc/environment",
                "/etc/hostname",
                "/etc/network/interfaces",
                "/etc/apache2/apache2.conf",
                "/etc/ssh/sshd_config",
                "/repository/.git/config",
                "/repository/.svn/config",
                "/repository/.hg/config",
                "/etc/aws/credentials",
                "/etc/gcp/credentials",
                "/.heroku/config",
                "/gcloud/.config/gcloud/credentials",
                "/config/database.conf",
                "/config/db_config.json",
                "/var/lib/mysql/.my.cnf",
                "/var/lib/postgresql/.pgpass",
                "/home/*/.bash_profile",
                "/home/*/.bashrc",
                "/home/*/.zshrc",
                "/home/*/.envrc",
                "/jenkins/credentials.xml",
                "/github/workflows/*",
                "/gitlab-ci.yml",
                "/var/log/application.log",
                "/var/log/secure",
                "/var/log/auth.log",
                "/var/log/httpd/access.log",
                "/var/log/httpd/error.log",
                "/home/*/.bash_history",
                "/home/*/.zsh_history",
                "/home/*/.mysql_history",
                "/home/*/.psql_history"
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
}

