namespace API_Tester;

public partial class MainPage
{
    /*
    Port Service Fingerprinting Test

    Purpose:
    Checks whether the target system exposes identifiable services on
    different ports that may reveal internal infrastructure details.

    Threat Model:
    Applications sometimes expose services on multiple ports for APIs,
    administration interfaces, debugging tools, or internal services.
    If these services respond to unauthenticated requests, attackers may
    be able to identify technologies, versions, or internal components
    running on the host.

    Service fingerprinting can reveal valuable reconnaissance information
    about the system architecture.

    Attack scenarios include:

        - identifying administrative panels exposed on alternate ports
        - detecting internal APIs or development services
        - discovering technologies such as web servers, databases, or
        monitoring interfaces
        - enumerating service versions with known vulnerabilities

    Example targets may include ports commonly associated with:

        - alternative HTTP services
        - development servers
        - container management interfaces
        - monitoring or metrics endpoints

    Test Strategy:
    The scanner attempts connections to common service ports related to
    the base API host and observes response behavior, headers, or status
    codes that may indicate the presence of accessible services.

    Potential Impact:
    If unintended services are exposed, attackers may be able to:

        - identify system components and technologies
        - access administrative or debugging interfaces
        - exploit services with known vulnerabilities
        - expand the attack surface of the application

    Expected Behavior:
    Production systems should expose only the minimal set of required
    services, restrict administrative interfaces, and avoid leaking
    service fingerprints or version information.
    */
    
    private async Task<string> RunPortServiceFingerprintTestsAsync(Uri baseUri)
    {
        var targets = new (int Port, string Name)[]
        {
            (22, "SSH"),
            (21, "FTP"),
            (23, "Telnet"),
            (25, "SMTP"),
            (3306, "MySQL"),
            (5432, "PostgreSQL"),
            (6379, "Redis"),
            (2375, "Docker API")
        };

        var findings = new List<string>();
        foreach (var target in targets)
        {
            var open = false;
            string banner = string.Empty;

            try
            {
                using var tcp = new TcpClient();
                var connectTask = tcp.ConnectAsync(baseUri.Host, target.Port);
                var completed = await Task.WhenAny(connectTask, Task.Delay(1200));
                if (completed == connectTask && tcp.Connected)
                {
                    open = true;
                    tcp.ReceiveTimeout = 500;
                    tcp.SendTimeout = 500;

                    var stream = tcp.GetStream();
                    var readBuffer = new byte[128];
                    if (stream.DataAvailable)
                    {
                        var read = await stream.ReadAsync(readBuffer, 0, readBuffer.Length);
                        if (read > 0)
                        {
                            banner = Encoding.ASCII.GetString(readBuffer, 0, read).Trim();
                        }
                    }
                }
            }
            catch
            {
                open = false;
            }

            findings.Add(open
            ? $"{target.Name} ({target.Port}): OPEN{(string.IsNullOrWhiteSpace(banner) ? string.Empty : $" | Banner: {banner}")}"
            : $"{target.Name} ({target.Port}): closed/filtered");
        }

        findings.Add("Review OPEN non-HTTP services for unnecessary exposure.");
        return FormatSection("Port Scan/Service Fingerprint", baseUri, findings);
    }

}

