namespace API_Tester;

public partial class MainPage
{
    /*
    Docker Container Exposure Test

    Purpose:
    Detects whether a Docker Engine API or container management interface
    is accidentally exposed over HTTP.

    Threat Model:
    Docker exposes a REST API that allows full control over containers,
    images, networks, and volumes. If this API is reachable without
    authentication, attackers may gain complete control of the host
    environment.

    The Docker API is typically intended to be accessible only through
    a local Unix socket or secured administrative interface. If it is
    exposed over TCP or proxied through a web service, it may allow
    unauthorized access.

    Test Strategy:
    The scanner probes common Docker Engine API endpoints including:

        /_ping
        /version
        /info
        /containers/json
        /images/json
        /networks

    These endpoints are used by Docker clients to query the daemon
    for container and system information.

    Potential Impact:
    If the Docker API is publicly accessible, attackers may be able to:

        - list running containers
        - pull or push container images
        - execute commands inside containers
        - start or stop containers
        - mount host filesystems
        - gain root-level access to the host

    Expected Behavior:
    Docker management APIs should not be exposed to public networks.
    Access should be restricted to local sockets or protected with
    strong authentication and network controls.
    */
    
    private async Task<string> RunDockerContainerExposureTestsAsync(Uri baseUri)
    {
        var probePaths = new[]
        {
            "/_ping",
            "/version",
            "/info",
            "/containers/json",
            "/containers/json?all=1",
            "/containers/json?limit=1",
            "/containers/1/json",
            "/containers/1/top",
            "/images/json",
            "/images/search?term=alpine",
            "/networks",
            "/networks/json",
            "/volumes",
            "/volumes/json",
            "/plugins",
            "/plugins/json",
            "/events",
            "/swarm",
            "/services",
            "/tasks",
            "/nodes",
            "/build/prune",
            "/system/df",
            "/v1.24/version",
            "/v1.24/containers/json",
            "/v1.24/images/json",
            "/v1.40/version",
            "/v1.40/containers/json",
            "/v1.41/containers/json?all=1",
            "/v1.41/images/json",
            "/v1.41/info"
        };

        var findings = new List<string>();
        foreach (var path in probePaths)
        {
            var uri = new Uri(baseUri, path);
            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, uri));
            var body = await ReadBodyAsync(response);
            var marker = ContainsAny(body, "docker", "container", "image", "engine", "api version", "serverversion")
            ? " (runtime marker)"
            : string.Empty;

            findings.Add($"{path}: {FormatStatus(response)}{marker}");
        }

        var root = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, baseUri));
        findings.Add($"Base endpoint: {FormatStatus(root)}");
        findings.Add("Review any 200/401 responses with runtime markers as potential Docker daemon/API exposure.");

        return FormatSection("Docker Container API Exposure", baseUri, findings);
    }

}

