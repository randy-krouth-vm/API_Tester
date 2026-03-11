namespace API_Tester;

public partial class MainPage
{
    /*
    Cloud Public Storage Exposure Test

    Purpose:
    Checks whether the application references or exposes publicly accessible
    cloud storage resources such as object storage buckets or blobs.

    Threat Model:
    Applications frequently store files, backups, logs, or static assets in
    cloud object storage services (e.g., AWS S3, Azure Blob Storage, Google
    Cloud Storage). If these resources are misconfigured with public read
    permissions, sensitive data may be exposed to unauthorized users.

    Test Strategy:
    The scanner inspects responses and referenced URLs for patterns commonly
    associated with public cloud storage endpoints, including:

        s3.amazonaws.com
        *.s3.amazonaws.com
        storage.googleapis.com
        *.blob.core.windows.net
        *.digitaloceanspaces.com

    If such URLs are discovered, the scanner may attempt to determine whether
    the referenced resource is publicly accessible.

    Potential Impact:
    Publicly exposed storage containers may leak sensitive information such as:

        - user-uploaded files
        - application backups
        - logs
        - configuration files
        - internal documents

    In some cases, improperly configured buckets may also allow write access,
    enabling attackers to upload malicious files.

    Expected Behavior:
    Cloud storage resources should enforce proper access controls using
    authentication, signed URLs, or restricted bucket policies. Public access
    should only be allowed for intentionally shared assets such as static
    content.
    */
    
    private async Task<string> RunCloudPublicStorageExposureTestsAsync(Uri baseUri)
    {
        var hostSeed = baseUri.Host.Split('.').FirstOrDefault() ?? "api";
        
        var candidates = Array.Empty<Uri>();
        /*var candidates = new[]
        {
            // AWS S3
            new Uri($"https://{hostSeed}.s3.amazonaws.com/"),
            new Uri($"https://s3.amazonaws.com/{hostSeed}/"),

            new Uri($"https://{hostSeed}.s3.us-east-1.amazonaws.com/"),
            new Uri($"https://{hostSeed}.s3.us-west-1.amazonaws.com/"),
            new Uri($"https://{hostSeed}.s3.us-west-2.amazonaws.com/"),
            new Uri($"https://{hostSeed}.s3.eu-west-1.amazonaws.com/"),
            new Uri($"https://{hostSeed}.s3.eu-central-1.amazonaws.com/"),
            new Uri($"https://{hostSeed}.s3.ap-southeast-1.amazonaws.com/"),
            new Uri($"https://{hostSeed}.s3.ap-southeast-2.amazonaws.com/"),
            new Uri($"https://{hostSeed}.s3.ap-northeast-1.amazonaws.com/"),
            new Uri($"https://{hostSeed}.s3.ap-northeast-2.amazonaws.com/"),
            new Uri($"https://{hostSeed}.s3.sa-east-1.amazonaws.com/"),

            // AWS S3 Website
            new Uri($"https://{hostSeed}.s3-website-us-east-1.amazonaws.com/"),
            new Uri($"https://{hostSeed}.s3-website-us-west-2.amazonaws.com/"),

            // Google Cloud Storage
            new Uri($"https://storage.googleapis.com/{hostSeed}/"),
            new Uri($"https://storage.googleapis.com/{hostSeed}.appspot.com/"),
            new Uri($"https://{hostSeed}.storage.googleapis.com/"),

            // Azure Blob Storage
            new Uri($"https://{hostSeed}.blob.core.windows.net/"),
            new Uri($"https://{hostSeed}.dfs.core.windows.net/"),

            // DigitalOcean Spaces
            new Uri($"https://{hostSeed}.nyc3.digitaloceanspaces.com/"),
            new Uri($"https://{hostSeed}.ams3.digitaloceanspaces.com/"),
            new Uri($"https://{hostSeed}.sgp1.digitaloceanspaces.com/"),

            // Cloudflare R2
            new Uri($"https://{hostSeed}.r2.cloudflarestorage.com/"),

            // Alibaba OSS
            new Uri($"https://{hostSeed}.oss-cn-hangzhou.aliyuncs.com/"),
            new Uri($"https://{hostSeed}.oss-cn-shanghai.aliyuncs.com/"),
            new Uri($"https://{hostSeed}.oss-cn-beijing.aliyuncs.com/"),

            // Oracle Object Storage
            new Uri($"https://objectstorage.us-ashburn-1.oraclecloud.com/n/{hostSeed}/"),
            new Uri($"https://objectstorage.us-phoenix-1.oraclecloud.com/n/{hostSeed}/"),

            // Backblaze B2
            new Uri($"https://f000.backblazeb2.com/file/{hostSeed}/"),

            // Wasabi S3 Compatible
            new Uri($"https://{hostSeed}.s3.wasabisys.com/"),
            new Uri($"https://s3.wasabisys.com/{hostSeed}/"),

            // IBM Cloud Object Storage
            new Uri($"https://{hostSeed}.s3.us.cloud-object-storage.appdomain.cloud/"),
            new Uri($"https://s3.us.cloud-object-storage.appdomain.cloud/{hostSeed}/"),

            // Generic S3 Compatible
            new Uri($"https://{hostSeed}.s3.amazonaws.com/{hostSeed}/"),
            new Uri($"https://cdn.{hostSeed}.s3.amazonaws.com/")
        };*/
        
        var findings = new List<string>();
        foreach (var candidate in candidates)
        {
            var response = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, candidate));
            var body = await ReadBodyAsync(response);
            var publicMarker = ContainsAny(body, "ListBucketResult", "EnumerationResults", "<Blob", "PublicAccessNotPermitted");
            findings.Add($"{candidate.Host}: {FormatStatus(response)}{(publicMarker ? " (storage marker)" : string.Empty)}");
        }

        findings.Add("Potential risk if any storage endpoint is publicly listable/readable.");
        return FormatSection("Cloud Storage/Public Asset Exposure", baseUri, findings);
    }

}

