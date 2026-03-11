namespace API_Tester;

public partial class MainPage
{
    /*
    File Upload Validation Test

    Purpose:
    Checks whether the application properly validates uploaded files and
    restricts unsafe file types.

    Threat Model:
    Applications that allow file uploads must ensure that uploaded content
    cannot be used to execute code or bypass security controls. Weak
    validation may allow attackers to upload files containing scripts,
    malicious payloads, or disguised executable content.

    Common issues include:

        - accepting dangerous file extensions
        - relying only on file extension checks
        - trusting the Content-Type header
        - failing to verify file signatures (magic bytes)
        - allowing double extensions (e.g., file.php.jpg)

    Test Strategy:
    The scanner attempts to upload files using different extensions,
    Content-Type headers, and payload formats to determine whether the
    application accepts files that should normally be rejected.

    Potential Impact:
    If file upload validation is weak, attackers may be able to:

        - upload executable scripts to achieve remote code execution
        - upload web shells or backdoors
        - store malicious files for later retrieval
        - bypass file type restrictions

    Expected Behavior:
    Applications should strictly validate uploaded files by enforcing
    allowed file types, verifying file signatures, limiting file size,
    and storing uploaded files outside executable directories.
    */

    private async Task<string> RunFileUploadValidationTestsAsync(Uri baseUri)
    {
        var response = await SafeSendAsync(() =>
        {
            var req = new HttpRequestMessage(HttpMethod.Post, baseUri);
            var multi = new MultipartFormDataContent();
            var content = new ByteArrayContent(Encoding.UTF8.GetBytes("<?php echo 'test'; ?>"));
            content.Headers.TryAddWithoutValidation("Content-Type", "image/jpeg");
            multi.Add(content, "file", "avatar.php.jpg");
            req.Content = multi;
            return req;
        });

        var body = await ReadBodyAsync(response);
        var findings = new List<string>
        {
            $"HTTP {FormatStatus(response)}",
            response is not null && response.StatusCode == HttpStatusCode.OK &&
            ContainsAny(body, "uploaded", "success", "stored")
            ? "Potential risk: suspicious file payload accepted."
            : "No obvious unsafe upload acceptance indicator."
        };

        return FormatSection("File Upload Validation", baseUri, findings);
    }

}

