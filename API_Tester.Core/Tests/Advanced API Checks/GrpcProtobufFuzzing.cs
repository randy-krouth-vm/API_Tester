namespace API_Tester;

public partial class MainPage
{
    /*
    gRPC Protobuf Fuzzing Test

    Purpose:
    Evaluates how the gRPC service handles malformed, unexpected, or
    randomized Protocol Buffers (protobuf) messages.

    Threat Model:
    gRPC services rely on protobuf message schemas to serialize and
    deserialize structured data. If the service does not properly validate
    incoming messages, malformed protobuf payloads may trigger parser
    errors, crashes, or unexpected behavior.

    Attackers may attempt to manipulate protobuf messages by:

        - sending invalid field types
        - injecting unexpected fields
        - truncating serialized messages
        - sending oversized or malformed payloads
        - corrupting message structure

    Test Strategy:
    The scanner sends crafted or mutated protobuf payloads to the gRPC
    endpoint and observes how the server responds. It checks for parser
    failures, service crashes, or abnormal responses that may indicate
    weak input validation.

    Potential Impact:
    If protobuf parsing is not handled safely, attackers may be able to
    cause:

        - service crashes
        - memory corruption
        - resource exhaustion
        - denial-of-service conditions

    In rare cases, vulnerabilities in protobuf libraries could potentially
    lead to deeper exploitation.

    Expected Behavior:
    The service should reject malformed protobuf messages with clear
    validation errors and should safely handle invalid inputs without
    crashing or exposing internal errors.
    */

    private async Task<string> RunGrpcProtobufFuzzingTestsAsync(Uri baseUri)
    {
        var uri = new Uri(baseUri, "/grpc.health.v1.Health/Check");
        var fuzzPayloads = new byte[][]
        {
            new byte[] { 0x00, 0x00, 0x00, 0xFF, 0xFF },
            Enumerable.Repeat((byte)0xFF, 64).ToArray(),
            new byte[] { 0x0A, 0x80, 0x80, 0x80, 0x80, 0x10 }
        };

        var findings = new List<string>();
        foreach (var payload in fuzzPayloads)
        {
            var response = await SafeSendAsync(() =>
            {
                var req = new HttpRequestMessage(HttpMethod.Post, uri);
                req.Content = new ByteArrayContent(payload);
                req.Content.Headers.TryAddWithoutValidation("Content-Type", "application/grpc");
                req.Headers.TryAddWithoutValidation("TE", "trailers");
                return req;
            });

            findings.Add($"Payload len {payload.Length}: {FormatStatus(response)}");
        }

        return FormatSection("gRPC Protobuf Fuzzing", uri, findings);
    }

}

