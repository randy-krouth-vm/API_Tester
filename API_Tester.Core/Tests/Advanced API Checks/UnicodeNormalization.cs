namespace API_Tester;

public partial class MainPage
{
    /*
    Unicode Normalization Test

    Purpose:
    Checks whether the API properly handles Unicode normalization when
    processing user input such as identifiers, paths, parameters, or
    authentication values.

    Threat Model:
    Unicode characters can be represented in multiple different ways that
    appear identical when rendered but differ at the byte level. If the
    application does not normalize Unicode input consistently, attackers
    may exploit these differences to bypass validation or security checks.

    For example, some characters may have multiple representations:

        é → single composed character
        e + ́ → decomposed character sequence

    Both appear identical to users but are encoded differently.

    Attackers may also use visually similar characters (homoglyphs) such as:

        Latin "a" vs Cyrillic "а"
        Latin "o" vs Greek "ο"

    Attack scenarios include:

        - bypassing authentication or username validation
        - bypassing input filters or blacklist checks
        - creating duplicate accounts that appear identical
        - evading file path validation
        - bypassing access control checks

    Example case:

        username = "admin"
        username = "аdmin"  (Cyrillic 'a')

    Visually identical but technically different.

    Test Strategy:
    The scanner submits inputs containing mixed Unicode forms, combining
    characters, homoglyphs, and alternate encodings to observe whether the
    application treats them consistently.

    Potential Impact:
    If Unicode normalization is inconsistent, attackers may be able to:

        - bypass validation or filtering rules
        - impersonate users with visually identical identifiers
        - evade security checks or blocklists
        - manipulate file paths or routing logic

    Expected Behavior:
    Applications should normalize Unicode input to a consistent form
    (such as NFC) before validation and comparison, and should treat
    visually or structurally equivalent inputs consistently.
    */
    
    private async Task<string> RunUnicodeNormalizationTestsAsync(Uri baseUri)
    {
        var payload = "adm\u0069n";
        var uriA = AppendQuery(baseUri, new Dictionary<string, string> { ["role"] = payload });
        var uriB = AppendQuery(baseUri, new Dictionary<string, string> { ["role"] = "admi\u0301n" });

        var a = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, uriA));
        var b = await SafeSendAsync(() => new HttpRequestMessage(HttpMethod.Get, uriB));

        var findings = new List<string>
        {
            $"Variant A: {FormatStatus(a)}",
            $"Variant B: {FormatStatus(b)}",
            a is not null && b is not null && a.StatusCode != b.StatusCode
            ? "Potential risk: Unicode normalization differences affect authorization/input handling."
            : "No obvious Unicode normalization differential behavior."
        };

        return FormatSection("Unicode Normalization", baseUri, findings);
    }

}

