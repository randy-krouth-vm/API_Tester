namespace ApiTester.Core;

public static class ResultFindWorkflowUtilities
{
    public static int FindMatchIndex(
        string text,
        string needle,
        int previousMatchIndex,
        bool caseSensitive,
        bool forward)
    {
        var comparison = caseSensitive
            ? StringComparison.Ordinal
            : StringComparison.OrdinalIgnoreCase;
        return forward
            ? FindForward(text, needle, previousMatchIndex, comparison)
            : FindBackward(text, needle, previousMatchIndex, comparison);
    }

    public static int FindForward(string text, string needle, int previousMatchIndex, StringComparison comparison)
    {
        if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(needle))
        {
            return -1;
        }

        var start = previousMatchIndex >= 0
            ? previousMatchIndex + needle.Length
            : 0;

        if (start >= text.Length)
        {
            start = 0;
        }

        var hit = text.IndexOf(needle, start, comparison);
        if (hit >= 0)
        {
            return hit;
        }

        return start > 0
            ? text.IndexOf(needle, 0, comparison)
            : -1;
    }

    public static int FindBackward(string text, string needle, int previousMatchIndex, StringComparison comparison)
    {
        if (string.IsNullOrEmpty(text) || string.IsNullOrEmpty(needle))
        {
            return -1;
        }

        var start = previousMatchIndex >= 0
            ? previousMatchIndex - 1
            : text.Length - 1;

        if (start < 0 || start >= text.Length)
        {
            start = text.Length - 1;
        }

        var hit = text.LastIndexOf(needle, start, comparison);
        if (hit >= 0)
        {
            return hit;
        }

        return start < text.Length - 1
            ? text.LastIndexOf(needle, text.Length - 1, comparison)
            : -1;
    }
}
