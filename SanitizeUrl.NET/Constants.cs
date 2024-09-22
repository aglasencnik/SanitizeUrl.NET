using System.Text.RegularExpressions;

namespace SanitizeUrl
{
    /// <summary>
    /// Represents a class that provides constants for the SanitizeUrl library.
    /// </summary>
    internal static class Constants
    {
        /// <summary>
        /// Gets the regular expression to match invalid protocols such as javascript, data, or vbscript.
        /// </summary>
        public static readonly Regex InvalidProtocolRegex =
            new Regex(@"^([^\w]*)(javascript|data|vbscript)", RegexOptions.IgnoreCase | RegexOptions.Multiline);

        /// <summary>
        /// Gets the regular expression expression to match HTML entities.
        /// </summary>
        public static readonly Regex HtmlEntitiesRegex =
            new Regex(@"&#(\w+)(^\w|;)?", RegexOptions.IgnoreCase);

        /// <summary>
        /// Gets the regular expression to match HTML control entities like newline or tab.
        /// </summary>
        public static readonly Regex HtmlCtrlEntityRegex =
            new Regex(@"&(newline|tab);", RegexOptions.IgnoreCase);

        /// <summary>
        /// Gets the regular expression to match control characters.
        /// </summary>
        public static readonly Regex CtrlCharactersRegex =
            new Regex(@"[\u0000-\u001F\u007F-\u009F\u2000-\u200D\uFEFF]", RegexOptions.IgnoreCase | RegexOptions.Multiline);

        /// <summary>
        /// Gets the regular expression to match URL schemes.
        /// </summary>
        public static readonly Regex UrlSchemeRegex =
            new Regex(@"^.+(:|&colon;)", RegexOptions.IgnoreCase | RegexOptions.Multiline);

        /// <summary>
        /// Gets the regular expression to match whitespace escape characters.
        /// </summary>
        public static readonly Regex WhitespaceEscapeCharsRegex =
            new Regex(@"(\\|%5[cC])((%(6[eE]|72|74))|[nrt])", RegexOptions.IgnoreCase);

        /// <summary>
        /// Gets the list of relative path starting characters.
        /// </summary>
        public static readonly char[] RelativeFirstCharacters = { '.', '/' };

        /// <summary>
        /// Gets the constant representing a blank URL.
        /// </summary>
        public const string BlankUrl = "about:blank";
    }
}
