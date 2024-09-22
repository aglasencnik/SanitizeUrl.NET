using System;
using System.Linq;
using System.Text.RegularExpressions;

namespace SanitizeUrl
{
    /// <summary>
    /// Represents a class that provides methods to sanitize URLs.
    /// </summary>
    public static class UrlSanitizer
    {
        /// <summary>
        /// Gets whether the relative URL is without protocol.
        /// </summary>
        /// <param name="url">Url</param>
        /// <returns>A bool value which specifies whether the url is relative without protocol.</returns>
        /// <exception cref="ArgumentNullException">Argument null exception if url is null.</exception>
        public static bool IsRelativeUrlWithoutProtocol(string url)
        {
            if (string.IsNullOrEmpty(url))
                throw new ArgumentNullException(nameof(url));

            return Constants.RelativeFirstCharacters.Contains(url[0]);
        }

        /// <summary>
        /// Decodes the HTML characters in the specified URL.
        /// </summary>
        /// <param name="html">Html</param>
        /// <returns>Decoded html characters.</returns>
        public static string DecodeHtmlCharacters(string html)
        {
            var removedNullByte = Constants.CtrlCharactersRegex.Replace(html, string.Empty);
            return Constants.HtmlEntitiesRegex.Replace(removedNullByte, match =>
            {
                var dec = match.Groups[1].Value;

                if (int.TryParse(dec, out var code))
                    return char.ConvertFromUtf32(code);

                return match.Value;
            });
        }

        /// <summary>
        /// Checks whether the specified URL is valid.
        /// </summary>
        /// <param name="url">Url</param>
        /// <returns>A bool value indicating whether the specified URL is valid.</returns>
        public static bool IsValidUrl(string url)
        {
            return Uri.IsWellFormedUriString(url, UriKind.RelativeOrAbsolute);
        }

        /// <summary>
        /// Decodes a URI by handling percent-encoded characters. 
        /// If the decoding fails, it returns the original URI.
        /// </summary>
        /// <param name="uri">The URI to decode.</param>
        /// <returns>The decoded URI or the original URI if decoding fails.</returns>
        public static string DecodeUri(string uri)
        {
            try
            {
                return Uri.UnescapeDataString(uri);
            }
            catch (UriFormatException)
            {
                // Ignoring error as it may contain a '%' not related to URI encoding.
                return uri;
            }
        }

        /// <summary>
        /// Sanitizes the specified URL.
        /// </summary>
        /// <param name="url">Url</param>
        /// <returns>Sanitized url.</returns>
        public static string SanitizeUrl(string url)
        {
            if (string.IsNullOrEmpty(url))
                return Constants.BlankUrl;

            var decodedUrl = DecodeUri(url.Trim());

            bool hasCharsToDecode;
            do
            {
                decodedUrl = DecodeHtmlCharacters(decodedUrl);
                decodedUrl = Constants.HtmlCtrlEntityRegex.Replace(decodedUrl, string.Empty);
                decodedUrl = Constants.HtmlEntitiesRegex.Replace(decodedUrl, string.Empty);
                decodedUrl = Constants.CtrlCharactersRegex.Replace(decodedUrl, string.Empty);
                decodedUrl = Constants.WhitespaceEscapeCharsRegex.Replace(decodedUrl, string.Empty);
                decodedUrl = Regex.Replace(decodedUrl, @"&[a-zA-Z0-9]+;", string.Empty);
                decodedUrl = decodedUrl.Trim();

                decodedUrl = DecodeUri(decodedUrl);

                var ctrlCharactersMatch = Constants.CtrlCharactersRegex.IsMatch(decodedUrl);
                var htmlEntitiesMatch = Constants.HtmlEntitiesRegex.IsMatch(decodedUrl);
                var htmlCtrlEntityMatch = Constants.HtmlCtrlEntityRegex.IsMatch(decodedUrl);
                var whitespaceEscapeCharsMatch = Constants.WhitespaceEscapeCharsRegex.IsMatch(decodedUrl);

                hasCharsToDecode =
                    Constants.CtrlCharactersRegex.IsMatch(decodedUrl) ||
                    Constants.HtmlEntitiesRegex.IsMatch(decodedUrl) ||
                    Constants.HtmlCtrlEntityRegex.IsMatch(decodedUrl) ||
                    Constants.WhitespaceEscapeCharsRegex.IsMatch(decodedUrl);

            } while (hasCharsToDecode);

            var sanitizedUrl = decodedUrl;

            if (string.IsNullOrEmpty(sanitizedUrl))
                return Constants.BlankUrl;

            if (IsRelativeUrlWithoutProtocol(sanitizedUrl))
                return sanitizedUrl;

            // Remove any leading whitespace before checking the URL scheme
            var trimmedUrl = sanitizedUrl.TrimStart();
            var urlSchemeParseResults = Constants.UrlSchemeRegex.Match(trimmedUrl);

            if (!urlSchemeParseResults.Success)
                return sanitizedUrl;

            var urlScheme = urlSchemeParseResults.Value.ToLower().Trim();
            if (Constants.InvalidProtocolRegex.IsMatch(urlScheme))
                return Constants.BlankUrl;

            var backSanitized = trimmedUrl.Replace("\\", "/");

            // Handle special cases for mailto: and custom deep-link protocols
            if (urlScheme == "mailto:" || urlScheme.Contains("://"))
                return backSanitized;

            // For http and https URLs, perform additional validation
            if (urlScheme == "http:" || urlScheme == "https:")
            {
                if (!IsValidUrl(backSanitized))
                    return Constants.BlankUrl;

                var urlObj = new Uri(backSanitized);
                return new UriBuilder(urlObj)
                {
                    Scheme = urlObj.Scheme.ToLower(),
                    Host = urlObj.Host.ToLower()
                }.Uri.ToString();
            }

            return backSanitized;
        }
    }
}
