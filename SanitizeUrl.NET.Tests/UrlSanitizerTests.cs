using System.Net;

namespace SanitizeUrl.Tests;

public class UrlSanitizerTests
{
    [Fact]
    public void SanitizeUrl()
    {
        Assert.Equal(
            "http://example.com:4567/path/to:something",
            UrlSanitizer.SanitizeUrl("http://example.com:4567/path/to:something")
        );

        Assert.Equal(
            "https://example.com:4567/path/to:something",
            UrlSanitizer.SanitizeUrl("https://example.com:4567/path/to:something")
        );

        Assert.Equal(
            "https://example.com/",
            UrlSanitizer.SanitizeUrl("https://example.com")
        );

        Assert.Equal(
            "https://example.com:4567/path/to:something",
            UrlSanitizer.SanitizeUrl("https://example.com:4567/path/to:something")
        );

        Assert.Equal(
            "./path/to/my.json",
            UrlSanitizer.SanitizeUrl("./path/to/my.json")
        );

        Assert.Equal(
            "path/to/my.json",
            UrlSanitizer.SanitizeUrl("path/to/my.json")
        );

        Assert.Equal(
            "//google.com/robots.txt",
            UrlSanitizer.SanitizeUrl("//google.com/robots.txt")
        );

        Assert.Equal(
            "com.braintreepayments.demo://example",
            UrlSanitizer.SanitizeUrl("com.braintreepayments.demo://example")
        );

        Assert.Equal(
            "mailto:test@example.com?subject=hello+world",
            UrlSanitizer.SanitizeUrl("mailto:test@example.com?subject=hello+world")
        );

        Assert.Equal(
            "www.example.com/with-áccêntš",
            UrlSanitizer.SanitizeUrl("www.example.com/with-áccêntš")
        );

        Assert.Equal(
            "www.example.com/лот.рфшишкиü–",
            UrlSanitizer.SanitizeUrl("www.example.com/лот.рфшишкиü–")
        );

        Assert.Equal(
            "www.example.com/foo",
            UrlSanitizer.SanitizeUrl("www.example.com/‍\0\u001f\0\u001f﻿foo")
        );

        Assert.Equal(
            "about:blank",
            UrlSanitizer.SanitizeUrl("")
        );

        Assert.Equal(
            "about:blank",
            UrlSanitizer.SanitizeUrl(null)
        );

        Assert.Equal(
            "http://example.com/path/to:something",
            UrlSanitizer.SanitizeUrl("   http://example.com/path/to:something    ")
        );

        Assert.Equal(
            "https://example.com/something",
            UrlSanitizer.SanitizeUrl("https://example.com&NewLine;&NewLine;/something")
        );

        var attackVendors = new[]
        {
            "&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041",
            "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;",
            "&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29",
            "jav&#x09;ascript:alert('XSS');",
            " &#14; javascript:alert('XSS');",
            "javasc&Tab;ript: alert('XSS');",
            "javasc&#\u0000x09;ript:alert(1)",
            "java&#38;&#38;&#35;78&#59;ewLine&#38;newline&#59;&#59;script&#58;alert&#40;&#39;XSS&#39;&#41;",
            "java&&#78;ewLine&newline;;script:alert('XSS')",
        };

        foreach (var attackVendor in attackVendors)
        {
            Assert.Equal(
                "about:blank",
                UrlSanitizer.SanitizeUrl(attackVendor)
            );
        }

        // https://example.com/javascript:alert('XSS')
        // since the javascript is the url path, and not the protocol,
        // this url is technically sanitized
        Assert.Equal(
            "https://example.com/javascript:alert('XSS')",
            UrlSanitizer.SanitizeUrl("&#104;&#116;&#116;&#112;&#115;&#0000058//&#101;&#120;&#97;&#109;&#112;&#108;&#101;&#46;&#99;&#111;&#109;/&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041")
        );

        attackVendors =
        [
            "javascri\npt:alert('xss')",
            "javascri\rpt:alert('xss')",
            "javascri\tpt:alert('xss')",
            "javascrip\\%74t:alert('XSS')",
            "javascrip%5c%72t:alert()",
            "javascrip%5Ctt:alert()",
            "javascrip%255Ctt:alert()",
            "javascrip%25%35Ctt:alert()",
            "javascrip%25%35%43tt:alert()",
            "javascrip%25%32%35%25%33%35%25%34%33rt:alert()",
            "javascrip%255Crt:alert('%25xss')",
        ];

        foreach (var attackVendor in attackVendors)
        {
            Assert.Equal(
                "about:blank",
                UrlSanitizer.SanitizeUrl(attackVendor)
            );
        }

        attackVendors =
        [
            "\fjavascript:alert()",
            "\vjavascript:alert()",
            "\tjavascript:alert()",
            "\njavascript:alert()",
            "\rjavascript:alert()",
            "\u0000javascript:alert()",
            "\u0001javascript:alert()",
        ];

        foreach (var attackVendor in attackVendors)
        {
            Assert.Equal(
                "about:blank",
                UrlSanitizer.SanitizeUrl(attackVendor)
            );
        }

        Assert.Equal(
            "/j/av/a/s/cript:alert()",
            UrlSanitizer.SanitizeUrl("\\j\\av\\a\\s\\cript:alert()")
        );
    }

    [Fact]
    public void InvalidProtocols()
    {
        var protocols = new[] { "javascript", "data", "vbscript" };

        foreach (var protocol in protocols)
        {
            Assert.Equal(
                $"about:blank",
                UrlSanitizer.SanitizeUrl($"{protocol}:alert(document.domain)")
            );

            Assert.Equal(
                $"not_{protocol}:alert(document.domain)",
                UrlSanitizer.SanitizeUrl($"not_{protocol}:alert(document.domain)")
            );

            Assert.Equal(
                $"about:blank",
                UrlSanitizer.SanitizeUrl($"&!*{protocol}:alert(document.domain)")
            );

            Assert.Equal(
                $"about:blank",
                UrlSanitizer.SanitizeUrl($"{protocol}&colon;:alert(document.domain)")
            );

            Assert.Equal(
                $"about:blank",
                UrlSanitizer.SanitizeUrl($"{protocol}&COLON;:alert(document.domain)")
            );

            string mixedCapitalizationProtocol = GenerateMixedCapitalization(protocol);
            string maliciousUrlWithMixedCapitalization = $"{mixedCapitalizationProtocol}:alert(document.domain)";

            Assert.Equal(
                $"about:blank",
                UrlSanitizer.SanitizeUrl(maliciousUrlWithMixedCapitalization)
            );

            string protocolWithControlCharacters = InsertControlCharacters(protocol);
            string maliciousUrlWithControlCharacters = $"{protocolWithControlCharacters}:alert(document.domain)";

            Assert.Equal(
                $"about:blank",
                UrlSanitizer.SanitizeUrl(WebUtility.HtmlDecode(maliciousUrlWithControlCharacters))
            );

            Assert.Equal(
                $"about:blank",
                UrlSanitizer.SanitizeUrl($"{WebUtility.UrlDecode($"%20%20%20%20{protocol}:alert(document.domain)")}")
            );

            Assert.Equal(
                $"about:blank",
                UrlSanitizer.SanitizeUrl($"    {protocol}:alert(document.domain)")
            );

            Assert.Equal(
                $"http://example.com#{protocol}:foo",
                UrlSanitizer.SanitizeUrl($"http://example.com#{protocol}:foo")
            );
        }
    }

    #region Utils

    private string GenerateMixedCapitalization(string protocol)
    {
        // Upper case every other letter in the protocol name
        var characters = protocol.ToCharArray();
        for (int i = 0; i < characters.Length; i++)
        {
            if (i % 2 == 0)
            {
                characters[i] = char.ToUpper(characters[i]);
            }
        }
        return new string(characters);
    }

    private string InsertControlCharacters(string protocol)
    {
        // Add control characters to the protocol
        var result = new System.Text.StringBuilder();

        for (int i = 0; i < protocol.Length; i++)
        {
            result.Append(protocol[i]);

            if (i == 1)
            {
                result.Append("%EF%BB%BF%EF%BB%BF"); // Invisible BOM
            }
            else if (i == 2)
            {
                result.Append("%e2%80%8b"); // Zero-width space
            }
        }

        return result.ToString();
    }

    #endregion
}
