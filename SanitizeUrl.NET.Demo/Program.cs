using SanitizeUrl;

Console.WriteLine(UrlSanitizer.SanitizeUrl("https://example.com")); // 'https://example.com'
Console.WriteLine(UrlSanitizer.SanitizeUrl("http://example.com")); // 'http://example.com'
Console.WriteLine(UrlSanitizer.SanitizeUrl("www.example.com")); // 'http://www.example.com'
Console.WriteLine(UrlSanitizer.SanitizeUrl("mailto:hello@example.com")); // 'mailto:hello@example.com'
Console.WriteLine(
    UrlSanitizer.SanitizeUrl("&#104;&#116;&#116;&#112;&#115;&#0000058//&#101;&#120;&#97;&#109;&#112;&#108;&#101;&#46;&#99;&#111;&#109;")
); // 'https://example.com'

Console.WriteLine(UrlSanitizer.SanitizeUrl("javascript:alert(document.domain)")); // 'about:blank'
Console.WriteLine(UrlSanitizer.SanitizeUrl("jAvasCrIPT:alert(document.domain)")); // 'about:blank'
Console.WriteLine(UrlSanitizer.SanitizeUrl("JaVaScRiP%0at:alert(document.domain)")); // 'about:blank'

// HTML encoded javascript:alert('XSS')
Console.WriteLine(
    UrlSanitizer.SanitizeUrl("&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041")
); // 'about:blank'
