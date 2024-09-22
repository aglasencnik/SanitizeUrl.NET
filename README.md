# SanitizeUrl.NET

[![NuGet version (SanitizeUrl.NET)](https://img.shields.io/nuget/v/SanitizeUrl.NET)](https://www.nuget.org/packages/SanitizeUrl.NET/)

![GitHub License](https://img.shields.io/github/license/aglasencnik/SanitizeUrl.NET)

**SanitizeUrl.NET** is a lightweight .NET library that sanitizes URLs by removing potentially harmful or unwanted characters. Inspired by Braintree's Sanitize URL for JavaScript, this package ensures URLs are safe for use in web applications, preventing XSS attacks and other vulnerabilities. Easy to integrate, with minimal overhead, making it ideal for secure URL handling in any .NET project.

## Installation

To use SanitizeUrl.NET in your C# project, you need to install the NuGet package. Follow these simple steps:

### Using NuGet Package Manager

1. **Open Your Project**: Open your project in Visual Studio or your preferred IDE.
2. **Open the Package Manager Console**: Navigate to `Tools` -> `NuGet Package Manager` -> `Package Manager Console`.
3. **Install SanitizeUrl.NET**: Type the following command and press Enter:
   `Install-Package SanitizeUrl.NET`

### Using .NET CLI

Alternatively, you can use .NET Core CLI to install SanitizeUrl.NET. Open your command prompt or terminal and run:

`dotnet add package SanitizeUrl.NET`

### Verifying the Installation

After installation, make sure that SanitizeUrl.NET is listed in your project dependencies to confirm successful installation.

## Usage

```csharp
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
```

## Support the Project

If you find this project useful, consider supporting it by [buying me a coffee](https://www.buymeacoffee.com/aglasencnik). Your support is greatly appreciated!

## Contributing

Contributions are welcome! If you have a feature to propose or a bug to fix, create a new pull request.

## License

This project is licensed under the [MIT License](https://github.com/aglasencnik/SanitizeUrl.NET/blob/main/LICENSE).

## Acknowledgment

This project is inspired by and built upon the [sanitize-url](https://github.com/braintree/sanitize-url) project.
