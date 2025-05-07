# Information disclosure

Information disclosure occurs when an application fails to properly protect sensitive information, giving users access to information they should not have available to them.

## Steps

1. Look for software version numbers and configuration information by using [recon techniques](https://recon.tymyrddin.dev/docs/app/README).
2. Search for exposed configuration files, database files, and other sensitive files uploaded to the production server that aren’t protected properly. Techniques you can use include path traversal, scraping the Wayback Machine or paste dump sites, and looking for files in exposed .git directories.
3. Find information in the application’s public files, such as its HTML and JavaScript source code, by grepping the file with keywords.
4. Consider the impact of the information you find before reporting it, and explore ways to escalate its impact.
5. Draft report.

## Try a path traversal attack

Start by trying a path traversal attack to read the server’s sensitive files.

## Search the Wayback Machine

Another way to find exposed files is by using the Wayback Machine, an online archive of what websites looked like at various points in time. You can use it to find hidden and deprecated endpoints, as well as large numbers of current endpoints without actively crawling the site, making it a good first look into what the application might be exposing.

On the Wayback Machine’s site, simply search for a domain to see its past versions. To search for a domain’s files, visit `https://web.archive.org/web/*/DOMAIN`.

## Search Paste Dump sites

Look into paste dump sites like Pastebin and GitHub gists. These let users share text documents via a direct link rather than via email or services like Google Docs, so developers often use them to send source code, configuration files, and log files to colleagues. 

On a site like Pastebin, shared text files are public by default. If developers upload a sensitive file, everyone will be able to read it. For this reason, these code-sharing sites are pretty infamous for leaking credentials like API keys and passwords.

[Pastebin-scraper](https://github.com/streaak/pastebin-scraper/) uses the Pastebin API to search for paste files. This tool is a shell script, the `-g` option indicates a general keyword search:

    ./scrape.sh -g KEYWORD

## Reconstruct source code from an exposed .git directory

Another way of finding sensitive files is to reconstruct source code from an exposed `.git` directory. When attacking an application, obtaining its source code can be extremely helpful for constructing an exploit. This is because some bugs, like [SQL injections](sqli.md), are way easier to find through static code analysis than black-box testing.

## Find Information in public files

Try to find information leaks in the application’s public files, such as their HTML and JavaScript source code. JavaScript files are a rich source of information leaks.

You can also locate JavaScript files on a site by using tools like [LinkFinder](https://github.com/GerbenJavado/LinkFinder/).

## Escalation

After you’ve found a sensitive file or a piece of sensitive data, determine its impact

If you have found credentials such as a password or an API key, validate that they’re currently in use by accessing the target’s system with them. If the sensitive files or credentials are valid and current, consider how one can compromise the application’s security with them.

If the impact of the information you found isn’t particularly critical, you can explore ways to escalate the vulnerability by chaining it with other security issues. For example, if you can leak internal IP addresses within the target’s network, you can use them to pivot into the network during an [SSRF](ssrf.md) exploit. Alternatively, if you can pinpoint the exact software version numbers the application is running, see if any CVEs are related to the software version that can help you achieve [RCE](rce.md).

## Portswigger lab writeups

* [Information disclosure in error messages](../burp/id/1.md)
* [Information disclosure on debug page](../burp/id/2.md)
* [Source code disclosure via backup files](../burp/id/3.md)
* [Authentication bypass via information disclosure](../burp/id/4.md)
* [Information disclosure in version control history](../burp/id/5.md)

## Remediation

* Make sure that everyone involved in producing the web application is aware of what information is considered sensitive. Sometimes seemingly harmless information can be much more useful to an attacker than people realise. 
* Audit any code for potential information disclosure as part of the build processes. It should be relatively easy to automate some associated tasks, such as stripping developer comments.
* Use generic error messages as much as possible. Do not provide attackers with clues about application behaviour unnecessarily.
* Double-check that debugging and diagnostic features are disabled in the production environment.
* Make sure you fully understand the configuration settings, and security implications, of any third-party technology used. Take the time to investigate and disable any features and settings that are not needed.

## Resources

* [Portswigger: Information disclosure vulnerabilities](https://portswigger.net/web-security/information-disclosure)


