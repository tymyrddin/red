# Information disclosure

Information disclosure occurs when an application fails to properly protect sensitive information, giving users access
to information not meant to be available to them.

## Steps

1. Look for software version numbers and configuration information by using recon techniques.
2. Search for exposed configuration files, database files, and other sensitive files uploaded to the production server
   that aren’t protected properly. Techniques include path traversal, scraping the Wayback Machine or paste dump sites,
   and looking for files in exposed .git directories.
3. Find information in the application’s public files, such as its HTML and JavaScript source code, by grepping the file
   with keywords.
4. Consider the impact of the information found before reporting it, and explore ways to escalate its impact.
5. Draft report.

## Try a path traversal attack

Start by trying a path traversal attack to read the server’s sensitive files.

## Search the Wayback Machine

Another way to find exposed files is by using the Wayback Machine, an online archive of what websites looked like at
various points in time. It finds hidden and deprecated endpoints, as well as large numbers of current endpoints without
actively crawling the site, making it a good first look into what the application might be exposing.

On the Wayback Machine’s site, simply search for a domain to see its past versions. To search for a domain’s files,
visit `https://web.archive.org/web/*/DOMAIN`.

## Search Paste Dump sites

Look into paste dump sites like Pastebin and GitHub gists. These let users share text documents via a direct link rather
than via email or services like Google Docs, so developers often use them to send source code, configuration files, and
log files to colleagues.

On a site like Pastebin, shared text files are public by default. If developers upload a sensitive file, everyone will
be able to read it. For this reason, these code-sharing sites are pretty infamous for leaking credentials like API keys
and passwords.

[Pastebin-scraper](https://github.com/streaak/pastebin-scraper/) uses the Pastebin API to search for paste files. This
tool is a shell script, the `-g` option indicates a general keyword search:

```bash
./scrape.sh -g KEYWORD
```

## Reconstruct source code from an exposed .git directory

Another way of finding sensitive files is to reconstruct source code from an exposed `.git` directory. When attacking an
application, obtaining its source code can be extremely helpful for constructing an exploit. This is because some bugs,
like [SQL injections](sqli.md), are way easier to find through static code analysis than black-box testing.

## Find Information in public files

Try to find information leaks in the application’s public files, such as their HTML and JavaScript source code.
JavaScript files are a rich source of information leaks.

JavaScript files can also be located with tools like [LinkFinder](https://github.com/GerbenJavado/LinkFinder/).

## Escalation

After a sensitive file or piece of sensitive data is found, determine its impact.

Credentials such as a password or API key, once found, can be validated by using them against the target’s system. If
the sensitive files or credentials are valid and current, the next question is how they compromise the application’s
security.

Where the impact is not particularly critical on its own, chaining it with other security issues escalates it. Leaked
internal IP addresses feed a pivot into the network during an [SSRF](ssrf.md) exploit; an exact software version number
points to CVEs that may reach [RCE](rce.md).

## Variants

The leaks worth chasing are verbose error messages, debug pages left enabled, source
disclosed through backup files or an exposed version-control history, and the occasional
authentication bypass where the leaked detail is itself the way in. The
[surface discovery runbook](../runbooks/recon.md) folds these into passive and low-noise
mapping.

## Resources

* [Portswigger: Information disclosure vulnerabilities](https://portswigger.net/web-security/information-disclosure)

## Counter moves

Information disclosure is what this page works through. These come back to the same answers: validated input, encoded
output, server-side authorisation, and patched dependencies. Defenders' notes on this are
under [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
