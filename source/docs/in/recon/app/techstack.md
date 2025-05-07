# Tech stack fingerprinting

Fingerprinting techniques can help you understand the target application even better. Fingerprinting is identifying the software brands and versions that a machine or an application uses. This information allows you to perform targeted attacks on the application, because you can search for any known misconfigurations and publicly disclosed vulnerabilities related to a particular version.

1. Run Nmap on a machine with the `-sV` flag on to enable version detection on the port scan.
2. In Burp, send an HTTP request to the server to check the HTTP headers used to gain insight into the tech stack.
3. Many web frameworks or other technologies will embed a signature in source code. Right-click a page, select `View Source Code`, and press `CTRL-F` to search for phrases like `powered by`, `built with`, and `running`.
4. Check technology-specific file extensions, filenames, folders, and directories.

[Wappalyzer](https://www.wappalyzer.com/) is a browser extension that identifies content management systems, frameworks, and programming languages used on a site. [BuiltWith](https://builtwith.com/) is a website that shows you which web technologies a site is built with. [StackShare](https://stackshare.io/) is an online platform that allows developers to share the tech they use. Maybe the organisation’s developers have posted their tech stack. And [Retire.js](https://retirejs.github.io/retire.js/) is a tool that detects outdated JavaScript libraries and `Node.js` packages.