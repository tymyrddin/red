# Gather system information

* Web server operating systems
* Server locations
* Users
* Passwords

## Website footprinting

Website footprinting is a technique in which information about the target is collected by monitoring the target’s website. Hackers can map the entire website of the target without being noticed.

Website footprinting gives information about:

* Software
* Operating system
* Subdirectories
* Contact information
* Scripting platform
* Query details

By examining the website headers, it is possible to obtain information about the following headers:

* Content-Type
* Accept-Ranges
* Connection Status
* Last-Modified Information
* X-powered-by Information
* Web Server Information

Additional ways to gather information is through HTML Source Code and cookie examination. By examining the HTML source code, it is possible to extract information from the comments in the code, as well as gain insight into the file system structure by observing the links and image tags.

Cookies can also reveal important information about the software that is running on the server and its behaviour. And by inspecting sessions, it is possible to identify the scripting platforms.

Web spiders methodically browse a website in search of specific information. Information collected can be helpful in planning social engineering attacks.

## Cloning websites

Website mirroring or website cloning refers to the process of duplicating a website. Mirroring a website helps in browsing the site offline, searching the website for vulnerabilities, and discovering useful information.

Websites may store documents of different format, which in turn may contain hidden information and metadata that can be analyzed and used in (planning) an attack. This metadata can be extracted with metadata extraction tools. 

## Eyeing repositories

Look for hardcoded secrets:

* SQL passwords
* AWS access keys
* Google Cloud private keys
* API tokens
* Test accounts

In GitHub search:

```text
# Sample of GitHub queries
org:TargetName password
org:TargetName aws_secret_access_key
org:TargetName aws_key
org:TargetName BEGIN RSA PRIVATE KEY
org:TargetName BEGIN OPENSSH PRIVATE KEY
org:TargetName secret_key
org:TargetName hooks.slack.com/services
org:TargetName sshpass -p
org:TargetName sq0csp
org:TargetName apps.googleusercontent.com
org:TargetName extension:pem key
```

## Sensitive files discovery

Many tools for finding the URLs of sensitive files exist. One such tool is `dirb`, a web content discovery tool.
