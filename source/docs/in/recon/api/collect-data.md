# Collect data 

Collect data from applications through automated and manual means.

1. Scan for open ports and services using shodan
2. Use an application as intended
3. Inspect web application with DevTools
4. Search for API-related directories
5. Discover API endpoints

From here: an entry point (typically using the root URI of "/") contains links to other REST APIs. Those APIs will 
contain links to other APIs and so on. Ideally, there is no API that does not have a link to it.

## Tools

* [Kiterunner](https://github.com/assetnote/kiterunner/releases)
* [Nikto](https://www.kali.org/tools/nikto/)
* [OWASP ZAP](https://owasp.org/www-project-zap/)