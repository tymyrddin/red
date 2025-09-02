# Cloud-centric attacks

Some attacks, such as DoS, have specialised context when applied to the cloud. Other attacks focus on services available only within cloud environments, such as malware injection and side-channel attacks for cloud resources. These attacks can be used to gain further access within a cloud environment or to use the cloud environment as an attack tool to accomplish goals against other Internet-facing targets.

## Denial of service

Cloud based DDoS attack vectors include CoAP (Constrained Application Protocol), WS-DD (Web Services Dynamic Discovery), ARMS (Apple Remote Management Service). 

These newly discovered DDoS vectors are network protocols that are essential to the devices they are being used in (IoT devices, smartphones, Macs), and device makers are unlikely to remove or disable the protocols in their products, hence this serious threat of DDoS attacks.

### Volumetric attacks

Volumetric attacks try to take up bandwidth or connections on their targets. Cloud resources are an attractive way to amplify an attack or to mask the true source of the attack. UDP reflection attacks can use protocols like Apple Remote Management Service, Web Services Dynamic Discovery (WS-DD), Constrained Application Protocol (CoAP), LDAP, and Memcached, all of which can be exposed by cloud resources.

### Direct-to-origin attacks

If real IPs are revealed, attackers can bypass protections and attack IP addresses directly. This is a direct-to-origin attack. Content delivery networks (CDNs) are designed to shoulder the bulk of the load. Massive amounts of traffic can therefore be serviced by relatively few systems. Attacking those few directly can quickly overload the target. The cached content in the CDN will still be serviced, but dynamic content can’t be generated and distributed.

## Malware injection

XSS and SQLi attacks also work in the cloud. And there are additional vectors of attack for malware injection in the cloud. Attackers may be able to use the access acquired through other attacks to inject malicious content into served images or cloud services.

Good controls for integrity management are not often considered.

## Server-side template injection

Template engines are widely used by web applications to present dynamic data via web pages and emails. Unsafely embedding user input in templates enables Server-Side Template Injection, a frequently critical vulnerability that is extremely easy to mistake for Cross-Site Scripting (XSS), or miss entirely. Unlike XSS, Template Injection can be used to directly attack web servers' internals and often obtain Remote Code Execution (RCE), turning every vulnerable application into a potential pivot point.

If fuzzing a template by injecting a sequence of special characters commonly used in template expressions, such as `${{<%[%'"}}%\`, raises an exception, it indicates that the injected template syntax is potentially being interpreted by the server in some way. This is one sign that a vulnerability to server-side template injection may exist. 

Plaintext context check: If requesting a URL such as: `http://vulnerable-website.com/?username=${7*7}`, renders `49` in the response, this shows that the mathematical operation is being evaluated server-side, and is vulnerable. 

Code context check: first establish that the parameter doesn't contain a direct XSS vulnerability by injecting arbitrary HTML into the value, the try and break out of the statement using common templating syntax and attempt to inject arbitrary HTML after it. If renders blank, either not vulnerable, or the wrong language was used for the test. If NOT renders blank, vulnerable.

Templating languages use very similar syntax that is specifically chosen not to clash with HTML characters. As a result, it can be relatively simple to create probing payloads to test which template engine is being used. Submitting invalid syntax is often enough because the resulting error message will tell exactly what the template engine is, and sometimes even which version.

## Side-channel attacks

These attacks abuse weaknesses in hardware to capture information from other instances. They are difficult to execute, and the data returned is not always predictable.

## Abusing software development kits

Cloud-based software development kits (SDKs) include command-line interfaces (CLIs) to interact with the cloud. Amazon implements `awscli`. Google Cloud Platform (GCP) implements the `gcloud` tool. Azure has the `az` tool. These may also include various other libraries to help interact with services. And, many organisations are going the route of using Infrastructure as Code (IaC).

These are all powerful tools, but this means that keys, secrets, configurations, and the data these tools become a very attractive goal.

Pentesting will have to focus on finding weaknesses in the implementation of policies and practices designed to protect this information throughout the provisioning and management process, especially when cloud SDKs and CI/CD are involved.

## Remediation

Most businesses try to get their cloud infrastructure built as cheaply as possible. Due to poor coding practices, the applications offer SQLi, XSS, CSRF vulnerabilities to hackers. The most common are listed in OWASP top 10. It is these vulnerabilities that are the root cause for the majority of cloud web services being compromised.

Outdated software contains critical security vulnerabilities that can compromise cloud services. Most software vendors do not use a streamlined update procedure or the users disable automatic updates themselves. This makes the cloud services outdated which hackers identify using automated scanners.

APIs are widely used in cloud services to share information across applications. And insecure APIs can therefor also lead to a large-scale data leak by:

* Improper use of HTTP methods like PUT, POST, DELETE in APIs can allow hackers to upload malware on the server or delete data. 
* Improper access control and lack of input sanitisation are also the main causes of APIs getting compromised.

## Resources

* [AWS IP address ranges](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html#aws-ip-download)
* [AWS IP ranges (.json)](https://ip-ranges.amazonaws.com/ip-ranges.json)
* [GrayHat Warfare](https://grayhatwarfare.com)

