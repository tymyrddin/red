# HMI security testing

![HMI](/_static/images/ot-hmi.png)

When the user interface is the weakest link (it usually is).

Human-Machine Interfaces are where operators interact with industrial processes. They're the screens showing pretty graphics of turbines spinning, tanks filling, and valves opening. They're the buttons that make things happen in the physical world. They're also, almost universally, the weakest security link in OT environments.

HMIs are typically Windows-based applications running on general-purpose computers. This means they inherit all the security problems of Windows, plus application-specific vulnerabilities, plus configuration mistakes made during deployment. Unlike PLCs which have limited attack surfaces, HMIs are full-featured computers with web browsers, file systems, user accounts, and network connectivity.

The good news is that HMI security testing uses familiar IT security techniques. The bad news is that HMIs in OT environments are often configured with security practices that would make an IT security team weep.

So apologies. Much of this is Security 101 material, but industrial applications frequently miss these basics.

## Default credentials (the eternal plague)

Default credentials are the original sin of industrial systems. Vendors ship products with default usernames and passwords intended for initial setup. These are supposed to be changed during commissioning. They rarely are.

### Why default credentials persist

The reasons are depressingly familiar. "Changing credentials might affect licensing" is a common vendor warning that terrifies system owners. "Multiple vendors need access" leads to keeping default credentials so everyone knows them. "We'll change them after testing" becomes "we never changed them" when the system goes live and nobody wants to risk breaking it. "The password is documented in the manual" which means everyone who has the manual knows the password, which is everyone including attackers.

### Common default credentials in HMI systems

Wonderware InTouch uses admin/admin, operator/operator, and sometimes username/password (yes, really).

Siemens WinCC uses various defaults depending on version, often with blank passwords for certain accounts.

Rockwell FactoryTalk View uses default passwords that are well-documented in public manuals and security advisories.

Ignition by Inductive Automation has improved significantly in recent versions by requiring password changes during setup, but older installations often have admin/password.

Generic credentials that appear everywhere include admin/admin, administrator/administrator, root/root, user/user, and guest/guest.

### Testing for default credentials

The approach is straightforward and requires no sophisticated tools. Try common defaults first using 
[lists of industrial default credentials](https://github.com/scadastrangelove/SCADAPASS). Try vendor-specific defaults 
from product documentation. Try variations (admin/admin123, admin/Admin, admin/password).

At UU P&L, testing default credentials on the main SCADA HMI produced immediate results:

```
URL: http://192.168.20.5:8080
Username: admin
Password: admin
Result: Login successful
```

The login screen helpfully displayed "Wonderware InTouch Web Client 2014 R2". A quick search found that admin/admin was indeed the documented default for this version. It had never been changed.

Once logged in with admin credentials, the interface provided complete operator control including viewing all process data, acknowledging alarms, issuing control commands to PLCs, modifying setpoints, and accessing system configuration.

When asked why the password hadn't been changed, the response was memorable: "The vendor said changing it might affect licensing. We didn't want to risk it. Also, everyone knows the password anyway, so what's the point?"

This is not an isolated incident. This is normal in OT. Default credentials work far more often than they should, and the reasons for not changing them are variations on the same themes of fear, convenience, and institutional inertia.

## Web interface vulnerabilities

Modern HMIs almost universally provide web interfaces for remote access. These web interfaces are developed by industrial automation experts, not web security experts. The results are predictable.

### Common web vulnerabilities in HMIs

- [Directory traversal](../../in/app/techniques/traversal.md) allows accessing files outside the web root. Many HMI web servers don't properly validate file paths, allowing attackers to read arbitrary files on the system.
- [SQL injection](../../in/app/techniques/sqli.md) appears in search functions, reporting modules, and anywhere user input interacts with databases without proper sanitization.
- [Cross-site scripting (XSS)](../../in/app/techniques/xss.md) occurs when HMIs display user-controllable data without encoding, allowing script injection.
- [Authentication bypass vulnerabilities](../../in/app/techniques/auth.md) appear when developers implement custom authentication rather than using proven frameworks. 
- Session management flaws include predictable session tokens, no session expiration, and session tokens in URLs rather than cookies.
- [Insecure direct object references](../../in/app/techniques/idor.md) allow accessing resources by guessing IDs rather than going through proper authorization checks.

### Testing HMI web interfaces

Use standard web application testing tools. [Burp Suite Community Edition](https://portswigger.net/burp/communitydownload) provides an intercepting proxy, scanner, and various tools for web testing. [OWASP ZAP](https://www.zaproxy.org/) is an open-source alternative with similar functionality.

The testing process is straightforward. Configure your browser to use Burp/ZAP as proxy (using [FoxyProxy](https://getfoxyproxy.org/downloads/#proxypanel) for example). Navigate through the HMI web interface normally. Observe all requests and responses. Identify injection points (parameters, form fields, cookies). Test for common vulnerabilities systematically.

### Directory traversal testing at UU P&L

The SCADA HMI web interface had a file download function for retrieving reports. The URL looked like:

```
http://192.168.20.5:8080/reports/download?file=daily_report.pdf
```

Tried modifying the filename parameter:

```
http://192.168.20.5:8080/reports/download?file=../../../windows/win.ini
```

The server helpfully returned the contents of win.ini, confirming directory traversal was possible. Further testing 
revealed the ability to read arbitrary files on the system including configuration files with database credentials, 
project files with PLC configurations, and backup files containing password hashes.

The vulnerability existed because the application took the filename parameter directly from the URL and passed 
it to the filesystem without validation. 

### SQL injection testing at UU P&L

The historian web interface had a search function for querying historical data:

```
http://192.168.30.5/search?tag=TURB01_SPEED&start=2024-01-01&end=2024-01-31
```

Testing for SQL injection using simple payloads:

```
http://192.168.30.5/search?tag=TURB01_SPEED'--
```

The server returned an SQL error message displaying the actual query:

```
Error: You have an error in your SQL syntax near 'TURB01_SPEED'--' at line 1
Full query: SELECT * FROM historian WHERE tag='TURB01_SPEED'--' AND timestamp BETWEEN '2024-01-01' AND '2024-01-31'
```

This confirmed SQL injection and revealed the database structure. With SQL injection, an attacker can read all data from the database, modify data (historical data manipulation would hide attacks), delete data, or potentially execute operating system commands depending on database permissions.

The application was constructing SQL queries by string concatenation rather than using parameterised queries. Again, this is fundamental web security, but industrial applications often use development practices from decades ago when SQL injection was less well understood.

## Authentication bypass

Some HMIs implement custom authentication mechanisms. These are frequently broken in creative ways.

### Common authentication bypass patterns

- Parameter manipulation changes authentication parameters to bypass checks. For example, adding `&admin=true` to login requests.
- Forced browsing involves directly accessing authenticated pages without logging in.
- Session prediction uses predictable session tokens to hijack other users' sessions.
- Logic flaws in authentication flow allow bypassing authentication through unexpected sequences of requests.

### Authentication bypass at UU P&L

The HMI web interface had a curious authentication mechanism. After successful login, it set a cookie:

```
Set-Cookie: auth=user:operator:1
```

The cookie format appeared to be username:role:authenticated_flag. Testing whether this could be manipulated was trivial. Modify the cookie to:

```
Cookie: auth=admin:administrator:1
```

Refresh the page. The interface now displayed with full administrative privileges. No password required, no verification that the user actually logged in as admin, just blind trust in a client-side cookie.

This is what happens when developers implement security without understanding security. The authentication check was performed client-side in JavaScript, and the server trusted whatever the cookie claimed.

A slightly more sophisticated variant was found on another system. The HMI checked authentication by calling an API:

```
GET /api/checkAuth HTTP/1.1
Cookie: sessionid=abc123
```

The API returned:

```json
{"authenticated": false, "role": "guest"}
```

The web interface JavaScript checked this response and showed/hid interface elements accordingly. But all enforcement was client-side. If you simply didn't call the API, or modified its response using a proxy, the server would happily execute any commands you sent it.

Server-side enforcement didn't exist. Client-side controls were the only controls. This is security theatre.

## Session management flaws

Session management in industrial HMIs is often implemented badly, if it's implemented at all.

### Common session management problems

- No session expiration means sessions remain valid indefinitely. Users log in once and stay logged in forever, even 
after they've left the company.
- Predictable session tokens use sequential IDs or timestamps, allowing attackers to guess valid tokens.
- Session tokens in URLs rather than cookies make tokens visible in logs, browser history, and referrer headers.
- No session invalidation on logout means logging out doesn't actually end the session, just removes it from the browser.

### Session management testing at UU P&L

The SCADA HMI used session tokens in URLs:

```
http://192.168.20.5:8080/dashboard?session=12345678
```

Session tokens appeared to be sequential. After logging in, session ID was 12345678. Logging in again with a different 
account gave 12345679. This suggested that guessing valid session IDs would be trivial.

Testing confirmed this. Incrementing the session ID by one accessed another user's session. It was possible to iterate 
through session IDs and hijack any active session.

Session expiration was tested by logging in, noting the session token, logging out, and trying to use the old session 
token. It still worked. Logout didn't actually invalidate the session.

Waiting 24 hours and testing the session token again, it still worked. Sessions appeared to never expire.

This meant that anyone who had ever logged into the system and whose session ID could be guessed could have their 
session hijacked indefinitely.

## Insecure file handling

HMIs often handle various files including configuration files, project files, reports, and logs. File handling 
is frequently insecure.

### File upload vulnerabilities

Some HMIs allow uploading files such as configuration files, trend templates, or custom graphics. If upload 
functionality doesn't validate file types, attackers can upload web shells or malicious executables.

At UU P&L, the HMI allowed uploading custom graphics for displays. Testing revealed that it accepted any file 
type, not just images. Uploading a PHP web shell:

```php
<?php system($_GET['cmd']); ?>
```

Saved as graphic.php and uploaded successfully. Accessing the file:

```
http://192.168.20.5:8080/uploads/graphic.php?cmd=whoami
```

Returned command output, confirming code execution. The HMI web server was running PHP and executing uploaded files without restriction.

### File download vulnerabilities

Beyond the directory traversal issues already discussed, file downloads often expose sensitive data that should be restricted.

The HMI at UU P&L had a backup function that created ZIP files of configuration. These were stored in a web-accessible directory with predictable names:

```
http://192.168.20.5:8080/backups/backup_2024-03-15.zip
```

No authentication was required to download these backups. Anyone who knew or guessed the URL could download complete HMI configurations including all passwords (which were stored in plaintext in XML files within the backup).

## Project file extraction

HMI project files contain complete application configurations including screen layouts, scripts, database connections, and often credentials. Extracting these files provides attackers with detailed knowledge of the system.

### Methods of project file extraction

- Direct file access through directory traversal or insecure file download functions.
- Backup file access as described above.
- Database extraction if project data is stored in databases.
- Network share access if project files are shared over the network.

### Project file analysis

Once extracted, project files can be analysingd for valuable information including database connection strings with credentials, PLC IP addresses and communication settings, alarm configurations and setpoints, user accounts and passwords, scripts containing business logic, and network topology information.

At UU P&L, the extracted HMI backup contained XML configuration files. Opening them in a text editor revealed:

```xml
<DatabaseConnection>
  <Server>192.168.30.5</Server>
  <Database>Historian</Database>
  <Username>sa</Username>
  <Password>Historian2015!</Password>
</DatabaseConnection>

<PLCConnection>
  <Type>Siemens S7</Type>
  <IP>192.168.10.10</IP>
  <Rack>0</Rack>
  <Slot>1</Slot>
</PLCConnection>

<UserAccounts>
  <User>
    <Username>admin</Username>
    <Password>admin</Password>
    <Role>Administrator</Role>
  </User>
  <User>
    <Username>operator</Username>
    <Password>operator</Password>
    <Role>Operator</Role>
  </User>
</UserAccounts>
```

Complete credentials, network information, and configuration in plaintext. This is extremely common in 
industrial systems. Encryption of credentials in configuration files is rare because it requires key 
management, and key management is difficult.

## Hardcoded secrets

Industrial applications frequently contain hardcoded credentials, API keys, and cryptographic secrets.

### Where hardcoded secrets appear

- JavaScript files in web interfaces often contain API endpoints with embedded keys.
- Configuration files include default passwords that are never changed.
- Binary files and executables contain credentials compiled into the application.
- Comments in source code (when accessible) sometimes include passwords and connection strings.

### Finding hardcoded secrets

Search project files and web resources for common patterns such as password=, api_key=, secret=, or connection strings. Use tools like [truffleHog](https://github.com/trufflesecurity/truffleHog) for automated secret scanning in code repositories.

At UU P&L, the HMI web interface JavaScript contained:

```javascript
const API_KEY = "1234567890ABCDEF";
const DB_PASSWORD = "xor_encrypted_but_key_is_here";
const ADMIN_BACKDOOR = "vendor_support_password_123";
```

The "encryption" mentioned in comments was XOR with a fixed key, which is not encryption but obfuscation. The XOR key was in the same JavaScript file. Reversing it took seconds.

The admin backdoor was particularly concerning. It was a hardcoded password that provided administrative access regardless of other authentication mechanisms. This was presumably intended for vendor support, but it meant anyone with access to the JavaScript could log in with full admin privileges.

## Client-side controls

Many HMIs implement security controls entirely client-side. The server trusts whatever the client sends without verification.

### Types of client-side controls

- Authorization checks in JavaScript that show/hide interface elements but don't prevent access to underlying functionality.
- Input validation in JavaScript that can be bypassed by modifying requests directly.
- Rate limiting in JavaScript that doesn't apply when bypassing the web interface.
- Command filtering that checks commands client-side but not server-side.

### Bypassing client-side controls

Use a proxy like Burp Suite to intercept and modify requests. The client-side checks never see the modified requests, but the server processes them.

At UU P&L, the HMI web interface had administrator-only functions that were hidden in the UI for operator accounts. The JavaScript checked the user's role and hid the buttons:

```javascript
if (userRole !== "administrator") {
  document.getElementById("dangerousButton").style.display = "none";
}
```

But the button still existed in the HTML, just hidden. Using browser developer tools, it could be made visible and clicked. More directly, the button called a function that could be called from the browser console:

```javascript
executeDangerousCommand("SHUTDOWN_ALL_TURBINES");
```

The server executed the command without checking whether the user had permission. It trusted that only administrators could call this function because the button was hidden for other users.

This is security by obscurity, and obscurity on the client side at that. It's not security at all.

## Remote code execution via HMI

The ultimate goal of many attacks is code execution on the HMI system. This provides complete control over the HMI and often the ability to pivot to other systems.

### Paths to code execution

File upload vulnerabilities allowing uploading and executing web shells or executables.

SQL injection with xp_cmdshell on SQL Server allowing command execution.

Command injection in application functions that execute system commands.

Deserialization vulnerabilities in applications using insecure deserialization.

### Remote code execution at UU P&L

The HMI had a system diagnostics function that executed ping commands:

```
http://192.168.20.5:8080/diagnostics/ping?host=192.168.10.10
```

The application appeared to execute `ping <host>` on the server. Testing for command injection:

```
http://192.168.20.5:8080/diagnostics/ping?host=192.168.10.10;whoami
```

The response included ping output followed by the output of whoami, confirming command injection. The application was concatenating user input directly into shell commands:

```python
os.system("ping " + user_input)
```

With command injection, complete control of the server was possible:

```
http://192.168.20.5:8080/diagnostics/ping?host=127.0.0.1;net user attacker P@ssw0rd /add
```

This created a new user account on the Windows server. Subsequent commands could add the user to administrators, enable RDP, download additional tools, or pivot to other systems on the network.

## The cumulative impact

Each vulnerability individually is concerning. Taken together, they paint a picture of systems that were never designed with security in mind.

At UU P&L, the HMI vulnerabilities included default credentials allowing immediate access, directory traversal exposing all files on the system, SQL injection compromising the historian database, authentication bypass via cookie manipulation, session hijacking through predictable tokens, file upload allowing web shell deployment, hardcoded credentials in JavaScript, client-side authorization easily bypassed, and command injection enabling remote code execution.

Any one of these would allow an attacker to compromise the HMI. All of them together meant the HMI security was essentially non-existent.

The recommendations were extensive and expensive because fixing these issues properly required both application changes (which required vendor cooperation) and architectural changes (which required budget and downtime).

Short-term mitigations included network segmentation to limit who could reach HMI web interfaces, web application firewall to block common attacks (imperfect but better than nothing), disabling unnecessary web interface features, implementing proper authentication at network level, and increased logging and monitoring.

Long-term fixes required vendor patches to address application vulnerabilities, complete redesign of authentication and authorization, moving from client-side to server-side security controls, and potentially replacing systems that couldn't be adequately secured.

The depressing reality is that HMI security is rarely a priority until after an incident. The systems work, operators are comfortable with them, and change is risky in operational environments. Security vulnerabilities that would be considered critical in IT systems are accepted as normal in OT because "that's how these systems are".

But normalcy doesn't equal security. The HMIs at UU P&L were utterly compromised and remained so because fixing them properly would take years and significant investment. In the meantime, network segmentation and monitoring were the only defences, and those defences were themselves imperfect.

This is the reality of OT security. It's messy, it's compromised, and it's the best we can do with systems that were never designed for hostile networks.
