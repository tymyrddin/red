# SCADA server assessment

![SCADA](/_static/images/ot-scada.png)

The command centre that commands too much trust.

SCADA (Supervisory Control and Data Acquisition) servers are the nerve centres of industrial operations. They collect data from hundreds or thousands of field devices, present it to operators through HMIs, log everything for historical analysis, and send control commands back to the field. They're the systems that operators stare at for 12-hour shifts, that engineers rely on for troubleshooting, and that management uses for operational reporting.

They're also usually Windows servers running complex applications developed by industrial automation companies, which means they combine the security problems of Windows servers with the security problems of specialised industrial software. The result is predictably problematic.

Unlike PLCs which are embedded devices with limited attack surfaces, SCADA servers are full-fledged computers. They have operating systems, file systems, databases, web servers, and network connectivity to everything. They're typically accessible from corporate networks (because engineers and managers need access), which makes them prime targets for attackers who've compromised corporate IT and are looking for paths into OT.

## Operating system hardening (or lack thereof)

SCADA servers run operating systems, typically Windows Server or occasionally Linux. These operating systems should be hardened according to security best practices. They rarely are.

### Why SCADA servers remain unhardened

The SCADA application vendor specifies exact operating system configurations. Deviating from these specifications "voids warranty" or "isn't supported". These specifications often include disabling security features because they might interfere with SCADA operations.

The servers require specific Windows versions. Upgrading the OS requires upgrading SCADA, which requires downtime, testing, and budget. So systems stay on Windows Server 2003, 2008, or other obsolete versions.

Patching is risky because patches might break SCADA applications. Testing patches requires comprehensive validation. So patches are delayed, skipped, or never applied.

Security software causes problems. Antivirus scanning can interfere with real-time performance. Host-based firewalls can block SCADA communications. EDR tools can flag normal SCADA operations as suspicious. So security software gets disabled.

### Assessing operating system security

Standard IT security tools work on SCADA servers. [Nmap](https://nmap.org/) for service enumeration. [Nessus](https://www.tenable.com/products/nessus) or [OpenVAS](https://www.openvas.org/) for vulnerability scanning. [Windows-Exploit-Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester) for patch analysis.

However, aggressive scanning can impact SCADA performance. Use minimal scan profiles, scan during low-activity periods, and monitor system performance during scanning.

At UU P&L, the primary SCADA server assessment revealed Windows Server 2012 R2, last patched in 2015, missing approximately 2,847 security patches (yes, that number is real), and no antivirus installed (disabled in 2013 because "it caused CPU spikes").

The server had 47 services running, many unnecessary for SCADA operations (print spooler, remote registry, etc.). Administrative shares were enabled with no password on the Administrator account (password had been removed years ago because "we kept forgetting it").

RDP was enabled and accessible from the corporate network with no network-level authentication required. The last login to the Administrator account was from an IP address in China three months prior. Nobody noticed because nobody monitored the server.

### Basic hardening recommendations

Even without touching the SCADA application, basic hardening is possible: disable unnecessary services, remove unnecessary user accounts, enable Windows Firewall with appropriate rules, apply security patches (after testing), implement proper authentication, enable audit logging, restrict administrative access, and monitor for suspicious activities.

At UU P&L, the immediate recommendations were change the Administrator password (ideally disable the account and use named admin accounts), enable Windows Firewall, disable administrative shares or require authentication, review and disable unnecessary services, and implement logging with alerts for security events.

These changes were all possible without touching the SCADA application. They were all declined initially because "we don't want to change anything that's working". After the Chinese IP address login was highlighted, the Administrator password was changed. The other recommendations remained "under consideration".

## Application security

SCADA applications are complex software packages with web interfaces, database backends, scripting engines, and numerous integration points. They're developed by industrial automation companies, not security software companies.

### Common SCADA application vulnerabilities

Authentication weaknesses include default credentials that are never changed, weak password policies allowing short or simple passwords, and no account lockout after failed login attempts.

Authorization flaws allow privilege escalation from operator to administrator, accessing functionality beyond assigned roles, and no segregation between viewing and controlling.

Input validation failures lead to SQL injection in database queries, command injection in script execution, and path traversal in file operations.

Session management issues include sessions that never expire, predictable session tokens, and session tokens in URLs rather than cookies.

### Testing SCADA applications

SCADA applications typically have web interfaces. These can be tested using standard web application tools like [Burp Suite](https://portswigger.net/burp) or [OWASP ZAP](https://www.zaproxy.org/).

However, SCADA web interfaces often interact with live industrial processes. Testing carefully is essential. Avoid automated scanners that might send hundreds of requests. Manual testing is safer. Test during low-activity periods. Have operators aware testing is occurring.

At UU P&L, the Wonderware InTouch SCADA web interface had numerous vulnerabilities. Authentication was admin/admin (already discovered). Once authenticated, the interface provided full operator control including viewing all process data, acknowledging alarms, sending control commands to PLCs, and modifying setpoints.

Testing for SQL injection in the alarm search function:

```
http://192.168.20.5:8080/alarms/search?query=test' OR '1'='1
```

The server returned all alarms, not just those matching "test". SQL injection confirmed. Further testing revealed the ability to extract database contents, including user password hashes.

The password hashes were MD5 with no salt. Cracking them took minutes:
- admin: admin (already known)
- operator: operator (also not surprising)  
- engineer: engineer123 (slightly more creative)
- manager: Password1 (the pinnacle of security)

## Database security

SCADA systems use databases for configuration, historical data, alarm logs, and user accounts. These databases are often Microsoft SQL Server, sometimes PostgreSQL or proprietary databases.

### Database security issues

Default credentials on SQL Server 'sa' account with blank or simple passwords.

Over-privileged accounts where SCADA application connects with db_owner or sysadmin rights.

No encryption of data at rest means database files contain plaintext sensitive data.

No encryption in transit means database credentials and data pass over network in cleartext.

Direct database access allowed from other systems without going through SCADA application.

### Assessing database security

Identify database type and version through service scanning or application configuration. Test default credentials (sa account on SQL Server, postgres on PostgreSQL). Check database permissions for application accounts. Review database configurations for security settings. Test for SQL injection in application (already covered above).

At UU P&L, the historian database was SQL Server 2008. The 'sa' account had password "Historian2015!" (which was at least better than blank). However, the 'sa' account was enabled and accessible from the network.

The SCADA application connected to SQL Server as 'sa', giving it complete database control. This is excessive; the application only needs specific table access.

The database wasn't encrypted. Copying the database files revealed all historical data, configuration, and user information in plaintext (well, except the MD5 hashes which we'd already cracked).

### SQL Server xp_cmdshell

SQL Server has an extended stored procedure called xp_cmdshell that executes operating system commands. If an attacker gains 'sa' or sysadmin access, they can enable xp_cmdshell and execute arbitrary commands on the server.

At UU P&L, testing (after obtaining 'sa' credentials through SQL injection) confirmed xp_cmdshell worked:

```sql
EXEC xp_cmdshell 'whoami'
```

Returned `NT AUTHORITY\SYSTEM`, confirming command execution with highest privileges. From here, complete server compromise was trivial.

## OPC UA security testing

OPC UA (Open Platform Communications Unified Architecture) is increasingly common for SCADA integration. It's more secure than older protocols but only if configured properly.

### OPC UA security modes

None provides no encryption or authentication. Messages pass in cleartext, anyone can connect.

Sign provides message authentication but not encryption. Messages are authenticated but readable.

SignAndEncrypt provides full security with authentication and encryption.

### OPC UA authentication

Anonymous allows anyone to connect without credentials.

Username/password requires credentials but passwords can be weak.

Certificate-based provides strong authentication using X.509 certificates.

### Testing OPC UA

Tools like [opcua-asyncio](https://github.com/FreeOpcUa/opcua-asyncio) allow 🐙 [probing OPC UA servers](https://github.com/ninabarzh/power-and-light/blob/main/vulns/opcua_readonly_probe.py)

At UU P&L, the SCADA server ran an OPC UA server on port 4840. Testing revealed SecurityMode was None (no encryption), authentication was Anonymous (no credentials required), and all tags were readable and writeable by anyone who could connect.

This meant anyone with network access to port 4840 could read all process values, write control commands, and modify configurations through OPC UA, completely bypassing the SCADA application's authentication and authorization.

## API vulnerabilities

Modern SCADA systems expose APIs for integration with other systems. These APIs are often poorly secured.

### Common API security issues

No authentication required for API access. Anyone who can reach the API can use it.

Weak authentication using simple API keys that never rotate or are embedded in client applications.

No rate limiting allows automated attacks or denial of service.

Excessive data exposure where APIs return more information than necessary.

Insecure direct object references allow accessing resources by guessing IDs.

### Testing APIs

Identify API endpoints through documentation, directory bruteforcing, or JavaScript analysis. Test endpoints without authentication. Test with invalid authentication. Test for injection vulnerabilities. Test for authorization bypass. Test for rate limiting.

At UU P&L, the SCADA web interface used a REST API for data retrieval. The API was discovered by examining JavaScript:

```javascript
fetch('/api/v1/tags/TURB01_SPEED')
  .then(response => response.json())
  .then(data => updateDisplay(data));
```

Testing the API revealed no authentication required:

```bash
curl http://192.168.20.5:8080/api/v1/tags/TURB01_SPEED
```

Returned current turbine speed. Testing other endpoints:

```bash
curl http://192.168.20.5:8080/api/v1/tags/
```

Returned a list of all available tags (thousands of them). Testing write operations:

```bash
curl -X POST http://192.168.20.5:8080/api/v1/tags/TURB01_SETPOINT \
  -H "Content-Type: application/json" \
  -d '{"value": 3600}'
```

Successfully changed turbine setpoint through the API with no authentication. This was tested on a safe tag (not actually sent to production), but the vulnerability was clear.

## Script injection in alarm systems

SCADA systems often allow scripts in alarm configurations. If these scripts don't properly validate input, script injection is possible.

### Where scripts appear

Alarm actions can execute scripts when alarms trigger. Email notifications may include scripted content. Reports generate using scripting languages. Custom displays may contain embedded scripts.

### Script injection testing

Identify where user input appears in scripts. Test for common injection patterns. Check if scripts execute with elevated privileges.

At UU P&L, the alarm system allowed configuring email notifications with customizable message text. Testing revealed the message text was processed by a scripting engine before sending.

Creating an alarm with message text:

```
Alarm: ${tag_name} - Value: ${tag_value}
${system("whoami")}
```

When the alarm triggered, the email contained the output of the `whoami` command, confirming script injection. The script executed as the SCADA service account, which had local administrator privileges.

## SQL injection in reporting modules

SCADA reporting modules frequently have SQL injection vulnerabilities because they dynamically construct queries based on user input.

### Vulnerable reporting patterns

Date range selection where start/end dates are inserted directly into SQL. Tag selection where tag names are concatenated into queries. Filtering options where filter criteria become part of WHERE clauses.

### SQL injection in reports

At UU P&L, the historian reporting module had severe SQL injection. The report generation URL:

```
http://192.168.30.5/reports/generate?start=2024-01-01&end=2024-01-31&tags=TURB01_SPEED
```

Testing the tags parameter:

```
http://192.168.30.5/reports/generate?start=2024-01-01&end=2024-01-31&tags=TURB01_SPEED' UNION SELECT username,password FROM users--
```

The generated report included the contents of the users table. SQL injection was trivial, and the database connection had excessive privileges allowing reading any table.

## File inclusion vulnerabilities

SCADA web interfaces sometimes include files dynamically based on user input. This can lead to local or remote file inclusion.

### Testing file inclusion

Identify file path parameters in URLs. Test for directory traversal. Test for remote file inclusion if the application fetches external resources.

At UU P&L, the SCADA web interface had a documentation viewer:

```
http://192.168.20.5:8080/docs/view?file=user_manual.pdf
```

Testing file parameter:

```
http://192.168.20.5:8080/docs/view?file=../../../windows/system32/drivers/etc/hosts
```

Returned the hosts file. Testing with configuration files:

```
http://192.168.20.5:8080/docs/view?file=../../../ProgramData/Wonderware/config.xml
```

Returned SCADA configuration including database credentials, PLC connection settings, and user account information.

## Access control bypass

SCADA applications should enforce role-based access control. Implementation is often flawed.

### Common access control flaws

Client-side enforcement where JavaScript hides buttons but doesn't prevent actions. Parameter manipulation where changing role parameters grants higher privileges. Direct URL access to administrative functions without checking permissions.

At UU P&L, operator accounts couldn't access the configuration interface (buttons were hidden). However, the configuration URL was still accessible:

```
http://192.168.20.5:8080/admin/configure
```

Accessing this URL directly, while logged in as operator, displayed the full configuration interface. The server never checked whether the user had admin privileges, only the client-side JavaScript did.

## Privilege escalation

Privilege escalation allows moving from low-privilege to high-privilege access.

### Escalation vectors in SCADA

Exploiting OS vulnerabilities to gain SYSTEM privileges. Abusing SCADA service accounts that run with excessive privileges. Leveraging database access to modify user roles. Exploiting application vulnerabilities to execute code as privileged users.

At UU P&L, the SCADA service ran as Local System (highest Windows privilege). The application allowed operators to upload custom display files. These files were processed by the SCADA service.

Uploading a malicious display file that executed code when processed gave SYSTEM-level code execution, complete privilege escalation from unprivileged operator to system administrator through file upload.

## The cumulative disaster

Each vulnerability individually is serious. Together, they paint a picture of complete security failure.

At UU P&L, the SCADA server had OS that hadn't been patched in 9 years, no antivirus, Administrator account with no password, default credentials on the application, SQL injection in multiple places, unauthenticated API access, script injection in alarms, file inclusion vulnerabilities, access control that could be bypassed, and multiple paths to privilege escalation.

Any attacker who reached the SCADA server (which was accessible from corporate network) could completely compromise it in minutes. From there, they could control all PLCs, manipulate all processes, and cause operational disruption or safety incidents.

The recommendations were extensive because the problems were extensive. Immediate actions included patching the OS (gradually, with testing), enabling and configuring antivirus, setting strong passwords on all accounts, changing default credentials, restricting database access, disabling unnecessary services, implementing network segmentation, and enabling comprehensive logging.

Application-level fixes required vendor patches for SQL injection, script injection, file inclusion, and access control issues. Some of these patches existed, others required custom development. Implementation would take months.

The long-term recommendation was replacing the SCADA system with a modern, security-focused platform. This would take years and cost hundreds of thousands of euros. Until then, the system would remain vulnerable, mitigated only by network segmentation, monitoring, and hoping attackers didn't notice.

This is the reality of SCADA security. Systems that were never designed with security in mind, running on outdated infrastructure, protected by credentials that haven't changed in decades. Fixing them properly is expensive and time-consuming. Not fixing them is dangerous. Organizations choose the compromise of partial mitigations and accepting residual risk, because complete solutions are beyond current budgets and operational constraints.
