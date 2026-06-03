# SQL injection

* SQL injection vulnerabilities occur due to a lack of input validation.
* To identify a SQL injection bug, enter special characters to generate an error or unexpected behaviour.
* There are three main types of SQL injection: in-band, inferential or blind, and out-band.
* The Intruder and Comparer tools in Burp automate SQL injection identification.
* Manual testing for SQL injection does not scale. Tools like SQLMap and NoSQLMap automate the exploitation.

## Steps

1. Map any of the application’s endpoints that take in user input.
2. Insert test payloads into these locations to discover whether they are vulnerable to SQL injection. Where the
   endpoint is not vulnerable to classic SQL injection, inferential techniques are the fallback.
3. Once the endpoint is confirmed vulnerable, different SQL injection queries leak information from the database.
4. Escalate the issue: establish what data the endpoint can leak and whether an authentication bypass is possible. Take
   care not to execute any action that would damage the integrity of the target’s database, such as deleting user data
   or modifying the structure of the database.
5. Draft a report with an example payload the security team can use to reproduce the result. Because SQL injection is
   often technical to exploit, a clear, easy-to-understand proof of concept is worth the time.

## Look for classic SQL injections

Classic SQL injections are the easiest to find and exploit. In classic SQL injections, the results of the SQL query are
returned directly to the attacker in an HTTP response. There are two subtypes: UNION based and error based.

## Look for blind SQL injections

Also called inferential SQL injections, blind SQL injections are a little harder to detect and exploit. They happen when
attackers cannot directly extract information from the database because the application does not return SQL data or
descriptive error messages. In this case, attackers can infer information by sending SQL injection payloads to the
server and observing its subsequent behaviour. Blind SQL injections have two subtypes as well: Boolean based and time
based.

## Exfiltrate information by using SQL injections

Sometimes the application does not use the input in a SQL query right away. Instead it uses the input unsafely during a
backend operation, so there is no way to retrieve the results via an HTTP response or to infer them from server
behaviour. Sometimes a time delay separates the moment the payload is submitted from the moment it is used in an unsafe
query, so no immediate difference shows in the application's behaviour.

In that case the database has to store the information somewhere when it runs the unsafe query.

In MySQL, the `SELECT. . .INTO` statement tells the database to store the results of a query in an output file on the
local machine.

```sql
SELECT Password FROM Users WHERE Username='admin'
INTO OUTFILE '/var/www/html/output.txt'
```

The information is then reachable at the `/output.txt` page on the target: `https://example.com/output.txt`. This also
detects second-order SQL injection, where a time delay often separates the malicious input from the query that
executes it.

## Look for NoSQL injections

Databases do not always use SQL. NoSQL, or Not Only SQL, databases are those that do not use the SQL language. Unlike
SQL databases, which store data in tables, NoSQL databases store data in other structures, such as key-value pairs and
graphs. NoSQL query syntax is database-specific, and queries are often written in the programming language of the
application. Modern NoSQL databases, such as MongoDB, Apache CouchDB, and Apache Cassandra, are also vulnerable to
injection attacks. These vulnerabilities are becoming more common as NoSQL rises in popularity.

In MongoDB syntax, `Users.find()` returns users that meet a certain criteria:

```js
Users.find({username: 'vickie', password: 'password123'});
```

If the application uses this functionality to log in users and populates the database query directly with user input,
like this:

```js
Users.find({username: $username, password: $password});
```

attackers can submit the password `{$ne: ""}` to log in as anyone. If the attacker submits:

```js
Users.find({username: 'admin', password: {$ne: ""}});
```

In MongoDB, `$ne` selects objects whose value is not equal to the specified value, and the query would return users
whose username is `admin` and password is not equal to an empty string.

Injecting into MongoDB queries can also allow attackers to execute arbitrary JavaScript code on the server. In MongoDB,
the `$where`, `mapReduce`, `$accumulator`, and `$function` operations allow developers to run arbitrary JavaScript.

Looking for NoSQL injections resembles detecting SQL injections. Special characters such as quotes (`' "`), semi-colons
(`;`), backslashes (`\`), parentheses (`()`), brackets (`[]`), and braces (`{}`) go into user-input fields, and errors
or other anomalies mark a candidate.

[NoSQLMap](https://github.com/codingo/NoSQLMap/) automates the hunting.

## Escalation

The vulnerability is one of the oldest, most widespread and most critical of web application vulnerabilities. It may be
used to neglect a web application’s certification and authorisation mechanisms and recover the contents of an entire
database. SQL injection can also be used to add, alter and remove accounts in a database, affecting data integrity:

* It may be possible to execute any malicious SQL inquiry or command through the web application and recover all the
  data saved in the database, including customer/client information, personally identifiable information (PII) such as
  names associated with social security numbers and credit card details, and credentials to access administrator
  accounts and private areas of the gateway, such as an administrator portal.
* By using an SQL injection, it is also possible to remove tables from the database.
* Depending on the server setup and software being used, by using an SQL injection vulnerability, it may be possible to
  write to a file or accomplish [operating system commands](rce.md). With such increased privileges this might result in
  a total server compromise.
* It is very hard to determine the impact of an exploited SQL injection. Attackers most often use SQL injections to
  extract information from the database. Successfully collecting data from a SQL injection is a technical task that can
  sometimes be complicated. If the hackers are skilled, it is hard to identify the attack until the data is available to
  the public and another reputation is going down the drain.

## Variants

The in-band cases retrieve hidden data from a WHERE clause, bypass a login, and run UNION
attacks to read other tables once column count and a text-bearing column are known, with
database fingerprinting and content listing differing across Oracle, MySQL, and Microsoft.
The blind cases infer data through conditional responses, conditional errors, or time delays,
and fall back to out-of-band interaction and exfiltration where nothing else differs. Filter
bypass via XML encoding slips a payload past a WAF. The
[server-side injection runbook](../runbooks/injection.md) covers detection, blind extraction,
and exploitation with sqlmap.

## Resources

* [Portswigger: SQL injection](https://portswigger.net/web-security/sql-injection)
* [OWASP: Testing for SQL Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
* [Snyk DAST/SAST tools to detect issues](https://snyk.io/)

## Counter moves

SQL injection is the variant in play. These come back to the same answers: validated input, encoded output, server-side
authorisation, and patched dependencies. Seen from the other side, this sits in the blue notes
on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
