# SQL injection

* SQL injection vulnerabilities occur due to a lack of input validation.
* To identify a SQL injection bug, enter special characters to generate an error or unexpected behaviour.
* There are three main types of SQL injection: in-band, inferential or blind, and out-band.
* You can use the Intruder and Comparer tools in Burp, to automate SQL injection identification.
* Testing for SQL injection manually isn’t scalable. Using tools like SQLMap and NoSQLMap, it is possible to automate SQL injection exploitation.

## Steps

1. Map any of the application’s endpoints that take in user input.
2. Insert test payloads into these locations to discover whether they’re vulnerable to SQL injections. If the endpoint isn’t vulnerable to classic SQL injections, try inferential techniques instead.
3. Once you’ve confirmed that the endpoint is vulnerable to SQL injections, use different SQL injection queries to leak information from the database.
4. Escalate the issue. Figure out what data you can leak from the endpoint and whether you can achieve an authentication bypass. Be careful not to execute any actions that would damage the integrity of the target’s database, such as deleting user data or modifying the structure of the database.
5. Draft up a report with an example payload that the security team can use to duplicate your results. Because SQL injections are quite technical to exploit most of the time, it’s a good idea to spend some time crafting an easy-to-understand proof of concept.

## Look for classic SQL injections

Classic SQL injections are the easiest to find and exploit. In classic SQL injections, the results of the SQL query are returned directly to the attacker in an HTTP response. There are two subtypes: UNION based and error based.

## Look for blind SQL injections

Also called inferential SQL injections, blind SQL injections are a little harder to detect and exploit. They happen when attackers cannot directly extract information from the database because the application does not return SQL data or descriptive error messages. In this case, attackers can infer information by sending SQL injection payloads to the server and observing its subsequent behaviour. Blind SQL injections have two subtypes as well: Boolean based and time based.

## Exfiltrate information by using SQL injections

Imagine that the web application you’re attacking does not use your input in a SQL query right away. Instead, it uses the input unsafely in a SQL query during a backend operation, so you have no way to retrieve the results of injection via an HTTP response, or infer the query’s results by observing server behaviour. Sometimes there’s even a time delay between when you submitted the payload and when the payload gets used in an unsafe query, so you won’t immediately be able to observe differences in the application's behaviour.

In this case, you will need to make the database store information somewhere when it does run the unsafe SQL query.

In MySQL, the `SELECT. . .INTO` statement tells the database to store the results of a query in an output file on the local machine.

    SELECT Password FROM Users WHERE Username='admin'
    INTO OUTFILE '/var/www/html/output.txt'

Then access the information by navigating to the `/output.txt` page on the target: `https://
example.com/output.txt`. This technique is also a good way to detect second-order SQL injections, since in second-order SQL injections, there is often a time delay between the malicious input and the SQL query being executed.

## Look for NoSQL injections

Databases do not always use SQL. NoSQL, or Not Only SQL, databases are those that do not use the SQL language. Unlike SQL databases, which store data in tables, NoSQL databases store data in other structures, such as key-value pairs and graphs. NoSQL query syntax is database-specific, and queries are often written in the programming language of the application. Modern NoSQL databases, such as MongoDB, Apache CouchDB, and Apache Cassandra, are also vulnerable to injection attacks. These vulnerabilities are becoming more common as NoSQL rises in popularity.

In MongoDB syntax, `Users.find()` returns users that meet a certain criteria:

    Users.find({username: 'vickie', password: 'password123'});

If the application uses this functionality to log in users and populates the database query directly with user input, like this:

    Users.find({username: $username, password: $password});

attackers can submit the password `{$ne: ""}` to log in as anyone. If the attacker submits:

    Users.find({username: 'admin', password: {$ne: ""}});

In MongoDB, `$ne` selects objects whose value is not equal to the specified value, and the query would return users whose username is `admin` and password is not equal to an empty string.

Injecting into MongoDB queries can also allow attackers to execute arbitrary JavaScript code on the server. In MongoDB, the `$where`, `mapReduce`, `$accumulator`, and `$function` operations allow developers to run arbitrary JavaScript.

The process of looking for NoSQL injections is similar to detecting SQL injections. You can insert special characters such as quotes (`' "`), semi-colons (`;`), and backslashes (`\`), as well as parentheses (`()`), brackets(`[]`), and braces (`{}`) into user-input fields and look for errors or other anomalies.

You can also automate the hunting process by using the tool [NoSQLMap](https://github.com/codingo/NoSQLMap/).

## Escalation

The vulnerability is one of the oldest, most widespread and most critical of web application vulnerabilities. It may be used to neglect a web application’s certification and authorisation mechanisms and recover the contents of an entire database. SQL injection can also be used to add, alter and remove accounts in a database, affecting data integrity:

* It may be possible to execute any malicious SQL inquiry or command through the web application and recover all the data saved in the database, including customer/client information, personally identifiable information (PII) such as names associated with social security numbers and credit card details, and credentials to access administrator accounts and private areas of the gateway, such as an administrator portal. 
* By using an SQL injection, it is also possible to remove tables from the database.
* Depending on the server setup and software being used, by using an SQL injection vulnerability, it may be possible to write to a file or accomplish [operating system commands](rce.md). With such increased privileges this might result in a total server compromise.
* It is very hard to determine the impact of an exploited SQL injection. Attackers most often use SQL injections to extract information from the database. Successfully collecting data from a SQL injection is a technical task that can sometimes be complicated. If the hackers are skilled, it is hard to identify the attack until the data is available to the public and another reputation is going down the drain.

## Portswigger lab writeups

* [SQL injection vulnerability in WHERE clause allowing retrieval of hidden data](../burp/sqli/1.md)
* [SQL injection vulnerability allowing login bypass](../burp/sqli/2.md)
* [SQL injection UNION attack, determining the number of columns returned by the query](../burp/sqli/3.md)
* [SQL injection UNION attack, finding a column containing text](../burp/sqli/4.md)
* [SQL injection UNION attack, retrieving data from other tables](../burp/sqli/5.md)
* [SQL injection UNION attack, retrieving multiple values in a single column](../burp/sqli/6.md)
* [SQL injection attack, querying the database type and version on Oracle](../burp/sqli/7.md)
* [SQL injection attack, querying the database type and version on MySQL and Microsoft](../burp/sqli/8.md)
* [SQL injection attack, listing the database contents on non-Oracle databases](../burp/sqli/9.md)
* [SQL injection attack, listing the database contents on Oracle](../burp/sqli/10.md)
* [Blind SQL injection with conditional responses](../burp/sqli/11.md)
* [Blind SQL injection with conditional errors](../burp/sqli/12.md)
* [Blind SQL injection with time delays](../burp/sqli/13.md)
* [Blind SQL injection with time delays and information retrieval](../burp/sqli/14.md)
* [Blind SQL injection with out-of-band interaction](../burp/sqli/15.md)
* [Blind SQL injection with out-of-band data exfiltration](../burp/sqli/16.md)
* [SQL injection with filter bypass via XML encoding](../burp/sqli/17.md)

## Remediation

There are several effective ways to prevent SQLI attacks from taking place, as well as protecting against them, should they occur.

* Most instances of SQL injection can be prevented by using parameterised queries (prepared statements) instead of string concatenation within the query (see notes below). While input validation should always be considered best practice, it is rarely a foolproof solution. The reality is that often it is simply not feasible to map out all legal and illegal inputs. 
* Using [secure coding practices](https://devsecops.tymyrddin.dev/docs/notes/coding) at every stage of the development and operations pipeline will provide better protection from SQL injection vulnerability. Automating static (SAST) and dynamic (DAST) analysis tools into the development pipeline is an effective way to get this additional level of testing.
* Implementing a [web application firewall (WAF)](https://server.tymyrddin.dev/docs/firewall/waf) can help detect and filter out SQL injection attacks. Modern web application firewalls are also often integrated with other security solutions. From these, a WAF can receive additional information that further increase its security capabilities.
* Implementing an [intrusion detection system](https://nta.tymyrddin.dev/index) can help spot user behaviours attempting to exploit vulnerabilities in applications.

### Notes on parameterised queries

Parameterised queries can be used for any situation where untrusted input appears as data within the query, including the `WHERE` clause and values in an `INSERT` or `UPDATE` statement. They can not be used to handle untrusted input in other parts of the query, such as table or column names, or the `ORDER BY` clause. Application functionality that places untrusted data into those parts of the query will need to take a different approach, such as white-listing permitted input values, or using different logic to deliver the required behaviour.

For a parameterised query to be effective in preventing SQL injection, the string that is used in the query must always be a hard-coded constant, and must never contain any variable data from any origin. Do not be tempted to decide case-by-case whether an item of data is trusted, and continue using string concatenation within the query for cases that are considered safe. It is all too easy to make mistakes about the possible origin of data, or for changes in other code to violate assumptions about what data is tainted.

## Resources

* [Portswigger: SQL injection](https://portswigger.net/web-security/sql-injection)
* [OWASP: Testing for SQL Injection](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection)
* [HackTricks: SQL injection](https://book.hacktricks.xyz/pentesting-web/sql-injection)
* [Snyk DAST/SAST tools to detect issues](https://snyk.io/)

