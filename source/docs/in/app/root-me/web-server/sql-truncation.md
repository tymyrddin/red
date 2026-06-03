# SQL truncation

[root-me challenge: SQL Truncation](https://www.root-me.org/en/Challenges/Web-Server/SQL-Truncation): Gain access to the administration zone.

----

Trying to register as admin, in the response:

```text
<!--
CREATE TABLE IF NOT EXISTS user(   
	id INT NOT NULL AUTO_INCREMENT,
    login VARCHAR(12),
    password CHAR(32),
    PRIMARY KEY (id));
-->
```

Using [SQL Truncation Attack](https://linuxhint.com/sql-truncation-attack/):

```text
login=admin+++++++a&password=admin123
```

## Techniques

- [SQL injection](../../techniques/sqli.md)
- [Server-side injection runbook](../../runbooks/injection.md)

## Counter moves

SQL truncation is what this page works through. Server-side validation and least privilege are what these reduce to. Seen from the other side, this sits in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
