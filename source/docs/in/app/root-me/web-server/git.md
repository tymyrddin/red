# Insecure code management

[Challenge](https://www.root-me.org/en/Challenges/Web-Server/Insecure-Code-Management): Get the password (in clear text) from the admin account.

Intercept, send to Repeater and check the (existence and content of) `.git` directory:

![RootMe](/_static/images/insecure-code-management1.png)

Download the directory:

```text
wget -r http://challenge01.root-me.org/web-serveur/ch61/.git/
```

![RootMe](/_static/images/insecure-code-management2.png)

Open the directory which contains `.git` in GitCola (for example), and **Undo Commit**:

![RootMe](/_static/images/insecure-code-management3.png)

