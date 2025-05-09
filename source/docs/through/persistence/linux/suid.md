# SUID and SGID exploits

Become root on Linux via SUID:

1. List files that have SUID or SGID bits set
2. Exploit

## Example: nano

### Crack passwords file

1. List files that have `SUID` or `SGID` bits set:

```text
find / -type f -perm -04000 -ls 2>/dev/null
```

2. Compare these executables with [GTFOBins SUID](https://gtfobins.github.io/#+suid). The nano text editor has the SUID bit set
3. Read `/etc/passwd` and `/etc/shadow` using nano.
4. Copy contant to local `passwd.txt` resp `shadow.txt` files.
5. Use the `unshadow` tool to create a file crackable by John the Ripper

```text
unshadow passwd.txt shadow.txt > passwords.txt
```

### Add a user

The other option would be to add a new user that has root privileges.

1. Using the `openssl` tool, create a password hash for a new user:

```text
openssl passwd -1 -salt <password>
```

2. Add this password with a username to the `/etc/passwd` file. Use `root:/bin/bash` to give this user a root shell.
3. Switch to this user.

## Notes

SUID (Set-user Identification) and SGID (Set-group Identification) allow files to be executed with the permission level of the file owner or the group owner, respectively.

Such files have an `s` bit set showing their special permission level. To find binaries known to be exploitable when the SUID bit is set see [GTFObins SUID](https://gtfobins.github.io/#+suid).
