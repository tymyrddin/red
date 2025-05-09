# sudo: weak configuration

[root-me challenge: sudo-weak-configuration](https://www.root-me.org/en/Challenges/App-Script/sudo-weak-configuration): Wishing to simplify the task by not modifying rights, the administrator has not thought about the side effects ...

----

`-l` lists the user's privileges:

```text
$ sudo -l
[sudo] password for app-script-ch1: 
...
User app-script-ch1 may run the following commands on challenge02:
    (app-script-ch1-cracked) /bin/cat /challenge/app-script/ch1/notes/*
```

The `*` can be anything ...

The `-u` flag gives the option to run a command as a user other than the default target user (usually root):

```text
sudo -u [different_username] command
```

The user may be either a username or a numeric user-ID (`UID`) prefixed with the `#` character (e.g., `#0` for `UID 0`).  When running commands as a UID, many shells require that the `#` be escaped with a backslash (`\`).  Some security policies may restrict `UID`s to those listed in the password database.  The sudoers policy allows `UID`s that are not in the password database as long as the `targetpw` option is not set.  Other security policies may not support this.

## Resources

* [Permissions POSIX](https://www.root-me.org/spip.php?article788)
* [sudo you are doing it wrong](https://repository.root-me.org/Administration/Unix/EN%20-%20sudo%20you%20are%20doing%20it%20wrong.pdf)
