# RSA Continued fractions

[RootMe Challenge: Private key](https://www.root-me.org/en/Challenges/Cryptanalysis/RSA-Continued-fractions): You have to login via ssh with an rsa-key authentication.

Public key:

```text
E = 0xf70b3bd74801a25eccbde24e01b077677e298391d4197b099a6f961244f04314da7de144dd69a8aa84686bf4ddbd14a6344bbc315218dbbaf29490a44e42e5c4a2a4e76b8101a5ca82351c07b4cfd4e08038c8d5573a827b227bce515b70866724718ec2ac03359614cdf43dd88f1ac7ee453917975a13c019e620e531207692224009c75eaef11e130f8e54cce31e86c84e9366219ae5c250853be145ea87dcf37aa7ece0a994195885e31ebcd8fe742df1cd1370c95b6684ab6c37e84762193c27dd34c3cf3f5e69957b8338f9143a0052c9381d9e2ecb9ef504c954b453f57632705ed44b28a4b5cbe61368e485da6af2dfc901e45868cdd5006913f338a3
```

```text
N = 0x0207a7df9d173f5969ad16dc318496b36be39fe581207e6ea318d3bfbe22c8b485600ba9811a78decc6d5aab79a1c2c491eb6d4f39820657b6686391b85474172ae504f48f02f7ee3a2ab31fce1cf9c22f40e919965c7f67a8acbfa11ee4e7e2f3217bc9a054587500424d0806c0e759081651f6e406a9a642de6e8e131cb644a12e46573bd8246dc5e067d2a4f176fef6eec445bfa9db888a35257376e67109faabe39b0cf8afe2ca123da8314d09f2404922fc4116d682a4bdaeecb73f59c49db7fa12a7fc5c981454925c94e0b5472e02d924dad62c260066e07c7d3b1089d5475c2c066b7f94553c75e856e3a2a773c6c24d5ba64055eb8fea3e57b06b04a3
```

Use continued fractions to calculate the private key, put it in a private ssh identity file, `chmod` it to `600` and log in:

```text
$ ssh -i .ssh/id_rsa -p 2221 cryptanalyse-ch24-cracked@challenge01.root-me.org
Warning: Identity file .ssh/id_rsa not accessible: No such file or directory.
      _           _ _                        ___  _ 
  ___| |__   __ _| | | ___ _ __   __ _  ___ / _ \/ |
 / __| '_ \ / _` | | |/ _ \ '_ \ / _` |/ _ \ | | | |
| (__| | | | (_| | | |  __/ | | | (_| |  __/ |_| | |
 \___|_| |_|\__,_|_|_|\___|_| |_|\__, |\___|\___/|_|
                                 |___/ root-me.org  

     
                                     ██▒ ▒██░    
                                 ░███░ █ █ ░███▒    
                             ░███░        ▓     ███░    
                           ▓█▓       ▓█░  ▓       ▓███    
                         ██▒     ░▓█▓███  ▓   ██  █▒ ░██    
                        ██  ███  ▒░       ▓░████░██    ▓█░    
                       ██   ▒██      ███      ░▓██      ▒█    
                      ██             ░█░      ░██        ▓█    
                     ░█████████████    █     ██░          █▓    
                     ██                 █ ░██             ██    
                     ██      ░         ░██▓               ██    
                     ██  ███    ░██▓░███                 ███    
                     ▒█          ▓██▓                  ░████    
                      █▓    ░████                    ░██ ▒█    
                      ▓█████░                      ███ ███▓    
                      ▓███                      █████░ ████    
                       ▓█     ░██▓░         ▒████████░  ██    
                       ▓█      ██░▒██████████████████░  ██    
                       ▓█       ███▓██▒  ░██████████░   ██    
                       ▓█                  ░████▒       ██    
                        ░██▓           ▒█▓           ▒██░    
                           ▒██░       ██ ▒█        ██▓    
                              █▒                  █    
                              █▒  ░█    █░   █▓   █    
                              █████████████████████    
     
 ████████████▄                             ██    ███             ███    
 ██          ██  ▄████████▄   ▄████████▄  ██████ ████           ████  ▄████████▄  
 ██          ██ ██        ██ ██        ██  ██    ██  ██       ██  ██ ██        ██  
 ████████████▀  ██        ██ ██        ██  ██    ██   ██     ██   ██ ████████████ 
 ██    ███      ██        ██ ██        ██  ██    ██     ██ ██     ██ ██    
 ██       ████   ▀████████▀   ▀████████▀   ██    ██       █       ██  ▀██████████ 


------------------------------------------------------------------------------------------------
    Welcome on challenge01    /
-----------------------------‘

/tmp and /var/tmp are writeable

Useful commands available:
    python, perl, gcc, netcat, gdb, gdb-peda, gdb-gef, ROPgadget, radare2, pwntools

Attention:
    Publishing solutions publicly (blog, github, youtube, etc.) is forbidden.
    Publier des solutions publiquement (blog, github, youtube, etc.) est interdit.

cryptanalyse-ch24-cracked@challenge01:~$ ls
flag
cryptanalyse-ch24-cracked@challenge01:~$ cat flag
```

## Resources

* [Continued Fractions - RSA](https://repository.root-me.org/Cryptographie/Asym%C3%A9trique/EN%20-%20Continued%20Fractions%20-%20RSA.pdf)
* [Fractions Continues et Algorithme LLL - RSA](https://repository.root-me.org/Cryptographie/Asym%C3%A9trique/FR%20-%20Fractions%20Continues%20et%20Algorithme%20LLL%20-%20RSA.pdf)

