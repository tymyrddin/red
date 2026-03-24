# File: Insecure storage Mozilla Firefox 14

[RootMe: File - Insecure storage 1: Mozilla Firefox 14](https://www.root-me.org/en/Challenges/Cryptanalysis/File-Insecure-storage-1): Retrieve the user’s password.

## Solution

[firefox_decrypt](https://github.com/Unode/firefox_decrypt) is a tool to extract passwords from profiles of Mozilla (Fire/Water)fox™, Thunderbird®, SeaMonkey® and derivates. This tool does not try to crack or brute-force the Master Password in any way. If the Master Password is not known it will simply fail to recover any data. If there is no Master Password ...

```text
sudo apt install libnss3
git clone https://github.com/Unode/firefox_decrypt
```

```text 
wget http://challenge01.root-me.org/cryptanalyse/ch20/ch20.tgz
```

```text
tar -zxvf ch20.tgz
./.mozilla/
./.mozilla/extensions/
./.mozilla/firefox/
./.mozilla/firefox/profiles.ini
./.mozilla/firefox/o0s0xxhl.default/
...
```

```text
python firefox_decrypt.py .mozilla/firefox/o0s0xxhl.default/
2023-03-06 15:40:11,605 - WARNING - profile.ini not found in .mozilla/firefox/o0s0xxhl.default/
2023-03-06 15:40:11,606 - WARNING - Continuing and assuming '.mozilla/firefox/o0s0xxhl.default/' is a profile location

Website:   http://www.root-me.org
Username: 'shell1cracked'
Password: 'xxxxxx'
```
