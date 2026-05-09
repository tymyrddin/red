# Set up Terraform on the bouncer

Terraform is open source and [supports a number of cloud providers](https://registry.terraform.io). Following
HashiCorp's licence change to BSL in 2023, the Linux Foundation forked the project as
[OpenTofu](https://opentofu.org/), which remains under MPL 2.0 and is a drop-in replacement. Either tool works for
this section; the configuration syntax is the same.

## Install on the bouncer

The bouncer is already reachable only over Tor or a VPN. Install Terraform or
OpenTofu on it, not on the operator's workstation:

```bash
# OpenTofu (preferred, MPL 2.0)
root@bouncer:~/# curl -sSL https://get.opentofu.org/install-opentofu.sh -o install.sh
root@bouncer:~/# bash install.sh --install-method standalone
```

Or Terraform:

```bash
root@bouncer:~/# curl -fsSL https://releases.hashicorp.com/terraform/1.10.0/terraform_1.10.0_linux_amd64.zip -o tf.zip
root@bouncer:~/# unzip tf.zip && install -m 0755 terraform /usr/local/bin/
```

## State on encrypted local storage

Terraform state contains every secret and resource ID. Do not put it in S3, Azure Blob, GCS, or any vendor backend
that ties state to a billing identity. Keep it on the bouncer, on an encrypted volume:

```bash
root@bouncer:~/# cryptsetup luksFormat /dev/vdb
root@bouncer:~/# cryptsetup luksOpen /dev/vdb infra
root@bouncer:~/# mkfs.ext4 /dev/mapper/infra
root@bouncer:~/# mount /dev/mapper/infra /opt/infra
root@bouncer:~/# mkdir /opt/infra/<operation> && cd /opt/infra/<operation>
```

The default `local` backend writes `terraform.tfstate` into the working directory. With the working directory on
the encrypted mount, state is sealed when the volume is locked and gone when the bouncer is destroyed.

## Credentials

Provider credentials live in environment variables, not in checked-in files. Set them per-shell on the bouncer and
let them die with the session. For providers that issue rotatable API tokens, generate a token per operation and
revoke at teardown.

```bash
root@bouncer:~/# export VULTR_API_KEY='...'
root@bouncer:~/# tofu init
root@bouncer:~/# tofu plan
```
