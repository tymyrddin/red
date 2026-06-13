# Packer

When a fresh VPS runs `apt-get install nginx certbot wireguard-tools` at boot, three things happen: outbound
package downloads appear in egress logs, installation timestamps are written to the host, and the setup window
is visible to anyone watching the host's traffic. A Packer-built image moves all of that offline. The snapshot
is built once on the bouncer or a dedicated build host, pushed to the provider as a private image, and every VPS
booted from it arrives with the tools already present and no installation history on disk.

The forensic benefit is secondary but real: a seized host booted from a golden image has no `apt` history
showing when tools were installed, because they were installed before the image was ever deployed.

## Build config

Packer uses HCL2 config files. A redirector image for Hetzner:

```
packer {
  required_plugins {
    hcloud = {
      source  = "github.com/hashicorp/hcloud"
      version = ">= 1.6.0"
    }
  }
}

variable "hcloud_token" { sensitive = true }

source "hcloud" "redirector" {
  token         = var.hcloud_token
  image         = "debian-12"
  location      = "nbg1"
  server_type   = "cx22"
  snapshot_name = "redirector-{{timestamp}}"
  ssh_username  = "root"
}

build {
  sources = ["source.hcloud.redirector"]

  provisioner "shell" {
    inline = [
      "export DEBIAN_FRONTEND=noninteractive",
      "apt-get update -qq",
      "apt-get install -y --no-install-recommends nginx certbot python3-certbot-nginx socat wireguard-tools ufw",
      "systemctl disable nginx",
      "apt-get clean && rm -rf /var/lib/apt/lists/*",
      # Wipe shell history from the build session
      "unset HISTFILE && history -c",
    ]
  }
}
```

`systemctl disable nginx` matters: the image arrives with nginx installed but not running. The per-host
cloud-init or [Ansible](ansible.md) playbook writes the config and starts the service, so a host does not
announce itself before the config is in place.

## Building

From the bouncer, with the token in the environment:

```bash
export PKR_VAR_hcloud_token="$HCLOUD_TOKEN"
packer init redirector.pkr.hcl
packer build redirector.pkr.hcl
```

Packer spins up a temporary build server, provisions it, takes a snapshot, and destroys the server. The snapshot
ID is printed at the end; add it to the Terraform config as the image to boot from. The build server itself is
gone; its IP appeared briefly in provider logs and nowhere else.

## Rotation

Build a fresh image per operation. Images accumulate in the provider account as a record of what was installed
and when; delete previous snapshots at teardown when keeping that history conflicts with the operation's opsec.
For providers without a Packer plugin, the same pattern works with [cloud-init](providers.md) scripting the installation 
at first boot, at the cost of the visible setup window.

## What Packer does not cover

The image is clean; the hosts booted from it are not necessarily so. Post-boot configuration (domain, upstream
address, WireGuard peers) still arrives via cloud-init or Ansible, and those events are in the host's systemd
journal. Packer eliminates the tool-install window, not the configuration window.
