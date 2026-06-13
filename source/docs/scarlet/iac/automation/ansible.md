# Ansible

[Terraform and cloud-init](providers.md) get a host to first boot. Ansible handles everything after: pushing
configs, updating peers in a [WireGuard mesh](../bouncers/wireguard-mesh.md), rotating certificates, and keeping
a cluster of hosts consistent without logging into each one.

The operational rule is the same as for Terraform: run Ansible from the bouncer, not from the operator's
workstation. The SSH connections the playbooks make originate from the bouncer's IP, which already sits behind
whatever opsec the operation uses.

## Inventory

A static inventory file on the encrypted volume is enough for a small operation. One group per role:

```ini
[redirectors]
redir-01 ansible_host=<ip> ansible_user=op ansible_ssh_private_key_file=./op_ed25519

[frontends]
front-01 ansible_host=<ip> ansible_user=op ansible_ssh_private_key_file=./op_ed25519

[backends]
back-01  ansible_host=10.8.0.10 ansible_user=op ansible_ssh_private_key_file=./op_ed25519
```

Backend hosts on the [WireGuard overlay](../bouncers/wireguard-mesh.md) use the overlay address; the bouncer is
already a peer on that network.

## Pushing a redirector config

A template per host type lets the same playbook serve a fleet of redirectors with different domain names:

```yaml
- hosts: redirectors
  become: true
  vars_files:
    - vars/{{ inventory_hostname }}.yml   # per-host domain, upstream
  tasks:
    - name: nginx redirector config
      template:
        src: redir.conf.j2
        dest: /etc/nginx/conf.d/redir.conf
        mode: "0640"
      notify: reload nginx

    - name: nginx running
      service:
        name: nginx
        state: started
        enabled: true

  handlers:
    - name: reload nginx
      service:
        name: nginx
        state: reloaded
```

`redir.conf.j2` is the [nginx redirector config](../redirectors/nginx-redirector.md) with `{{ domain }}` and
`{{ upstream }}` in place of the hardcoded values. Per-host variable files on the encrypted volume keep the
mapping of host to role out of the playbook itself.

## Running it

```bash
ansible-playbook -i inventory.ini redirectors.yml
```

Adding a new redirector: provision the host (via cloud-init or Terraform), add it to the inventory, re-run the
playbook. Removing one: destroy the host, drop it from the inventory. No manual SSH required at any step.

## What Ansible does not replace

Ansible is idempotent and fast for config distribution, but it touches the host over SSH, which leaves an
authentication event in `auth.log`. For hosts that are genuinely ephemeral and only live a few hours, Packer
images and cloud-init may be preferable to avoid any post-boot remote access at all.
