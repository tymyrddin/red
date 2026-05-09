# Providers and provisioning

Two facts collide in this section. Terraform shines with providers that ship a first-party plugin. The hosts that
accept [anonymous payments](../bouncers/payments.md) usually do not. Pick the realistic pattern for the host you
chose.

## Hosts with a Terraform provider

* [Vultr](https://registry.terraform.io/providers/vultr/vultr/latest) (provider quality: good; payments: cards,
some crypto via gateways).
* [DigitalOcean](https://registry.terraform.io/providers/digitalocean/digitalocean/latest) (provider quality:
good; payments: cards, PayPal).
* [Hetzner Cloud](https://registry.terraform.io/providers/hetznercloud/hcloud/latest) (provider quality: good;
payments: SEPA, cards, identity verification varies).
* [Linode](https://registry.terraform.io/providers/linode/linode/latest) (Akamai-owned; cards).
* [OVH](https://registry.terraform.io/providers/ovh/ovh/latest) (cards, SEPA).

None of these are ideal for ops the target ever sees, because all of them tie the account to a real payment
identity. Use them only when a red teaming engagement scope tolerates that linkage, or when paying via a layered prepaid
card that holds up to legal pressure (it usually does not).

## Hosts that accept anonymous payments

Most hosts on the [alternative providers](../bouncers/alt-providers.md) page (NiceVPS, Cinfu, PiVPS) do not ship a
Terraform provider. The realistic provisioning pattern is one of:

1. Their HTTP API plus cloud-init for first-boot configuration.
2. Plain SSH plus a shell script or Ansible playbook.

### Cloud-init pattern

Most VPS panels accept a user-data blob at create time. Drop a cloud-init document and the host arrives ready:

```yaml
#cloud-config
users:
  - name: op
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - ssh-ed25519 AAAA... operator
ssh_pwauth: false
package_update: true
packages:
  - nginx
  - docker.io
runcmd:
  - ufw default deny incoming
  - ufw allow 22/tcp
  - ufw allow 443/tcp
  - ufw --force enable
  - systemctl enable --now docker
```

Pair with a small shell wrapper around the provider's API to spawn, list, and destroy hosts. Burn the API token at
teardown.

### SSH provisioning

When the panel does not expose an API, manual provisioning works:

```bash
ssh-keygen -t ed25519 -f ./op_ed25519 -N ''
# Paste the public key into the panel at create time
ssh -i ./op_ed25519 op@<host> 'bash -s' < bootstrap.sh
```

`bootstrap.sh` does the same job as the cloud-init `runcmd` block. Keep the script in the encrypted state
directory on the bouncer, not in a public repo.

## Choosing

* Short-lived redirector with no Terraform provider for the host: cloud-init or SSH bootstrap.
* Frontend or backend that you expect to rebuild several times: Terraform or OpenTofu against a provider that has
a plugin, accepting the identity trade-off.
* Anything in between: an Ansible playbook driven from the bouncer, hand-targeted at fresh hosts.

## Operational hygiene

* Rotate the bouncer between operations. Building a new bouncer per engagement is cheaper than letting one
accumulate state, history, and links.
* Do not commit Terraform or OpenTofu configs to a public repository. Keep them on the encrypted volume on the
bouncer. Public commits leak target hints, naming, and provider choices.
