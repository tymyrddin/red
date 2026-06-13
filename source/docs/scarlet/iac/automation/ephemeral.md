# Ephemeral hosts

The original insight in the `iac/` section is that replacing infrastructure in minutes is an asymmetric
advantage. Ephemeral hosts take that one step further: the host destroys itself on a timer, regardless of
whether the operator remembers to tear it down. A six-hour redirector that self-destructs leaves no lingering
surface for a defender who reaches the IP after the operation has moved on.

Two patterns are worth knowing. They differ in where the destroy logic lives.

## Host-side: scheduled shutdown via cloud-init

The host is told its own TTL at boot. A cloud-init `runcmd` schedules the shutdown:

```yaml
#cloud-config
runcmd:
  # ... normal setup ...
  - echo "poweroff" | at "now + 6 hours"
```

`poweroff` stops the host but does not delete it. The provider bills a stopped host at reduced or full rate
depending on contract, and the disk image remains available for forensic requests. To delete rather than halt,
the host needs the provider API token, which creates a secret-on-host trade-off:

```yaml
runcmd:
  - |
    SELF=$(curl -sf http://169.254.169.254/hetzner/v1/metadata/instance-id)
    echo "curl -sf -X DELETE https://api.hetzner.cloud/v1/servers/${SELF} \
         -H 'Authorization: Bearer ${HCLOUD_TOKEN}'" | at "now + 6 hours"
```

The API token on the host is the risk. If the host is seized before the TTL fires, the token is recoverable.
Keep the token scoped to delete-only on the specific server if the provider supports resource-scoped tokens, and
revoke it at the bouncer after the TTL window closes regardless.

## Bouncer-side: watcher destroys hosts after TTL

The bouncer keeps a manifest of provisioned hosts and their creation times. A short script runs on a loop and
destroys anything past its TTL, calling the provider API without needing the token on the host at all:

```bash
#!/bin/bash
# Run from cron or a systemd timer on the bouncer
MANIFEST=/opt/infra/<operation>/hosts.tsv   # host_id <tab> created_epoch
TTL=21600  # 6 hours in seconds

now=$(date +%s)
while IFS=$'\t' read -r host_id created; do
    age=$(( now - created ))
    if (( age >= TTL )); then
        curl -sf -X DELETE "https://api.hetzner.cloud/v1/servers/${host_id}" \
             -H "Authorization: Bearer ${HCLOUD_TOKEN}"
        sed -i "/^${host_id}\t/d" "$MANIFEST"
        echo "$(date): destroyed ${host_id} (age ${age}s)" >> /opt/infra/<operation>/destroy.log
    fi
done < "$MANIFEST"
```

Terraform also works here: record the host ID, set a calendar reminder, run `tofu destroy -target
hcloud_server.<name>` when the TTL expires. The watcher script is simply the automation of that reminder.

## Trade-offs

* A host that self-destructs before the operator is finished with it is an operational hazard. Six hours is a working assumption; calibrate to the actual beacon interval and operation tempo. A host that the implant beacons to every four hours needs a longer lifetime than one session.
* Deletion is irreversible. If the host needs to be inspected (beacon not calling in, traffic anomaly), the TTL window is the only chance. The [Ansible](ansible.md) pattern of pushing configs from the bouncer means config is reconstructible; the host's runtime state is not.
* Some providers charge a minimum billing period per host regardless of how quickly it is destroyed. Factor that into cost if spinning up and destroying many short-lived hosts per day.
* The destroy action itself is logged by the provider. A pattern of hosts created and destroyed at fixed intervals, all under the same account, is a recognisable footprint in provider audit logs even after the hosts are gone.
