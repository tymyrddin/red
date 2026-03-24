# Trends in persistence

Persistence used to mean "something runs at startup". Now it means "something can
regain access whenever it wants". That something might be a token, a role, a trust
relationship, or a hidden configuration entry. No process required. No file on disk.
Nothing for an autorun scanner to find.

The trajectory matches evasion: less "plant a flag", more "become part of the
plumbing".

The pages in this section cover the major technique areas:

- [Identity-based persistence](identity.md): stolen tokens, OAuth application
  backdoors, federation trust abuse; persistence that survives reboots, patching,
  and sometimes incident response
- [Cloud control plane persistence](cloud.md): hidden IAM roles, overpermissive
  service accounts, CI/CD pipeline implants; persistence that lives in configuration
- [Living persistence](living-persistence.md): scheduled tasks, WMI subscriptions,
  cron jobs, systemd services; LoLbin-style persistence using legitimate mechanisms
- [Application-layer backdoors](app-layer.md): web shells, hidden admin accounts,
  database triggers, backdoored update mechanisms; persistence that survives OS
  rebuilds if the application is redeployed unchanged

Firmware and kernel-level persistence (UEFI implants, driver hooks) are covered in
the reverse engineering and evasion sections respectively, as the techniques overlap
significantly.

## The stealthy persistence landscape

| Method | Effort | Stealth | Resilience | Notes |
| ------ | ------ | ------- | ---------- | ----- |
| Stolen tokens / OAuth apps | low | very high | high | survives reboots and patching |
| Cloud IAM abuse | medium | high | high | hidden in configuration, not code |
| LoLbin scheduled tasks / WMI | low | medium | medium | caught if endpoint monitoring is strict |
| Firmware implant | very high | very high | very high | survives OS reinstall |
| Hidden service accounts / app backdoors | medium | high | medium-high | survives app redeploy if unchanged |
| Memory-resident C2 | medium | high | medium | fileless, lost on reboot without secondary persistence |
| Steganographic C2 | medium | very high | medium | resilient channel, blends with legitimate traffic |
| Kernel/driver hooks | high | high | high | hides processes and EDR |

## The bottom line

Old persistence (registry keys, startup folders) is still used and mostly caught.
Modern persistence (identity, cloud, configuration) is harder to detect and often
missed entirely. The best mechanisms do not look like persistence; they look like
something IT might have configured on purpose.

Red team persistence is most effective when layered: combining identity, configuration,
and endpoint mechanisms so that removing one layer does not end the operation.
