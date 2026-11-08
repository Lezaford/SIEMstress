# Detection coverage

What SIEMstress catches, where it's blind, and what to add next. Every rule below has
attack and benign scenarios in `tests/test_detections.py`, which fails if a rule is
added without one.

Technique IDs refer to [MITRE ATT&CK](https://attack.mitre.org/).

## Covered

| Attacker goal | Technique | Rule | Needs |
|---|---|---|---|
| Guess passwords over SSH | T1110.001 / .003 | `ssh-brute-force` | sshd logs |
| Log in as root directly | T1078.003 | `ssh-root-login` | sshd logs |
| Guessing that worked: success after failures from the same address | T1110 → T1078 | `login-after-failures` | sshd logs |
| Guess any local account's password | T1110.001 | `login-failures` | PAM (journal or syslog) |
| Escalate through sudo | T1548.003 | `sudo-password-failures`, `sudo-not-permitted` | sudo logs |
| Escalate through su | T1548 | `su-failure` | su logs |
| Keep access with a new account | T1136.001 | `user-created` | shadow-utils or audit |
| Grant an account root-equivalent groups | T1098.007 | `privileged-group-member` | shadow-utils or audit |
| Take over or lock out accounts | T1531 | `root-password-changed`, `account-locked`, `user-deleted` | PAM, shadow-utils |
| Turn off SELinux | T1562.001 | `selinux-permissive` | audit (journal) |
| Blind the audit system | T1562.012 | `audit-disabled`, `audit-rules-removed` | audit (journal) |
| Probe what a confined service can reach | T1083 | `selinux-denials` | audit (journal) |
| Sniff network traffic | T1040 | `promiscuous-interface` | audit (journal) |
| Scan for open ports | T1046 | `firewall-scan` | firewall logging turned on |
| Run commands inside a container | T1609 | `container-exec` | Docker/Podman socket |
| Crash-looping container (often a symptom) | — | `container-restart-loop` | Docker/Podman socket |

## Rules that need extra setup

These rules exist but can't fire until their input exists:

- **SSH rules**: need `sshd` running. With no SSH service there is nothing to attack, so
  nothing to see.
- **`firewall-scan`**: firewalld's logging of denied packets is off by default. Turn it on with
  `sudo firewall-cmd --set-log-denied=unicast` (unicast avoids broadcast noise).
- **Container rules**: needs a Docker or Podman API socket. For rootless Podman:
  `systemctl --user enable --now podman.socket`, then set `sources.docker`.
- **File-level audit** (who read `/etc/shadow`, who edited `authorized_keys`): the
  audit system records these only with watch rules, and none are installed by default. See gaps.

On Fedora the journal receives audit records straight from the kernel, so stopping the
auditd service doesn't blind SIEMstress; switching kernel auditing off does, and that
is what `audit-disabled` catches.

## Gaps, most valuable first

Not built until there's a use case for them:

1. **Host went silent.** Dashboards mark hosts quiet or silent, but nothing alerts. A
   stopped log forwarder is also what an attacker covering tracks looks like (T1562).
   Needs a periodic check rather than an event rule.
2. **Logs deleted** (T1070.002): a vacuumed journal or removed log files leave no log
   line of their own. Only noticeable as a silent host (1), or by forwarding logs off
   the machine as they're written, which the syslog listener already allows.
3. **Login from a new place**: first-ever successful login for a user from a given IP
   or network. Needs remembered history per user.
4. **Persistence through SSH keys, cron and systemd** (T1098.004, T1053.003,
   T1543.002): changes to `authorized_keys`, crontabs and unit files. Needs audit watch
   rules on those paths, then parsers for the resulting SYSCALL/PATH records.
5. **Reading secrets** (T1003.008): access to `/etc/shadow`. Same audit-watch approach.
6. **Internal SSH between your own machines** (T1021.004): lateral movement looks like
   a normal login; worth a low-level alert once there are several hosts.

Not in scope for a log-based SIEM: malware on disk, outbound data theft and anything
that never writes a log line. Those need endpoint or network tools alongside it.
