<p align="center"><img src="src/siemstress/assets/logo.svg" alt="SIEMstress" width="620"></p>

# SIEMstress

A lightweight SIEM for homelabs. It stitches logs from your machines into one
place, then flags the things worth looking at.

Pure Python standard library, SQLite storage, single process. Licensed under the
GNU GPL, version 3 or later (see `LICENSE`).

## Status

- [x] Collection: local systemd journal, syslog over UDP/TCP (RFC 3164 / 5424),
      log files, Docker/Podman events
- [x] Normalization: SSH, sudo, su, PAM and account-management events
- [x] Detection rules and phone alerts (ntfy)
- [x] Dashboards: desktop app (Qt) and terminal UI (Textual)
- [x] Audit log, firewall (UFW, firewalld, pfSense/OPNsense) and Pi-hole parsing
- [x] Per-host and per-user attribution; sender allowlist and TLS with client certificates
- [x] Case workflow: assignee, notes, disposition, actions taken, audit log, ATT&CK tags,
      related events, MTTA/MTTR report

See [docs/detection-coverage.md](docs/detection-coverage.md) for what is and isn't detected
and [docs/alert-handling.md](docs/alert-handling.md) for how alerts are worked and closed.

## Install

Packages for Fedora, Debian/Ubuntu and Arch are built from `packaging/` (see
[packaging/README.md](packaging/README.md)). Once installed:

```sh
sudo systemctl enable --now siemstress       # the collector, as a hardened system service
sudo usermod -aG siemstress $USER            # use the dashboards; log out and back in
siemstress doctor                            # checks everything and says how to fix it
```

Configuration lives in `/etc/siemstress/config.toml` (annotated example:
`contrib/config.example.toml`), data in `/var/lib/siemstress/`, and `man siemstress`
lists every command. The dashboards come in the `siemstress-gui` and `siemstress-tui`
packages and start with `siemstress gui` and `siemstress tui` (see
[Dashboards](#dashboards)).

Running from a checkout or `pip install --user` works too: everything then lives under
`~/.config/siemstress` and `~/.local/share/siemstress`, and commands use those whenever
they exist.

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install -e '.[gui,tui]' pytest ruff
.venv/bin/pytest
.venv/bin/ruff check . && .venv/bin/ruff format --check .
tools/build-packages.sh && tools/test-packages.sh   # distro packages, built and tested in containers
```

## Usage

```sh
siemstress run                                  # collect until stopped
siemstress stats
siemstress search --since 1h --severity warning
siemstress search --app sudo --grep "session opened"
siemstress search --action ssh.login --outcome failure --since 1d
siemstress search --user root --action sudo
siemstress alerts --since 7d --level high      # unresolved by default; --status all
siemstress case 12                              # evidence, related events, activity log
siemstress ack 12 13                            # acknowledge and take ownership
siemstress note 12 "checked the router logs"
siemstress resolve 12 --disposition false-positive --action tuned-rule \
    --summary "Matched the nightly backup job"  # prompts for anything left out
siemstress reopen 12 --reason "seen again"
siemstress report --since 30d                   # MTTA/MTTR, dispositions, tuning candidates
siemstress rules                                # list active rules
siemstress hunt --since 30d                     # replay stored events through the rules
siemstress notify-test
```

Events are stored in `$XDG_DATA_HOME/siemstress/events.db`
(default `~/.local/share/siemstress/events.db`) and kept for 30 days.

### Hosts and users

Every event is labeled with the machine that produced it, using names SIEMstress
can verify rather than whatever a log line claims:

| Source | Host name comes from |
|---|---|
| This machine's journal | `hostname` in config.toml, else the static hostname (matched by machine ID) |
| Syslog over TLS | the sender's client certificate |
| Syslog from an allowlisted address | the name in `[syslog.senders]` |
| Syslog from an allowlisted network with name `""` | the name the sender reports |

When a sender reports a different name than the verified one, it's kept as
`extra.claimed_host`. The transient DHCP/reverse-DNS hostname is never used, so a
laptop doesn't show up as several machines.

`user` is who did it: the account named in the message (SSH login, sudo, su,
audit's original login user), or for this machine's journal, the person or root
whose process wrote the entry (service accounts are left out). Per-host user lists
exclude failed attempts, so guessed usernames from brute-force attacks don't
appear as users.

### Normalized fields

Recognized events get `action`, `outcome`, `user` (who acted), `target_user`
(who it was done to) and `src_ip`; parser-specific details such as the sudo
command or SSH auth method go in `extra`.

| Action | Source |
|---|---|
| `ssh.login`, `ssh.invalid_user`, `ssh.max_attempts` | sshd |
| `sudo.exec` | sudo |
| `su.switch` | su |
| `auth`, `session.open`, `session.close`, `password.change`, `account.lock` | PAM (any program) |
| `user.create`, `user.delete`, `group.create`, `group.delete`, `group.add_member`, `group.remove_member`, `account.lock`, `account.unlock` | shadow-utils, audit |
| `audit.auth`, `audit.login`, `audit.command`, `software.*`, `selinux.mode`, `selinux.denied`, `network.promiscuous`, `process.crash`, `system.boot` | Linux audit |
| `firewall.block`, `firewall.allow` | netfilter LOG (UFW, firewalld), pfSense/OPNsense `filterlog` |
| `dns.query`, `dns.blocked` | Pi-hole |
| `docker.container.*`, `docker.image.*` | Docker / Podman events |

Audit records come from the journal on Fedora (no root needed). They add the
original login user (`auid`) to account changes and decode sudo commands.

Parsers are regex tables in `src/siemstress/parsers/`; adding a format is
usually one `pattern(...)` line plus a test case in `tests/test_parsers.py`.

### Dashboards

There are two, and they show the same data: the desktop app (Qt) and the terminal UI
(Textual). Both are subcommands of `siemstress`, and both need the collector to have run
at least once so a database exists.

| | Desktop app | Terminal UI |
|---|---|---|
| Start it | `siemstress gui` | `siemstress tui` |
| Needs | PySide6 | Textual |
| Packaged install | `siemstress-gui` package | `siemstress-tui` package |
| From a checkout or pip | `pip install -e '.[gui]'` | `pip install -e '.[tui]'` |
| Good for | a desktop; tray notifications for new alerts | SSH sessions and headless hosts |

```sh
siemstress gui                  # desktop app
siemstress tui                  # terminal UI
siemstress tui --refresh 10     # refresh every 10 seconds instead of 5
siemstress --db /path/to/events.db tui   # read a specific database (--db goes before the command)
siemstress install-desktop      # add the desktop app, with its icon, to your application menu
```

On a packaged install, first join the `siemstress` group (`sudo usermod -aG siemstress
$USER`, then log out and back in) so the dashboards can read and update the database.
`siemstress doctor` tells you if that or anything else is wrong.

Both are safe to run alongside the collector: they never create or migrate the
database, only read it and update alert status. They refresh every 5 seconds
(`--refresh N`).

Alerts are open (●) until acknowledged (◐, being worked on) or resolved (✓). Closing
one requires a disposition, the actions taken and a summary; every change is kept in
the alert's activity log. Opening an alert shows its case: details, related events
and the log. Resolved alerts are hidden unless you ask for them.

Colors mean the same thing everywhere: red is critical or failed, orange high,
amber medium or needs a look, blue low, green fine or resolved, gray handled or
background. Hosts go amber ("quiet") after an hour without events and red
("silent") after a day.

In the TUI: `1`-`4` switch tabs, `/` searches events, `w` cycles the time window
(1h, 24h, 7d, 30d), `enter` opens an alert's case, `a` acknowledges, `t` takes it,
`n` adds a note, `r` resolves, `o` reopens, `h` shows or hides resolved alerts, `F5`
refreshes, `q` quits. In the desktop app, select one or more alerts and use the
toolbar, right-click menu or `A`/`M`/`N`/`R`/`O`. Both search
boxes accept words plus `action:`, `user:`, `ip:`, `host:`, `app:` and `outcome:`
filters, e.g. `action:ssh ip:203.0.113.9 failed`.

The icon and logo are generated by `tools/make_art.py` (needs the `Hershey-Fonts`
dev dependency); edit and rerun it to change them.

### Detection rules

Rules live in TOML. The built-ins are in `src/siemstress/default_rules.toml`
(which also documents the format); files in `~/.config/siemstress/rules/*.toml`
add rules or override a built-in by reusing its id.

```toml
[[rule]]
id = "ssh-brute-force"
title = "SSH brute force from {src_ip} ({count} failures)"
level = "high"
match = { action = ["ssh.login", "ssh.invalid_user"], outcome = "failure" }
group_by = ["src_ip"]
threshold = { count = 10, window = "5m" }
cooldown = "1h"
```

Rules can also fire on a sequence: `after` requires a number of other events from the
same group first. The built-in `login-after-failures` uses it to catch a successful
SSH login that follows repeated failures from the same address:

```toml
match = { action = "ssh.login", outcome = "success" }
group_by = ["src_ip"]
after = { match = { action = ["ssh.login", "ssh.invalid_user"], outcome = "failure" }, count = 5, window = "30m" }
```

Every rule has attack and benign scenarios in `tests/test_detections.py`; add one when
you add or change a rule. Use `siemstress hunt` to try a rule against history too.
Threshold and cooldown state is kept in memory and resets on restart.

### Notifications

Copy `contrib/config.example.toml` to `~/.config/siemstress/config.toml`, set
an ntfy topic, subscribe to it in the ntfy phone app, then run
`siemstress notify-test`. Alerts for events older than 15 minutes (e.g. from the
first-run backfill) are stored but not pushed.

### Collection scope

By default SIEMstress keeps everything it receives. `[scope]` in `config.toml`
narrows that:

```toml
[scope]
hosts = ["server1", "web*"]          # only these hosts
exclude_hosts = ["printer*"]
exclude_ips = ["192.168.1.250"]     # source or sender address, or a network
```

Out-of-scope events are dropped before detection and storage. That's a trade-off:
events from an excluded address can't raise alerts either, so exclude specific
known-noisy sources (your own scanner) rather than whole networks. The collector
logs its scope at startup and warns if this machine itself is excluded.
`[sources] journal = false` stops collecting this machine's journal entirely.

Which machines may *send* logs is configured separately, under `[syslog.senders]`.

### Optional sources

The Docker socket and the usual Pi-hole log paths are watched by default. An input
that doesn't exist on a host is skipped without errors or log noise, and picked up
automatically if it appears later (e.g. after installing Docker). Unreadable
inputs log one warning. Configure them under `[sources]` in `config.toml`; see
`contrib/config.example.toml`.

Firewall logs arrive through the journal or syslog once logging is on:
`sudo firewall-cmd --set-log-denied=all` (firewalld), `sudo ufw logging on` (UFW),
or remote logging to SIEMstress on pfSense/OPNsense.

### Receiving from other hosts

Only this machine may send syslog until you allow others. In config.toml:

```toml
[syslog]
listen = "0.0.0.0:5514"
udp = false                        # UDP senders can be spoofed

[syslog.senders]
"192.168.1.40" = "web01"   # label this address's events web01
```

Open the port (`sudo firewall-cmd --add-port=5514/tcp --permanent && sudo
firewall-cmd --reload`) and on the Debian host add
`/etc/rsyslog.d/90-siemstress.conf`, then `sudo systemctl restart rsyslog`:

```
*.* @@<siemstress-host>:5514
```

Rejected senders are logged at most once an hour per address.

#### With TLS

TLS encrypts logs in transit and authenticates each sender: a host needs a
certificate from your CA, and its events are named after that certificate.

```sh
contrib/make-certs.sh ~/.config/siemstress/tls ca
contrib/make-certs.sh ~/.config/siemstress/tls server siem 192.168.1.10   # this machine
contrib/make-certs.sh ~/.config/siemstress/tls client web01       # per sender
```

Set `tls_listen`, `tls_cert`, `tls_key` and `tls_ca` under `[syslog]` (see
`contrib/config.example.toml`) and open port 6514. On the Debian host, install
`rsyslog-openssl`, copy `ca.crt`, `web01.crt` and `web01.key` to
`/etc/rsyslog.d/siemstress/`, and use this instead of the plain forwarding line
(untested against a live rsyslog so far):

```
global(
  DefaultNetstreamDriver="ossl"
  DefaultNetstreamDriverCAFile="/etc/rsyslog.d/siemstress/ca.crt"
  DefaultNetstreamDriverCertFile="/etc/rsyslog.d/siemstress/web01.crt"
  DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/siemstress/web01.key"
)
*.* action(type="omfwd" target="192.168.1.10" port="6514" protocol="tcp"
           StreamDriver="ossl" StreamDriverMode="1"
           StreamDriverAuthMode="x509/name" StreamDriverPermittedPeers="siem")
```

### Running as a service

`contrib/siemstress.service` is a systemd *user* unit; it expects `siemstress` installed at
`~/.local/bin/siemstress` (for example with `pipx install .`). Edit `ExecStart` if yours lives elsewhere.
