# Planung: Härtungsmodule

Ziel: Debian-13-Server nach Stand der Technik härten. Grundlagen: CIS Benchmark Debian,
BSI IT-Grundschutz SYS.1.3, Mozilla/ssh-audit-Empfehlungen für SSH. Gemessen wird mit Lynis.

## Reihenfolge

| # | Modul | Abhängig von | Status |
|---|---|---|---|
| 1 | `base` – Updates, Zeit, Locale, Paketquellen, Pakete | – | umgesetzt, auf VPS getestet |
| 2 | `users` – Admin-Benutzer, sudo, root, Passwort-Richtlinien | – | umgesetzt, auf VPS getestet |
| 3 | `ssh` – SSH-Härtung | users | umgesetzt, auf VPS getestet |
| 4 | `firewall` – nftables | – | umgesetzt, Test auf VPS offen |
| 5 | `crowdsec` – Brute-Force-Schutz, Blocklisten (statt fail2ban) | firewall | geplant |
| 6 | `kernel` – sysctl, Kernelmodule, Mount-Optionen | – | geplant |
| 7 | `services` – unnötige Dienste, offene Ports | – | geplant |
| 8 | `logging` – journald, auditd, Logrotation | – | geplant |
| 9 | `apparmor` – AppArmor im Enforce-Modus | – | geplant |
| 10 | `integrity` – AIDE, Paketintegrität | – | geplant |
| 11 | `audit` – Lynis-Prüfung (nur check) | – | geplant |

Später (Dienst-Module, nach der Härtung): `docker`, ggf. `nginx`, `tailscale`, zentrales Logging, ggf. Mailversand.

## 1. `base`

### Automatische Updates
- `unattended-upgrades` nur für **Sicherheitsupdates**.
- Neustart: standardmäßig **nur melden** (`check` → WARN bei `/run/reboot-required`).
  Automatischer Neustart pro Server über `BASE_AUTO_REBOOT="03:30"`.
- `check`: ausstehende Updates, ausstehende Sicherheitsupdates, Neustart nötig, unattended-upgrades aktiv.
- Mail-Benachrichtigung: vorerst nicht (braucht Mailversand, ggf. eigenes Modul später).
- Debians Standard spielt auch reguläre Stable-Updates ein (`label=Debian`); srvctl leert die Liste per `#clear` und setzt nur Security-Quellen.
- **needrestart** startet betroffene Dienste nach Updates automatisch neu (`BASE_NEEDRESTART=auto`, abschaltbar mit `list`).
- `check` nutzt `debsecan` (Pakete mit behobenen, aber nicht eingespielten Lücken).

### Zeitsynchronisation
- **chrony mit NTS** ersetzt systemd-timesyncd.
- Server per `BASE_NTS_SERVERS` (Standard: PTB `ptbtime1-3.ptb.de`, Netnod, Cloudflare).
- Firewall-Hinweis: ausgehend UDP 123 und TCP 4460.
- `authselectmode require`: Nur NTS-authentifizierte Quellen werden zur Synchronisation genutzt; der Debian-Pool wird auskommentiert.
- `check`: chrony aktiv, synchronisiert, NTS-Authentifizierung aktiv (`chronyc -N authdata`).

### Zeitzone und Locale
- Zeitzone `BASE_TIMEZONE="Europe/Berlin"`.
- Locale `BASE_LOCALE="en_US.UTF-8"`, zusätzlich erzeugt: `BASE_LOCALES_EXTRA="de_DE.UTF-8"`.

### Paketquellen
- `check`: Security-Quelle vorhanden, keine Quelle mit `trusted=yes`/`allow-insecure`,
  Quellen mit `signed-by`, Fremdquellen als WARN (Ausnahmen: `BASE_APT_ALLOWED_SOURCES`).
- `setup`: ergänzt nur die Security-Quelle, falls sie fehlt. Hoster-Mirror bleiben unverändert.

### Pakete
- `BASE_PACKAGES_INSTALL`: u. a. `needrestart`, `debsecan`, `apt-listchanges`, `ca-certificates`.
- `BASE_PACKAGES_REMOVE`: u. a. `telnet`, `rsh-client`, `nis`, `talk`, `ftp`, `avahi-daemon`, `cups`, `xinetd`, `rpcbind`.
- `check` meldet Abweichungen; `setup` installiert und entfernt. Das Entfernen wird angezeigt und bestätigt (außer `--yes`).

## 2. `users`

### Admin-Benutzer und SSH-Schlüssel
- Benutzername **und** Schlüssel werden bei `setup` **interaktiv** abgefragt. Im (öffentlichen) Repo steht nichts über die Admins.
- Schlüssel landen nur in `~<user>/.ssh/authorized_keys` und werden mit `ssh-keygen` geprüft.
  Abgelehnt werden DSA und RSA unter 3072 Bit.
- Admins sind in den Gruppen `sudo` und `sshusers` (`sshusers` wird im `ssh`-Modul für `AllowGroups` genutzt).
- Ohne Terminal bricht `setup` mit einem Hinweis ab, statt einen Benutzer ohne Schlüssel anzulegen.
- **Erkennung fremder Schlüssel:** Nur die Fingerprints werden in `/var/lib/srvctl/users.state` gespeichert
  (nur root, nur lokal). `check` meldet FAIL bei Schlüsseln, die nicht über srvctl eingetragen wurden.
- `configure` interaktiv: Admin hinzufügen, Schlüssel hinzufügen, Schlüssel entfernen (Fingerprints werden mitgeführt).
- Ein entfernter Admin wird gesperrt, nicht gelöscht.

### sudo
- sudo **mit Passwort**. Das Passwort wird bei `setup` interaktiv gesetzt und gilt nur für sudo (SSH bleibt schlüsselbasiert).
- Drop-in `/etc/sudoers.d/srvctl` (mit `visudo -c` geprüft): `use_pty`, `logfile=/var/log/sudo.log`, kurzer `timestamp_timeout`.

### root
- root-Passwort sperren (`passwd -l`), **erst wenn** ein Admin mit Passwort und Schlüssel existiert.
- `su` nur für die Gruppe `sudo` (`pam_wheel`).
- Notzugang: Admin an der Hoster-Konsole + sudo, im Extremfall Rescue-System.

### Passwort-Richtlinien
- Modern nach NIST SP 800-63B / BSI: Mindestlänge 14, keine erzwungenen Zeichenklassen, **kein Ablauf**,
  Wörterbuchabgleich (`pam_pwquality`). Lynis-Hinweis zum fehlenden Ablauf wird bewusst akzeptiert.
- Hash `yescrypt` (prüfen), `umask 027`, `pam_faillock`: 5 Fehlversuche → 15 Minuten Sperre.
- Umsetzung: eigene `pwquality.conf.d/srvctl.conf`; `pam_faillock` über zwei `pam-auth-update`-Profile (CIS-Vorlage),
  keine Handarbeit an `common-auth`. Debians `HOME_MODE 0700` bleibt (strenger als 0750).
- Rollback stellt Konfigurationsdateien wieder her und entsperrt root, falls srvctl es gesperrt hat;
  angelegte Admins und Passwörter bleiben.

### Kontenprüfung
| Prüfung | Bei Abweichung |
|---|---|
| Leere Passwörter | FAIL, `configure` sperrt nach Rückfrage |
| Weitere UID 0 | FAIL, nur melden |
| Doppelte UIDs/GIDs/Namen | FAIL, nur melden |
| Systemkonten mit Login-Shell | WARN, `configure` setzt `nologin` nach Rückfrage |
| Home-Verzeichnisse für andere zugänglich | WARN, `configure` setzt `750` |
| Unbekannte Mitglieder von `sudo`/`sshusers` | WARN, nur melden |

## 3. `ssh`

Umsetzung als Drop-in `/etc/ssh/sshd_config.d/00-srvctl.conf` (bei sshd gilt der erste Treffer).
Jede Änderung wird vor dem Neuladen mit `sshd -t` geprüft; neu geladen wird mit `reload`, bestehende Sitzungen bleiben offen.

### Schutz vor dem Aussperren
- Vorprüfung: mindestens ein Admin in `sshusers` mit gültigem Schlüssel, `sshd -t` erfolgreich.
- **Bestätigungs-Timer** (Framework-Funktion): Nach dem Neuladen startet ein `systemd-run`-Timer (5 Minuten).
  Ohne `srvctl confirm` aus einer **neuen** SSH-Sitzung wird die vorherige Konfiguration automatisch wiederhergestellt.

### Anmeldung
`PermitRootLogin no`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `AuthenticationMethods publickey`,
`AllowGroups sshusers`, `MaxAuthTries 3`, `LoginGraceTime 30`, `MaxStartups 10:30:60`, `PermitEmptyPasswords no`,
`HostbasedAuthentication no`, `PermitUserEnvironment no`, `LogLevel VERBOSE`.

### Port
- `SSH_PORT=22` (änderbar); das `firewall`-Modul übernimmt den Wert.

### Kryptografie (Profil „modern mit PQ-Hybrid“)
- Kex: `mlkem768x25519-sha256`, `sntrup761x25519-sha512`, `sntrup761x25519-sha512@openssh.com`, `curve25519-sha256`, `curve25519-sha256@libssh.org`
- Ciphers: `chacha20-poly1305@openssh.com`, `aes256-gcm@openssh.com`, `aes128-gcm@openssh.com`
- MACs: `hmac-sha2-512-etm@openssh.com`, `hmac-sha2-256-etm@openssh.com`
- Host-Keys: Ed25519 + RSA-4096. Ein kürzerer RSA-Key wird neu erzeugt (Clients sehen dann einmalig eine Host-Key-Warnung), ECDSA-Host-Key entfernt.
- `RequiredRSASize 3072`.
- `check` nutzt zusätzlich `ssh-audit` (Debian-Paket) als unabhängige Prüfung.
- Benutzer-Schlüssel (`PubkeyAcceptedAlgorithms`): Ed25519, RSA (SHA-2), ECDSA und FIDO2-Varianten – passend zu `users`.
- `check` vergleicht die **wirksamen** Werte aus `sshd -T`, nicht nur die Datei.

### Weiterleitungen
- `AllowTcpForwarding local` (Tunnel mit `-L` möglich, kein `-R`), `AllowAgentForwarding no` (stattdessen ProxyJump `-J`),
  `X11Forwarding no`, `PermitTunnel no`. Per Config änderbar.

### Zweiter Faktor
- FIDO2-Sicherheitsschlüssel (`sk-ssh-ed25519`, `sk-ecdsa`) werden akzeptiert, auch im Modul `users`.
- `SSH_REQUIRE_SK=1` erzwingt, dass nur noch Hardware-Schlüssel gelten. Kein TOTP.

### Sitzungen und Banner
- `ClientAliveInterval 300`, `ClientAliveCountMax 3`: tote Verbindungen werden getrennt, kein Idle-Logout.
- Kurzer neutraler Banner ohne OS- oder Versionsangaben (`SSH_BANNER_TEXT`), `DebianBanner no`.

## 4. `firewall`

### Werkzeug
- **nftables direkt**, eigene Tabelle `table inet srvctl` (IPv4 + IPv6), aus Template erzeugt, vor dem Laden mit `nft -c` geprüft.
- **Nie `flush ruleset`**: Nur die eigene Tabelle wird ersetzt, damit Tabellen von CrowdSec, Docker und Tailscale erhalten bleiben.
  (Debians Standard-`/etc/nftables.conf` beginnt mit `flush ruleset`; das wird angepasst.)
- Änderungen laufen über den Bestätigungs-Timer (wie bei `ssh`).
- Debians `nftables.service` führt beim Stoppen `flush ruleset` aus; ein systemd-Drop-in ersetzt das durch
  `nft delete table inet srvctl`. `/etc/nftables.conf` bindet nur noch `/etc/srvctl/nftables/*.nft` ein.
- Regeln liegen in `/etc/srvctl/nftables/srvctl.nft` (Muster `table; delete table; table {…}` = atomarer Austausch).
- Getestet in isolierten Netzwerk-Namespaces: Ports, Allowlist, Ratenlimit, Ausgangssperre.

### Eingehend
- `input` und `forward`: Grundregel `drop`; erlaubt sind bestehende Verbindungen und Loopback, ungültige Pakete werden verworfen.
- ICMP: für IPv6 nötige Typen (ND, RA, Packet Too Big usw.) erlaubt, Ping mit Ratenbegrenzung.
- Offen: nur SSH (`SSH_PORT`, automatisch). Weitere Ports pro Host: `FIREWALL_TCP_PORTS`, `FIREWALL_UDP_PORTS`.
- `check`: Abgleich lauschende Dienste ↔ offene Ports (blockierter, aber nach außen lauschender Dienst = Hinweis; offener Port ohne Dienst = WARN).

### SSH-Zugriff
- Von überall erreichbar, neue Verbindungen pro IP begrenzt (Ratenlimit); Angreifer sperrt CrowdSec.
- Optional `FIREWALL_SSH_ALLOW="…"` (in `local.conf`, Repo ist öffentlich). `setup` verweigert, wenn die aktuelle SSH-Client-IP nicht enthalten ist.

### Ausgehend
- Standard: alles erlaubt. `FIREWALL_OUTPUT_POLICY=drop` pro Server: dann nur DNS 53, HTTP/S 80/443, NTP 123, NTS 4460
  plus `FIREWALL_OUT_TCP_PORTS` / `FIREWALL_OUT_UDP_PORTS`.

### Erweiterbarkeit für Dienst-Module
- Helfer `firewall_rules MODUL <<<'…'` schreibt `/etc/srvctl/firewall.d/MODUL.nft`; die Bausteine werden in `inet srvctl` eingebunden.
- Docker-Details (forward, `DOCKER-USER`, veröffentlichte Ports) folgen im Modul `docker`; bis dahin meldet `check` FAIL, falls Docker ohne dieses Modul installiert ist.
- Option im späteren `tailscale`-Modul: SSH nur über `tailscale0`.

## 5. `crowdsec`

### Paketquelle
- Offizielles CrowdSec-Repository als deb822-Quelle mit `signed-by`; **kein** `curl | bash`.
- Fingerprint des Repo-Schlüssels fest im Modul hinterlegt und beim Download geprüft.
- `base` führt die Quelle als erlaubte Fremdquelle.

### Datenaustausch
- Signale teilen und Gemeinschafts-Blockliste empfangen (Standard).
- Web-Console optional: `CROWDSEC_ENROLL_KEY` in `local.conf` → Server wird angemeldet.
- DSGVO: Angreifer-IPs sind personenbezogen; Grundlage ist das berechtigte Interesse (IT-Sicherheit).

### Erkennung
- Collections: `crowdsecurity/linux`, `crowdsecurity/sshd-impossible-travel`; weitere über `CROWDSEC_COLLECTIONS`.
  Dienst-Module bringen ihre eigenen Collections mit (z. B. `nginx` → `crowdsecurity/nginx`, `crowdsecurity/http-cve`).
- **Quelle journald** (Debian 13 hat kein rsyslog und damit kein `auth.log`); Erfassung für sshd ausdrücklich konfiguriert.
- Täglicher Timer: `cscli hub update && cscli hub upgrade`.
- `check`: Dienst und Bouncer aktiv, CrowdSec verarbeitet tatsächlich Logzeilen (`cscli metrics`), Verbindung zur Gemeinschafts-API.

### Sperren
- Bouncer `crowdsec-firewall-bouncer-nftables` (eigene Tabelle).
- Sperrdauer 4 h, bei Wiederholung steigend (4 h × Anzahl bisheriger Sperren); `CROWDSEC_BAN_DURATION`.
- Allowlist `CROWDSEC_WHITELIST` (in `local.conf`); das spätere `tailscale`-Modul ergänzt `100.64.0.0/10`.

## 6. `kernel`

### Netzwerk-sysctl (`/etc/sysctl.d/90-srvctl.conf`)
- `rp_filter=1`, `accept_redirects=0`, `send_redirects=0`, `secure_redirects=0`, `accept_source_route=0`,
  `tcp_syncookies=1`, `log_martians=1`, `icmp_echo_ignore_broadcasts=1`, `icmp_ignore_bogus_error_responses=1`, `tcp_rfc1337=1`.
- **Nicht** gesetzt: `ip_forward` (Sache von `docker`/`tailscale`), `accept_ra=0` (würde IPv6 auf vielen VPS abschalten).

### Kernel-sysctl
- `kptr_restrict=2`, `dmesg_restrict=1`, `unprivileged_bpf_disabled=1`, `bpf_jit_harden=2`, `kexec_load_disabled=1`,
  `perf_event_paranoid=3`, `sysrq=0`, `randomize_va_space=2`, `fs.suid_dumpable=0`, `fs.protected_hardlinks/symlinks=1`,
  `fs.protected_fifos/regular=2`.
- `kernel.yama.ptrace_scope=1`; unprivilegierte User-Namespaces bleiben an (Docker, Sandboxes). Strenger per Config.

### Kernelmodule sperren (`install … /bin/false`)
- `cramfs`, `freevxfs`, `hfs`, `hfsplus`, `jffs2`, `udf`, `dccp`, `sctp`, `rds`, `tipc`, `usb-storage`, `firewire-core`, `bluetooth`.
- Nicht gesperrt: `overlay`, `br_netfilter`, `squashfs`, `wireguard`. Zusätzlich: `KERNEL_BLACKLIST_EXTRA`.

### Mount-Optionen
- `/dev/shm`: `nodev,nosuid,noexec`.
- `/tmp`, `/var/tmp`: `nodev,nosuid`; `noexec` per `KERNEL_TMP_NOEXEC=1` zuschaltbar.

### Core-Dumps
- Aus: `* hard core 0`, `fs.suid_dumpable=0`, systemd-coredump `Storage=none`.

## 7. `services`

### Lauschende Dienste
- `check` listet Dienste, die nicht nur auf localhost lauschen (`ss -tulpn`), mit Prozess, Port und Paket.
- Erlaubt: sshd, chrony, CrowdSec, `SERVICES_ALLOWED` sowie von anderen srvctl-Modulen angemeldete Dienste.
- Unbekannte: nur WARN, nichts wird automatisch abgeschaltet.

### Unerwünschte Dienste
- `avahi-daemon`, `cups`, `rpcbind`, `nfs-server`, `smbd`, `snmpd`, `bluetooth`, `ModemManager` (Liste per Config).
- `configure`: stoppen, deaktivieren, maskieren (nach Rückfrage).

### cron und at
- `cron.allow`/`at.allow` nur `root`; Rechte `600`/`700` für `/etc/crontab` und `/etc/cron.*`.
- Nicht installiert = erfüllt (es wird nichts nachinstalliert).

### Mailserver
- Falls exim4/postfix vorhanden: nur auf localhost lauschen. Mailversand nach außen ggf. späteres eigenes Modul.

## 8. `logging`

### journald
- `Storage=persistent`, `Compress=yes`, `MaxRetentionSec=90d`, `SystemMaxUse=1G` (`LOGGING_RETENTION`, `LOGGING_MAX_USE`).

### auditd
- CIS-Regelsatz: Benutzer/Gruppen/Passwörter, sudoers, SSH-Konfiguration, Zeit, Netzwerk, Anmeldungen/Sitzungen,
  privilegierte Programme (setuid), Kernelmodule, Mounts, Löschungen durch Benutzer, AppArmor-Richtlinien.
- Standard änderbar; `LOGGING_AUDIT_IMMUTABLE=1` setzt `-e 2` (Änderung dann nur mit Neustart). `check` meldet den Modus.

### Zentrales Logging
- Vorerst nicht; später eigenes Modul (z. B. systemd-journal-upload oder Vector → Loki), bevorzugt über Tailscale.

### Logrotation und Rechte
- logrotate für `/var/log/srvctl.log` und `/var/log/sudo.log`; Logdateien nicht für alle lesbar (`640`).

## 9. `apparmor`
- `apparmor-utils` und `apparmor-profiles-extra` installieren; prüfen, ob AppArmor im Kernel aktiv ist.
- Profile, die Debian im Enforce-Modus ausliefert, bleiben dort; Complain-Profile werden gemeldet.
  `APPARMOR_ENFORCE="…"` stellt einzelne Profile gezielt auf Enforce.
- `check`: `aa-unconfined` – nach außen lauschende Dienste ohne Profil = WARN.

## 10. `integrity`
- **AIDE** mit Debian-Standardregeln, tägliche Prüfung per Timer, Ergebnis im journald; `check` meldet den letzten Befund.
- Baseline: apt-Hook prüft **vor** Paket-Updates gegen die Baseline (Abweichungen werden gemeldet und gesichert)
  und aktualisiert sie **danach**; srvctl aktualisiert sie ebenso nach eigenen Änderungen.
- `check`: `dpkg --verify` (veränderte Paketdateien).
- Kein rkhunter/chkrootkit (viele Fehlalarme, wenig Nutzen gegenüber AIDE + auditd + Lynis).

## 11. `audit` (nur `check`)
- Lynis aus dem Debian-Paket (vor der Umsetzung prüfen, ob die Version Debian 13 vollständig kennt).
- Bewertung: Hardening-Index ≥ `AUDIT_MIN_SCORE` (80) OK, darunter WARN, unter 70 FAIL; Lynis-Warnungen einzeln als WARN.
- Eigenes Lynis-Profil mit **bewussten Ausnahmen** aus dieser Planung (z. B. kein Passwortablauf, Port 22, kein `noexec` auf `/tmp`).
- Wöchentlicher Timer speichert den Bericht; `check` nutzt ihn, solange er jünger als 7 Tage ist.
  `srvctl --fresh check audit` erzwingt einen neuen Lauf.

## Framework-Erweiterungen (aus der Planung) – umgesetzt
- Helfer `ask` für Texteingaben (mit Validierung, mehrzeilig für Schlüssel), `ask_password` (verdeckt, doppelte Eingabe).
- Statusverzeichnis `/var/lib/srvctl` (nur root) für lokalen Modulzustand.
- **Bestätigungs-Timer:** `confirm_or_revert` startet einen `systemd-run`-Timer, der die Backups des Laufs zurückspielt
  und Dienste neu lädt, wenn nicht rechtzeitig `srvctl confirm` aufgerufen wird. Genutzt von `ssh` und `firewall`.
- **`srvctl status`:** Tabelle pro Modul (umgesetzt / Abweichungen / nicht umgesetzt) aus einem stillen `check`-Lauf
  plus letzte Änderung (Zeitpunkt, Aktion) aus `/var/lib/srvctl`.
- **Dienst-Registrierung:** Module deklarieren `MODULE_LISTEN=(prozess …)`; `services` erlaubt diese Prozesse.
- **Option `--fresh`:** Module ignorieren zwischengespeicherte Ergebnisse (z. B. Lynis-Bericht).
