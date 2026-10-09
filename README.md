# srvctl

Modulares Bash-Werkzeug, um Debian- und Ubuntu-Server **zu prüfen, einzurichten und zu konfigurieren**.
Es läuft lokal auf dem jeweiligen Server.

## Installation

```bash
git clone git@github.com:spudan/srvctl.git /opt/srvctl
chown -R root:root /opt/srvctl && chmod -R go-w /opt/srvctl
ln -s /opt/srvctl/srvctl /usr/local/bin/srvctl
```

Voraussetzungen: Debian oder Ubuntu, Bash ≥ 5, root-Rechte. Für das Menü wird `whiptail` gebraucht.

> **Sicherheit:** srvctl läuft als root und führt alle Dateien in seinem Verzeichnis aus.
> Das Verzeichnis und alle übergeordneten Verzeichnisse dürfen deshalb nur für root beschreibbar sein.
> srvctl prüft das bei jedem Start und warnt bzw. bricht ab. Empfohlen ist `/opt/srvctl`,
> kein Web- oder Home-Verzeichnis.

## Benutzung

```bash
srvctl                         # interaktives Menü
srvctl check                   # alle Module prüfen
srvctl check ssh firewall      # bestimmte Module prüfen
srvctl setup nginx --dry-run   # zeigen, was passieren würde
srvctl setup nginx             # einrichten (mit Rückfrage)
srvctl -y configure all        # ohne Rückfragen konfigurieren
srvctl rollback nginx          # letzte Änderung des Moduls rückgängig machen
srvctl list                    # Module anzeigen
srvctl info nginx              # Details zu einem Modul
srvctl backups                 # vorhandene Backups anzeigen
```

| Option | Bedeutung |
|---|---|
| `-n`, `--dry-run` | Nur anzeigen, was passieren würde (inkl. Diff bei Dateien) |
| `-y`, `--yes` | Keine Rückfragen |
| `-v`, `--verbose` | Ausführliche Ausgabe, zeigt auch ausgeführte Befehle |
| `-q`, `--quiet` | Nur Warnungen, Fehler und Zusammenfassung (für cron) |
| `--no-color` | Keine Farben (automatisch, wenn die Ausgabe kein Terminal ist) |
| `-c`, `--config DATEI` | Zusätzliche Konfigurationsdatei |
| `--host NAME` | Host-Konfiguration für NAME statt `hostname -s` |

**Exit-Codes:** `0` alles OK · `1` Warnungen · `2` Fehler · `3` Framework-Fehler · `64` Aufruffehler · `130` abgebrochen.
So lässt sich z. B. ein cron-Job bauen: `srvctl -q check || mail ...`

## Verhalten

- **Abhängigkeiten:** Bei `setup` und `configure` werden Abhängigkeiten automatisch vorher ausgeführt. Schlägt ein Modul fehl, werden die Module, die davon abhängen, übersprungen. `check` und `rollback` bringen nur die angegebenen Module in die richtige Reihenfolge, `rollback` in umgekehrter Reihenfolge.
- **Rückfrage:** Vor `setup`/`configure`/`rollback` zeigt srvctl den Plan an und fragt nach. Ohne Terminal und ohne `--yes` bricht es ab.
- **Backups:** Jede Datei wird vor einer Änderung nach `/var/backups/srvctl/<Lauf>/<Pfad>` gesichert. Aufbewahrt werden die letzten 30 Läufe.
- **Rollback** arbeitet wie ein Undo-Stapel: Jeder Aufruf macht den jüngsten noch nicht zurückgesetzten Lauf des Moduls rückgängig. Dateien, die es vorher nicht gab, werden wieder entfernt.
- **Log:** Alle Schritte, Befehle und Ergebnisse landen in `/var/log/srvctl.log`.
- **Sperre:** Ändernde Aktionen können nicht parallel laufen (`/run/lock/srvctl.lock`).

## Konfiguration

Die Dateien werden nacheinander geladen, spätere Dateien überschreiben frühere:

1. `config/default.conf` – Standardwerte
2. `config/hosts/<hostname>.conf` – pro Server
3. `config/local.conf` – lokal, nicht in Git (z. B. für Geheimnisse)
4. `--config DATEI`

Format: Bash-Variablen (`NAME="wert"`). Modul-Einstellungen beginnen mit dem Modulnamen in Großbuchstaben (`NGINX_...`).
Konfigurationsdateien müssen root gehören und dürfen nicht für Gruppe/andere beschreibbar sein.

Wichtige Framework-Variablen: `MODULES_ENABLED` / `MODULES_DISABLED` (was `all` umfasst), `SRVCTL_LOG_FILE`,
`SRVCTL_BACKUP_DIR`, `SRVCTL_BACKUP_KEEP`, `SRVCTL_IGNORE_PATH_WARNING`.

## Eigene Module schreiben

Ein Modul ist eine Datei `modules/<name>.sh`. Vorlage: [`modules/example.sh`](modules/example.sh).

```bash
MODULE_NAME="nginx"                 # muss dem Dateinamen entsprechen
MODULE_DESC="Webserver nginx"
MODULE_DEPENDS=()                   # z. B. (base firewall)

nginx::check()     { check_pkg nginx; check_service nginx; }
nginx::setup()     { pkg_install nginx; svc_enable nginx; }
nginx::configure() { ...; }
nginx::rollback()  { backup_restore_module nginx; svc_reload nginx; }   # optional
```

Regeln:

- Alle Aktionen sind optional. Ohne `rollback` stellt das Framework automatisch die gesicherten Dateien wieder her.
- `setup` und `configure` müssen **idempotent** sein, also gefahrlos mehrfach laufen können.
- `setup`/`configure`/`rollback` laufen mit `errexit`: Der erste fehlschlagende Befehl bricht das Modul ab. Befehle, die bewusst fehlschlagen dürfen, gehören in `if` oder hinter `||`. `check` läuft ohne `errexit`.
- Nicht gesetzte Variablen sind ein Fehler (`nounset`). Für Werte mit Standard gibt es `cfg_get NAME default`.
- Ergebnisse immer über `result_*` melden. Dateien nur über `write_file`/`conf_set`/`ensure_line` ändern und Befehle über `run_cmd` ausführen, dann greifen Backup, Dry-Run und Log.
- Kein `exit` in Modulen, sondern `return`.
- Templates gehören nach `templates/<modul>/`.

### Helfer-Referenz

| Bereich | Funktionen |
|---|---|
| Ergebnisse | `result_ok`, `result_warn`, `result_fail`, `result_skip` |
| Ausgabe | `log_info`, `log_warn`, `log_error`, `log_debug` |
| Konfiguration | `cfg_get NAME [DEFAULT]`, `cfg_require NAME...` |
| Ausführen | `run_cmd CMD...` (Dry-Run-fähig), `confirm "Frage?"` |
| Dateien | `write_file PFAD [MODUS] [BESITZER] <<<"$inhalt"`, `conf_get DATEI KEY [SEP]`, `conf_set DATEI KEY WERT [SEP]`, `ensure_line DATEI ZEILE`, `template_render DATEI` – nach Änderungen ist `FILE_CHANGED=1` |
| Backups | `backup_file PFAD`, `backup_restore PFAD [LAUF]`, `backup_restore_module MODUL` |
| Pakete | `pkg_installed`, `pkg_install`, `pkg_remove`, `pkg_update_once` |
| Dienste | `svc_exists`, `svc_is_active`, `svc_is_enabled`, `svc_enable`, `svc_disable`, `svc_restart`, `svc_reload` |
| Fertige Checks | `check_pkg PAKET`, `check_service DIENST`, `check_conf DATEI KEY ERWARTET [SEP]` |
| System | `cmd_exists`, `os_is debian`, `os_version_ge 12`, Variablen `OS_ID`, `OS_VERSION`, `OS_CODENAME`, `CONFIG_HOST` |

`write_file` per `<<<` oder `< <(...)` füttern, nicht über eine Pipe, sonst geht `FILE_CHANGED` verloren.

## Struktur

```
srvctl              Einstiegspunkt (Argumente, Ablauf)
lib/log.sh          Ausgabe, Logdatei, Ergebnisse, Zusammenfassung
lib/core.sh         Root-Check, OS-Erkennung, Sperre, Rechteprüfung
lib/config.sh       Laden der Konfiguration
lib/safety.sh       Backups, Rollback, Dry-Run, Rückfragen, write_file
lib/helpers.sh      Helfer für Module (Pakete, Dienste, Config-Dateien, Templates)
lib/modules.sh      Module laden, Abhängigkeiten, Ausführung
lib/menu.sh         whiptail-Menü
modules/            Module
templates/          Vorlagen für Konfigurationsdateien
config/             Konfiguration
```
