# shellcheck shell=bash
# crowdsec - CrowdSec agent with nftables bouncer from the official repository
# (Debian ships 1.4.6). Detects attacks in the journal (SSH first), blocks
# attackers and uses the community blocklist.
# Decisions: docs/PLAN.md, section "5. crowdsec".

MODULE_NAME="crowdsec"
MODULE_DESC="CrowdSec: Angriffserkennung, Sperren per nftables, Gemeinschafts-Blockliste"
MODULE_DEPENDS=(firewall)

readonly _CS_KEY_URL=https://packagecloud.io/crowdsec/crowdsec/gpgkey
# Signing key of the packagecloud repository (verified 2026-10-09)
readonly _CS_KEY_FPR=6A89E3C2303A901A889971D3376ED5326E93CD0C
readonly _CS_REPO_URL=https://packagecloud.io/crowdsec/crowdsec/any
readonly _CS_KEYRING=/etc/apt/keyrings/srvctl-crowdsec.gpg
readonly _CS_SOURCES=/etc/apt/sources.list.d/srvctl-crowdsec.sources
readonly _CS_PIN=/etc/apt/preferences.d/srvctl-crowdsec
readonly _CS_UU=/etc/apt/apt.conf.d/53srvctl-crowdsec
readonly _CS_PROFILES=/etc/crowdsec/profiles.yaml
readonly _CS_WHITELIST=/etc/crowdsec/parsers/s02-enrich/srvctl-whitelist.yaml
readonly _CS_ACQUIS=/etc/crowdsec/acquis.d/srvctl-sshd.yaml
readonly _CS_METRICS=http://127.0.0.1:6060/metrics
readonly _CS_BOUNCER_CONF=/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
readonly _CS_PACKAGES="crowdsec crowdsec-firewall-bouncer-nftables"
readonly _CS_HEADER="Verwaltet von srvctl (Modul: crowdsec) – manuelle Änderungen werden überschrieben"

# --- Configuration -------------------------------------------------------------

_cs_collections() {
  echo "crowdsecurity/linux crowdsecurity/sshd-impossible-travel $(cfg_get CROWDSEC_COLLECTIONS "")"
}

_cs_ban_hours() { cfg_get CROWDSEC_BAN_HOURS 4; }

_cs_validate() {
  local ok=0 entry
  if [[ ! $(_cs_ban_hours) =~ ^[1-9][0-9]*$ ]]; then
    result_fail "CROWDSEC_BAN_HOURS: '$(_cs_ban_hours)' ist keine Stundenzahl"
    ok=1
  fi
  for entry in $(cfg_get CROWDSEC_WHITELIST ""); do
    if [[ ! $entry =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ ]]; then
      result_fail "CROWDSEC_WHITELIST: '$entry' ist keine IP-Adresse oder kein Netz"
      ok=1
    fi
  done
  for entry in $(_cs_collections); do
    if [[ ! $entry =~ ^[a-z0-9_-]+/[a-z0-9_.-]+$ ]]; then
      result_fail "CROWDSEC_COLLECTIONS: '$entry' ist kein Collection-Name"
      ok=1
    fi
  done
  return "$ok"
}

# --- Repository ----------------------------------------------------------------

_cs_keyring_fpr() {
  gpg --show-keys --with-colons "$1" 2>/dev/null | awk -F: '$1 == "fpr" { print $10; exit }'
}

_cs_apply_repo() {
  local changed=0 tmp fpr

  if [[ ! -f $_CS_KEYRING || $(_cs_keyring_fpr "$_CS_KEYRING") != "$_CS_KEY_FPR" ]]; then
    tmp=$(mktemp "${RUN_DIR}/cskey.XXXXXX")
    if ! curl -fsSL --proto '=https' --tlsv1.2 --max-time 30 -o "$tmp" "$_CS_KEY_URL"; then
      result_fail "Repo-Schlüssel konnte nicht geladen werden ($_CS_KEY_URL)"
      return 1
    fi
    fpr=$(_cs_keyring_fpr "$tmp")
    if [[ $fpr != "$_CS_KEY_FPR" ]]; then
      result_fail "Repo-Schlüssel hat den Fingerprint '${fpr:-?}', erwartet $_CS_KEY_FPR – abgebrochen"
      return 1
    fi
    log_info "Repo-Schlüssel geprüft: $fpr"
    gpg --dearmor <"$tmp" >"${tmp}.gpg"
    write_file "$_CS_KEYRING" 0644 <"${tmp}.gpg"
    if ((FILE_CHANGED)); then changed=1; fi
  fi

  write_file "$_CS_SOURCES" 0644 <<<"# ${_CS_HEADER}
Types: deb
URIs: ${_CS_REPO_URL}
Suites: any
Components: main
Signed-By: ${_CS_KEYRING}"
  if ((FILE_CHANGED)); then changed=1; fi

  # Specific record first: only the CrowdSec packages may come from this repo.
  write_file "$_CS_PIN" 0644 <<<"# ${_CS_HEADER}
# Aus dem CrowdSec-Repository nur die CrowdSec-Pakete zulassen (aktuelle Version statt Debians 1.4.6)
Package: ${_CS_PACKAGES}
Pin: origin packagecloud.io
Pin-Priority: 600

Package: *
Pin: origin packagecloud.io
Pin-Priority: -1"
  if ((FILE_CHANGED)); then changed=1; fi

  write_file "$_CS_UU" 0644 <<<"// ${_CS_HEADER}
// CrowdSec-Pakete automatisch aktualisieren (nur diese erlaubt das Pinning)
Unattended-Upgrade::Origins-Pattern {
        \"origin=packagecloud.io/crowdsec/crowdsec,label=crowdsec\";
};"

  if ((changed)); then
    rm -f -- "${RUN_DIR}/apt-updated" # force apt-get update for the new source
  fi
  pkg_update_once
}

# --- Configuration files -------------------------------------------------------

_cs_profiles() {
  local hours expr
  hours=$(_cs_ban_hours)
  # Repeat offenders: hours × (number of earlier decisions + 1)
  expr="Sprintf('%dh', (GetDecisionsCount(Alert.GetValue()) + 1) * ${hours})"
  cat <<EOF
# ${_CS_HEADER}
# Sperre ${hours} h, bei Wiederholung steigend (${hours} h × Anzahl bisheriger Sperren + 1)
name: default_ip_remediation
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Ip"
decisions:
 - type: ban
   duration: ${hours}h
duration_expr: "${expr}"
on_success: break
---
name: default_range_remediation
filters:
 - Alert.Remediation == true && Alert.GetScope() == "Range"
decisions:
 - type: ban
   duration: ${hours}h
on_success: break
EOF
}

_cs_whitelist() {
  local entry
  local -a ips=() cidrs=()
  for entry in $(cfg_get CROWDSEC_WHITELIST ""); do
    if [[ $entry == */* ]]; then cidrs+=("$entry"); else ips+=("$entry"); fi
  done
  ((${#ips[@]} + ${#cidrs[@]})) || return 0
  echo "# ${_CS_HEADER}"
  echo "name: srvctl/whitelist"
  echo "description: \"Von srvctl verwaltete Allowlist (CROWDSEC_WHITELIST)\""
  echo "whitelist:"
  echo "  reason: \"CROWDSEC_WHITELIST (srvctl)\""
  if ((${#ips[@]})); then
    echo "  ip:"
    printf '    - "%s"\n' "${ips[@]}"
  fi
  if ((${#cidrs[@]})); then
    echo "  cidr:"
    printf '    - "%s"\n' "${cidrs[@]}"
  fi
}

# True if some acquisition already reads sshd from the journal
_cs_has_ssh_acquisition() {
  grep -rqsE '_SYSTEMD_UNIT=ssh\.service' /etc/crowdsec/acquis.yaml /etc/crowdsec/acquis.d/
}

_cs_installed_collections() {
  cscli collections list -o json 2>/dev/null | python3 -c '
import json, sys
try:
    items = json.load(sys.stdin).get("collections") or []
except ValueError:
    items = []
for item in items:
    if "enabled" in str(item.get("status", "")) or item.get("installed"):
        print(item.get("name", ""))
' 2>/dev/null || true
}

# Applies collections, acquisition, profiles and whitelist. Sets _CS_CHANGED.
_cs_apply_config() {
  local collection missing=()
  local installed
  installed=$(_cs_installed_collections)
  for collection in $(_cs_collections); do
    grep -qxF "$collection" <<<"$installed" || missing+=("$collection")
  done
  if ((${#missing[@]})); then
    run_cmd cscli collections install "${missing[@]}"
    _CS_CHANGED=1
  fi

  if ! _cs_has_ssh_acquisition; then
    write_file "$_CS_ACQUIS" 0644 <<<"# ${_CS_HEADER}
# Debian 13 hat kein auth.log: sshd direkt aus dem Journal lesen
source: journalctl
journalctl_filter:
  - \"_SYSTEMD_UNIT=ssh.service\"
labels:
  type: syslog"
    if ((FILE_CHANGED)); then _CS_CHANGED=1; fi
  fi

  write_file "$_CS_PROFILES" 0644 <<<"$(_cs_profiles)"
  if ((FILE_CHANGED)); then _CS_CHANGED=1; fi

  local whitelist
  whitelist=$(_cs_whitelist)
  if [[ -n $whitelist ]]; then
    write_file "$_CS_WHITELIST" 0644 <<<"$whitelist"
    if ((FILE_CHANGED)); then _CS_CHANGED=1; fi
  elif [[ -f $_CS_WHITELIST ]]; then
    backup_file "$_CS_WHITELIST"
    run_cmd rm -f -- "$_CS_WHITELIST"
    _CS_CHANGED=1
  fi
}

_cs_bouncer_key() { sed -n 's/^api_key:[[:space:]]*//p' "$_CS_BOUNCER_CONF" 2>/dev/null; }

_cs_bouncer_key_missing() {
  local key
  key=$(_cs_bouncer_key)
  [[ -z $key || $key == "<API_KEY>" || $key == '${API_KEY}' ]]
}

# The bouncer's postinst registers itself via cscli. If CrowdSec is installed
# in the same apt run it is often not configured yet, the registration fails
# and the config keeps the placeholder "<API_KEY>", so the service cannot start.
_cs_ensure_bouncer_key() {
  _cs_bouncer_key_missing || return 0
  if ((DRY_RUN)); then
    log_dry "Bouncer bei der lokalen API registrieren und API-Schlüssel eintragen"
    return 0
  fi
  log_info "Firewall-Bouncer hat keinen API-Schlüssel – wird bei der lokalen API registriert"
  local id key
  id="crowdsec-firewall-bouncer-$(date +%s)"
  # Not via run_cmd: the key must not end up in the log.
  _log_file CMD "cscli -oraw bouncers add $id"
  key=$(cscli -oraw bouncers add "$id")
  if [[ ! $key =~ ^[A-Za-z0-9+/=_-]+$ ]]; then
    result_fail "Bouncer konnte nicht registriert werden (cscli bouncers add)"
    return 1
  fi
  file_sed "$_CS_BOUNCER_CONF" "s|^api_key:.*$|api_key: ${key}|"
  printf '%s\n' "$id" >"${_CS_BOUNCER_CONF}.id"
  result_ok "Firewall-Bouncer registriert ($id)"
}

_cs_apply_enroll() {
  local key state
  key=$(cfg_get CROWDSEC_ENROLL_KEY "")
  [[ -n $key ]] || return 0
  state=$(state_path crowdsec enrolled)
  [[ -f $state ]] && return 0
  if ((DRY_RUN)); then
    log_dry "cscli console enroll -e context --name $(hostname -s) ***"
    return 0
  fi
  # Not via run_cmd: the key must not end up in the log.
  _log_file CMD "cscli console enroll -e context --name $(hostname -s) ***"
  cscli console enroll -e context --name "$(hostname -s)" "$key"
  write_file "$state" 0600 <<<"$RUN_ID"
  result_ok "Bei der CrowdSec-Console angemeldet – Anmeldung dort im Browser bestätigen"
}

# --- Checks --------------------------------------------------------------------

# _cs_metric NAME [FILTER] - sums a Prometheus metric (optionally lines matching FILTER)
_cs_metric() {
  curl -fsS --max-time 5 "$_CS_METRICS" 2>/dev/null |
    awk -v m="$1" -v f="${2:-}" '$1 ~ "^" m "[{ ]" || $1 == m {
      if (f == "" || index($0, f)) sum += $NF; found = 1 }
      END { if (found) printf "%d\n", sum }'
}

_cs_check() {
  local pkg
  for pkg in $_CS_PACKAGES; do
    if ! pkg_installed "$pkg"; then
      result_fail "$pkg ist nicht installiert – 'srvctl setup crowdsec'"
      return 0
    fi
  done
  local version
  version=$(dpkg-query -W -f='${Version}' crowdsec)
  result_ok "CrowdSec $version aus dem offiziellen Repository"
  if [[ ! -f $_CS_PIN || ! -f $_CS_UU ]]; then
    result_warn "Pinning oder automatische Updates für CrowdSec fehlen – 'srvctl configure crowdsec'"
  fi

  check_service crowdsec
  check_service crowdsec-firewall-bouncer
  if _cs_bouncer_key_missing; then
    result_fail "Firewall-Bouncer hat keinen API-Schlüssel – 'srvctl configure crowdsec'"
  fi
  if ! svc_is_enabled crowdsec-hubupdate.timer; then
    result_warn "Tägliches Hub-Update (crowdsec-hubupdate.timer) ist nicht aktiv"
  fi

  if cscli lapi status >/dev/null 2>&1; then
    result_ok "Lokale API erreichbar"
  else
    result_fail "Lokale API antwortet nicht (cscli lapi status)"
  fi
  if cscli capi status >/dev/null 2>&1; then
    result_ok "Verbindung zur Gemeinschafts-API (Signale teilen, Blockliste empfangen)"
  else
    result_warn "Keine Verbindung zur Gemeinschafts-API (cscli capi status)"
  fi

  local installed collection missing=()
  installed=$(_cs_installed_collections)
  for collection in $(_cs_collections); do
    grep -qxF "$collection" <<<"$installed" || missing+=("$collection")
  done
  if ((${#missing[@]})); then
    result_warn "Fehlende Collections: ${missing[*]}"
  else
    result_ok "Collections aktiv: $(_cs_collections)"
  fi

  if ! _cs_has_ssh_acquisition; then
    result_fail "CrowdSec liest das SSH-Journal nicht (keine Erfassung für ssh.service)"
  else
    local hits
    hits=$(_cs_metric cs_journalctlsource_hits_total ssh.service)
    if [[ -z $hits ]]; then
      result_warn "Metriken nicht abrufbar ($_CS_METRICS) – Verarbeitung nicht prüfbar"
    elif ((hits > 0)); then
      result_ok "SSH-Journal wird verarbeitet ($hits Zeilen seit dem Start)"
    else
      result_warn "Noch keine SSH-Logzeilen verarbeitet (frisch gestartet?)"
    fi
  fi

  if grep -q 'duration_expr' "$_CS_PROFILES" 2>/dev/null; then
    result_ok "Sperrdauer $(_cs_ban_hours) h, bei Wiederholung steigend"
  else
    result_warn "Sperrdauer steigt bei Wiederholung nicht (profiles.yaml)"
  fi

  local tables
  tables=$(nft list tables 2>/dev/null)
  if grep -q 'crowdsec' <<<"$tables"; then
    local decisions
    decisions=$(_cs_metric cs_active_decisions)
    result_ok "Bouncer aktiv (nftables)${decisions:+, $decisions gesperrte Adressen/Netze}"
  else
    result_fail "Bouncer-Tabellen fehlen in nftables – Sperren wirken nicht"
  fi
}

# --- Actions -------------------------------------------------------------------

crowdsec::check() {
  _cs_validate || return 0
  _cs_check
}

crowdsec::setup() {
  _cs_validate || return 1
  pkg_install curl gnupg ca-certificates
  _cs_apply_repo
  local -a pkgs
  read -ra pkgs <<<"$_CS_PACKAGES"
  pkg_install "${pkgs[@]}"
  crowdsec::configure
}

crowdsec::configure() {
  _cs_validate || return 1
  if ((!DRY_RUN)) && ! pkg_installed crowdsec; then
    result_fail "CrowdSec ist nicht installiert – zuerst 'srvctl setup crowdsec'"
    return 1
  fi
  if ((DRY_RUN)) && ! pkg_installed crowdsec; then
    log_dry "Konfiguration (Collections, Profile, Allowlist) wird nach der Installation angewendet"
    return 0
  fi
  _cs_apply_repo
  _CS_CHANGED=0
  _cs_apply_config
  if ((_CS_CHANGED)); then
    if ((!DRY_RUN)) && ! crowdsec -t >/dev/null 2>&1; then
      result_fail "CrowdSec-Konfiguration ungültig (crowdsec -t) – Änderungen werden zurückgesetzt"
      backup_restore_run crowdsec "$RUN_ID"
      return 1
    fi
    svc_reload crowdsec
    result_ok "CrowdSec konfiguriert (Collections, Sperrdauer, Allowlist)"
  else
    result_ok "CrowdSec-Konfiguration ist aktuell"
  fi
  svc_enable crowdsec
  _cs_ensure_bouncer_key
  if svc_is_active crowdsec-firewall-bouncer; then
    : # running with a valid key
  else
    run_cmd systemctl enable crowdsec-firewall-bouncer
    run_cmd systemctl restart crowdsec-firewall-bouncer
  fi
  _cs_apply_enroll
}
