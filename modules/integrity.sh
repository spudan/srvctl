# shellcheck shell=bash
# integrity - file integrity monitoring with AIDE (Debian's daily check with
# package-update filter) and dpkg --verify. Findings stay visible in check
# until they are acknowledged with "srvctl configure integrity".
# Decisions: docs/PLAN.md, section "10. integrity".

MODULE_NAME="integrity"
MODULE_DESC="Integrität: AIDE-Tagesprüfung (ohne Paket-Updates), veränderte Paketdateien"
MODULE_DEPENDS=()

readonly _INT_DEFAULTS=/etc/default/aide
readonly _INT_EXCLUDES=/etc/aide/aide.conf.d/99_aide_srvctl
readonly _INT_REPORTER=/usr/local/sbin/srvctl-aide-report
readonly _INT_REPORT_DIR=/var/log/aide
readonly _INT_DB=/var/lib/aide/aide.db
readonly _INT_HEADER="Verwaltet von srvctl (Modul: integrity) – manuelle Änderungen werden überschrieben"

# --- Helpers -------------------------------------------------------------------

_int_ack_file() { state_path integrity acknowledged; }

# Epoch of the last acknowledgement (0 if never)
_int_ack_time() {
  local file
  file=$(_int_ack_file)
  [[ -r $file ]] && cat -- "$file" || echo 0
}

# Reports written after the last acknowledgement, oldest first
_int_open_reports() {
  local ack file
  ack=$(_int_ack_time)
  for file in "$_INT_REPORT_DIR"/srvctl-report-*.txt; do
    [[ -f $file ]] || continue
    (($(stat -c %Y "$file") > ack)) && echo "$file"
  done
  return 0
}

# Paths srvctl changed itself since the last acknowledgement (backup manifests)
_int_srvctl_paths() {
  local ack dir
  ack=$(_int_ack_time)
  for dir in "${BACKUP_DIR}"/*/; do
    [[ -f ${dir}MANIFEST ]] || continue
    (($(stat -c %Y "${dir}MANIFEST") > ack - 86400)) || continue
    awk -F'\t' '$1 == "SAVED" || $1 == "ABSENT" { print $3 }' "${dir}MANIFEST"
  done | sort -u
}

# Changed/added/removed paths in the open reports, without srvctl's own changes
_int_findings() {
  local -a reports
  mapfile -t reports < <(_int_open_reports)
  ((${#reports[@]})) || return 0
  # AIDE entry lines look like "f   ...    : /path" or "f++++++++++++++++: /path"
  sed -nE 's/^[a-zA-Z!][^:]{10,}:[[:space:]]+(\/.*)$/\1/p' "${reports[@]}" | sort -u |
    grep -vxF -f <(_int_srvctl_paths; echo /nonexistent-srvctl) || true
}

# --- AIDE ----------------------------------------------------------------------

_int_check_aide() {
  if ! pkg_installed aide; then
    result_fail "AIDE ist nicht installiert – 'srvctl setup integrity'"
    return 0
  fi
  if [[ ! -s $_INT_DB ]]; then
    result_fail "AIDE-Datenbank fehlt ($_INT_DB) – 'srvctl setup integrity'"
    return 0
  fi
  if ! svc_is_enabled dailyaidecheck.timer; then
    result_warn "Tägliche AIDE-Prüfung (dailyaidecheck.timer) ist nicht aktiv"
  fi
  if [[ ! -x $_INT_REPORTER ]] || ! grep -q "^MAILCMD=\"${_INT_REPORTER}\"" "$_INT_DEFAULTS" 2>/dev/null; then
    result_warn "AIDE-Berichte werden nicht für srvctl abgelegt – 'srvctl configure integrity'"
  fi

  local last age
  last=$(stat -c %Y "$_INT_REPORT_DIR/aide.log" 2>/dev/null) || last=""
  if [[ -z $last ]]; then
    result_warn "AIDE hat noch keine Tagesprüfung durchgeführt (läuft nachts)"
  else
    age=$((($(date +%s) - last) / 86400))
    if ((age >= 2)); then
      result_warn "Letzte AIDE-Prüfung vor $age Tagen – läuft dailyaidecheck.timer?"
    fi
  fi

  local -a findings reports
  mapfile -t findings < <(_int_findings)
  mapfile -t reports < <(_int_open_reports)
  if ((${#findings[@]})); then
    local shown
    shown=$(printf '%s\n' "${findings[@]:0:5}" | paste -sd ' ')
    ((${#findings[@]} > 5)) && shown+=" … (+$((${#findings[@]} - 5)))"
    result_warn "AIDE: ${#findings[@]} veränderte Datei(en) außerhalb von Paket-Updates: $shown – Bericht: ${reports[-1]}; nach Prüfung 'srvctl configure integrity'"
  else
    result_ok "AIDE: keine unerwarteten Dateiänderungen$([[ -n $last ]] && printf ' (letzte Prüfung %(%Y-%m-%d %H:%M)T)' "$last")"
  fi
}

# --- dpkg --verify -------------------------------------------------------------

# Package files whose content differs (configuration files excluded).
# Cached for a day; --fresh forces a new run.
_int_dpkg_verify() {
  local cache
  cache=$(state_path integrity dpkg-verify)
  if ((!FRESH)) && [[ -f $cache ]] && (($(date +%s) - $(stat -c %Y "$cache") < 86400)); then
    cat -- "$cache"
    return 0
  fi
  local out
  # Columns: 9 check flags, optional attribute ("c" = conffile), path. Only
  # content changes ("5" = checksum) of non-conffiles count.
  out=$(nice dpkg --verify 2>/dev/null | awk '$1 ~ /^..5/ && $2 != "c" { print $NF }' | sort -u)
  if ((!DRY_RUN)); then
    printf '%s\n' "$out" | grep . >"$cache" || : >"$cache"
  fi
  printf '%s\n' "$out" | grep . || true
}

_int_check_dpkg() {
  local -a changed
  mapfile -t changed < <(_int_dpkg_verify)
  if ((${#changed[@]})); then
    result_fail "Veränderte Programmdateien aus Paketen (dpkg --verify): $(printf '%s\n' "${changed[@]:0:5}" | paste -sd ' ')$( ((${#changed[@]} > 5)) && echo " … (+$((${#changed[@]} - 5)))")"
  else
    result_ok "Paketdateien unverändert (dpkg --verify$( ((FRESH)) || echo ", bis 24 h zwischengespeichert"))"
  fi
}

# --- Apply ---------------------------------------------------------------------

_INT_RULES_CHANGED=0

_int_apply_config() {
  write_file "$_INT_REPORTER" 0755 root:root <<EOF
#!/bin/sh
# ${_INT_HEADER}
# Wird von dailyaidecheck statt eines Mailprogramms aufgerufen (MAILCMD) und
# legt den gefilterten Bericht ab; srvctl check wertet ihn aus.
umask 027
file="${_INT_REPORT_DIR}/srvctl-report-\$(date +%Y%m%d-%H%M%S).txt"
cat > "\$file"
logger -t srvctl-aide -p auth.notice "AIDE-Tagesbericht gespeichert: \$file"
find "${_INT_REPORT_DIR}" -maxdepth 1 -name 'srvctl-report-*.txt' -mtime +90 -delete 2>/dev/null
exit 0
EOF

  local key value
  while read -r key value; do
    conf_set "$_INT_DEFAULTS" "$key" "$value" "="
  done <<EOF
COMMAND update
COPYNEWDB yes
FILTERUPDATES yes
FILTERINSTALLATIONS yes
QUIETREPORTS yes
SILENTREPORTS no
MAILCMD "${_INT_REPORTER}"
EOF

  write_file "$_INT_EXCLUDES" 0644 <<EOF
# ${_INT_HEADER}
# Laufend veränderte Dateien (AIDE: tiefster Verzeichnisknoten, darin erste Regel –
# deshalb nur Ausschlüsse, eingeschränkt auf Dateien "f" bzw. Verzeichnisse "d").

# srvctl: Laufzeit- und Statusdateien; die Verzeichnisse ändern sich durch neue Dateien,
# die Dateien darin (z. B. Schlüssel-Fingerprints) bleiben überwacht
!/tmp/srvctl\.
!/var/lib/srvctl(/[^/]+)?\$ d
!/var/lib/srvctl/pending(/|\$)
!/var/lib/srvctl/[^/]+/\.(last-action|reverted)\$ f
!/var/lib/srvctl/integrity/dpkg-verify\$ f
!/var/backups/srvctl(/|\$)

# Laufzeitdaten
!/run/faillock(/|\$)
!/var/lib/crowdsec/data/crowdsec\.db(-shm|-wal|-journal)?\$ f

# Wachsende Logdateien (Rechte prüft das Modul logging, Zugriffe protokolliert auditd)
!/var/log/audit/audit\.log(\.[0-9]+)?\$ f
!/var/log/(crowdsec|crowdsec_api|sudo|srvctl)\.log(\.[0-9]+(\.gz)?)?\$ f
!/var/log/aide/aideinit\.(log|errors)\$ f
EOF
  _INT_RULES_CHANGED=$FILE_CHANGED
  if ((!DRY_RUN)) && ! aide --config-check -c /etc/aide/aide.conf >/dev/null 2>&1; then
    result_fail "AIDE-Konfiguration ungültig (aide --config-check) – Änderungen werden zurückgesetzt"
    backup_restore_run integrity "$RUN_ID"
    return 1
  fi
  svc_enable dailyaidecheck.timer
}

# Creates the baseline, or rebuilds it when the exclusion rules changed
# (otherwise the next check reports the newly excluded entries as removed).
_int_apply_init() {
  if [[ -s $_INT_DB ]] && ((!_INT_RULES_CHANGED)); then
    return 0
  fi
  if [[ -s $_INT_DB ]]; then
    log_info "Ausnahmen geändert – AIDE-Baseline wird neu erstellt (dauert einige Minuten)"
  else
    log_info "AIDE-Datenbank wird erstellt – das dauert einige Minuten"
  fi
  run_cmd nice aideinit --yes --force
  result_ok "AIDE-Baseline erstellt ($_INT_DB)"
}

# Shows open findings and records the acknowledgement after confirmation
_int_acknowledge() {
  local -a findings
  mapfile -t findings < <(_int_findings)
  if ((${#findings[@]} == 0)); then
    if [[ -n $(_int_open_reports) ]]; then
      write_file "$(_int_ack_file)" 0600 <<<"$(date +%s)"
    fi
    return 0
  fi
  log_info "Offene AIDE-Funde (Berichte: $(_int_open_reports | paste -sd ' ')):"
  printf '      %s\n' "${findings[@]:0:30}"
  ((${#findings[@]} > 30)) && log_info "… und $((${#findings[@]} - 30)) weitere"
  if confirm "Diese Änderungen sind geprüft und in Ordnung – quittieren?"; then
    write_file "$(_int_ack_file)" 0600 <<<"$(date +%s)"
    result_ok "${#findings[@]} AIDE-Fund(e) quittiert"
  else
    result_warn "AIDE-Funde nicht quittiert"
  fi
}

# --- Actions -------------------------------------------------------------------

integrity::check() {
  _int_check_aide
  _int_check_dpkg
}

integrity::setup() {
  pkg_install aide aide-common
  integrity::configure
}

integrity::configure() {
  if ((!DRY_RUN)) && ! pkg_installed aide; then
    result_fail "AIDE ist nicht installiert – zuerst 'srvctl setup integrity'"
    return 1
  fi
  if ((DRY_RUN)) && ! pkg_installed aide; then
    log_dry "AIDE wird nach der Installation konfiguriert und initialisiert"
    return 0
  fi
  _int_apply_config
  _int_apply_init
  _int_acknowledge
}
