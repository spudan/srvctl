# shellcheck shell=bash
# audit - independent measurement with Lynis (check only, setup installs it).
# Hardening index with thresholds, Lynis warnings listed individually,
# deliberate decisions of this project as documented exceptions.
# Decisions: docs/PLAN.md, section "11. audit".

MODULE_NAME="audit"
MODULE_DESC="Prüfung mit Lynis: Hardening-Index, Warnungen, dokumentierte Ausnahmen"
MODULE_DEPENDS=()

readonly _AUDIT_PROFILE=/etc/lynis/custom.prf
readonly _AUDIT_REPORT=/var/log/lynis-report.dat
readonly _AUDIT_TIMER_DROPIN=/etc/systemd/system/lynis.timer.d/srvctl.conf
readonly _AUDIT_HEADER="Verwaltet von srvctl (Modul: audit) – manuelle Änderungen werden überschrieben"

# Deliberate decisions (docs/PLAN.md) – "TEST-ID[:DETAIL] Begründung"
readonly _AUDIT_EXCEPTIONS="AUTH-9282 Kein Passwortablauf (NIST SP 800-63B, Modul users)
AUTH-9286 Kein Passwortablauf (NIST SP 800-63B, Modul users)
SSH-7408:PORT SSH auf Port 22 bewusst (Modul ssh)
SSH-7408:ALLOWTCPFORWARDING Tunnel mit -L erlaubt (AllowTcpForwarding local, Modul ssh)
HRDN-7230 Kein Malware-Scanner (rkhunter/chkrootkit bewusst nicht, AIDE + auditd + CrowdSec)
FIRE-4512 Firewall über nftables (Modul firewall); iptables-Kompatibilitätsmodule ohne Regeln sind kein Mangel"

# --- Configuration -------------------------------------------------------------

_audit_min_score() { cfg_get AUDIT_MIN_SCORE 80; }
_audit_fail_score() { cfg_get AUDIT_FAIL_SCORE 70; }
_audit_max_age_days() { cfg_get AUDIT_MAX_AGE_DAYS 7; }

_audit_validate() {
  local ok=0 var entry
  for var in AUDIT_MIN_SCORE AUDIT_FAIL_SCORE AUDIT_MAX_AGE_DAYS; do
    [[ $(cfg_get "$var" 1) =~ ^[0-9]+$ ]] || {
      result_fail "$var: '$(cfg_get "$var")' ist keine Zahl"
      ok=1
    }
  done
  for entry in $(cfg_get AUDIT_EXCEPTIONS ""); do
    [[ $entry =~ ^[A-Z]+-[0-9]+(:[A-Za-z0-9_]+)?$ ]] || {
      result_fail "AUDIT_EXCEPTIONS: '$entry' ist keine Lynis-Test-ID (z. B. BOOT-5122 oder SSH-7408:MAXSESSIONS)"
      ok=1
    }
  done
  return "$ok"
}

# --- Report --------------------------------------------------------------------

# _audit_value KEY - first value of KEY in the report
_audit_value() { sed -n "s/^$1=//p" "$_AUDIT_REPORT" 2>/dev/null | head -n 1; }

# _audit_items warning|suggestion - "ID|Text" per line
_audit_items() {
  sed -n "s/^$1\\[\\]=//p" "$_AUDIT_REPORT" 2>/dev/null | awk -F'|' '{ print $1 "|" $2 }' | sort -u
}

_audit_report_age_days() {
  [[ -f $_AUDIT_REPORT ]] || return 1
  echo $((($(date +%s) - $(stat -c %Y "$_AUDIT_REPORT")) / 86400))
}

# Runs Lynis now (1–2 minutes). Report: /var/log/lynis-report.dat
_audit_run() {
  # A stale PID file of an aborted run makes Lynis quit immediately
  local pidfile pid
  for pidfile in /run/lynis.pid /var/run/lynis.pid; do
    [[ -f $pidfile ]] || continue
    pid=$(<"$pidfile")
    if ! kill -0 "$pid" 2>/dev/null; then rm -f -- "$pidfile"; fi
  done
  log_info "Lynis prüft das System – das dauert 1–2 Minuten"
  if ! nice lynis audit system --cronjob --quiet >/dev/null 2>&1; then
    result_warn "Lynis ist mit einem Fehler beendet worden (Details: /var/log/lynis.log)"
  fi
}

# --- Checks --------------------------------------------------------------------

_audit_check() {
  if ! pkg_installed lynis; then
    result_fail "Lynis ist nicht installiert – 'srvctl setup audit'"
    return 0
  fi
  if [[ ! -f $_AUDIT_PROFILE ]]; then
    result_warn "Ausnahmen-Profil $_AUDIT_PROFILE fehlt – 'srvctl configure audit'"
  fi

  local age
  age=$(_audit_report_age_days) || age=""
  if ((FRESH)) || [[ -z $age ]] || ((age >= $(_audit_max_age_days))); then
    _audit_run
    age=0
  fi
  if [[ ! -f $_AUDIT_REPORT ]]; then
    result_fail "Kein Lynis-Bericht vorhanden ($_AUDIT_REPORT)"
    return 0
  fi

  local score min fail when
  score=$(_audit_value hardening_index)
  min=$(_audit_min_score)
  fail=$(_audit_fail_score)
  when=$(stat -c %Y "$_AUDIT_REPORT")
  printf -v when '%(%Y-%m-%d %H:%M)T' "$when"
  if [[ ! $score =~ ^[0-9]+$ ]]; then
    result_fail "Lynis-Bericht enthält keinen Hardening-Index"
  elif ((score >= min)); then
    result_ok "Lynis Hardening-Index: $score (Ziel ≥ $min, Bericht vom $when)"
  elif ((score >= fail)); then
    result_warn "Lynis Hardening-Index: $score (Ziel ≥ $min, Bericht vom $when)"
  else
    result_fail "Lynis Hardening-Index: $score (unter $fail, Bericht vom $when)"
  fi

  local id text
  while IFS='|' read -r id text; do
    [[ -n $id ]] || continue
    result_warn "Lynis-Warnung $id: $text"
  done < <(_audit_items warning)

  local suggestions
  suggestions=$(_audit_items suggestion | grep -c .)
  if ((suggestions > 0)); then
    log_info "Lynis hat $suggestions Vorschläge – anzeigen: grep '^suggestion' $_AUDIT_REPORT"
  fi
  local skipped
  skipped=$(_audit_exceptions | awk '{ print $1 }' | paste -sd ' ')
  log_info "Bewusste Ausnahmen: $skipped"
}

# --- Apply ---------------------------------------------------------------------

# Built-in exceptions plus AUDIT_EXCEPTIONS: "ID Begründung" per line
_audit_exceptions() {
  echo "$_AUDIT_EXCEPTIONS"
  local entry
  for entry in $(cfg_get AUDIT_EXCEPTIONS ""); do
    echo "$entry Ausnahme aus der Konfiguration (AUDIT_EXCEPTIONS)"
  done
}

_audit_apply() {
  local id reason content="# ${_AUDIT_HEADER}"$'\n'"# Bewusste Entscheidungen dieses Projekts (docs/PLAN.md) – werden von Lynis nicht bewertet"$'\n'
  while read -r id reason; do
    content+=$'\n'"# ${reason}"$'\n'"skip-test=${id}"$'\n'
  done < <(_audit_exceptions)
  write_file "$_AUDIT_PROFILE" 0640 <<<"${content%$'\n'}"
  if ((FILE_CHANGED)) && [[ -f $_AUDIT_REPORT ]]; then
    log_info "Ausnahmen geändert – der nächste 'srvctl check audit' erstellt einen neuen Bericht"
    run_cmd touch -d '30 days ago' "$_AUDIT_REPORT"
  fi

  write_file "$_AUDIT_TIMER_DROPIN" 0644 <<<"# ${_AUDIT_HEADER}
# Wöchentlich statt täglich; srvctl check nutzt den Bericht bis zu $(_audit_max_age_days) Tage
[Timer]
OnCalendar=
OnCalendar=weekly"
  if ((FILE_CHANGED)); then
    run_cmd systemctl daemon-reload
  fi
  svc_enable lynis.timer
}

# --- Actions -------------------------------------------------------------------

audit::check() {
  _audit_validate || return 0
  _audit_check
}

audit::setup() {
  _audit_validate || return 1
  pkg_install lynis
  audit::configure
}

audit::configure() {
  _audit_validate || return 1
  if ((!DRY_RUN)) && ! pkg_installed lynis; then
    result_fail "Lynis ist nicht installiert – zuerst 'srvctl setup audit'"
    return 1
  fi
  _audit_apply
  result_ok "Lynis eingerichtet (wöchentliche Prüfung, $(_audit_exceptions | grep -c .) bewusste Ausnahmen)"
}
