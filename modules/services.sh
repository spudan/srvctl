# shellcheck shell=bash
# services - listening services, unwanted services, cron/at access and a
# local-only mail server. Decisions: docs/PLAN.md, section "7. services".

MODULE_NAME="services"
MODULE_DESC="Dienste: lauschende Dienste prüfen, unnötige abschalten, cron/at, Mailserver nur lokal"
MODULE_DEPENDS=()

readonly _SVC_HEADER="Verwaltet von srvctl (Modul: services)"
readonly _SVC_CRON_DIRS="/etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly"

# --- Configuration -------------------------------------------------------------

_svc_unwanted() {
  cfg_get SERVICES_DISABLE "avahi-daemon cups cups-browsed rpcbind nfs-server smbd nmbd snmpd bluetooth ModemManager"
}

# Process names allowed to listen publicly: own list + MODULE_LISTEN of all modules
_svc_allowed() {
  local mod
  echo "$(cfg_get SERVICES_ALLOWED "")"
  for mod in "${MOD_NAMES[@]}"; do
    echo "${MOD_LISTEN[$mod]}"
  done
}

_svc_validate() {
  local ok=0 name
  for name in $(_svc_unwanted) $(cfg_get SERVICES_ALLOWED ""); do
    if [[ ! $name =~ ^[A-Za-z0-9@._-]+$ ]]; then
      result_fail "SERVICES_DISABLE/SERVICES_ALLOWED: '$name' ist kein Dienst-/Prozessname"
      ok=1
    fi
  done
  for name in ssh sshd nftables crowdsec chrony systemd-journald; do
    if [[ " $(_svc_unwanted) " == *" $name "* ]]; then
      result_fail "SERVICES_DISABLE: '$name' wird von srvctl gebraucht"
      ok=1
    fi
  done
  return "$ok"
}

# Units (service/socket) of NAME that exist, e.g. "cups.service cups.socket"
_svc_units() {
  local unit
  for unit in "$1.service" "$1.socket" "$1.path"; do
    systemctl list-unit-files --no-legend "$unit" 2>/dev/null | grep -q . && echo "$unit"
  done
  return 0
}

# _svc_running NAME - true if any unit of NAME is enabled or active
_svc_running() {
  local unit state
  for unit in $(_svc_units "$1"); do
    state=$(systemctl is-enabled "$unit" 2>/dev/null)
    [[ $state == masked ]] && continue
    if [[ $state == enabled ]] || systemctl is-active --quiet "$unit"; then
      return 0
    fi
  done
  return 1
}

# --- Listening services --------------------------------------------------------

_svc_check_listeners() {
  local allowed proto port proc pid addr pkg count=0
  local -A seen=()
  allowed=" $(_svc_allowed | tr '\n' ' ') "
  while read -r proto port proc pid addr; do
    [[ -n ${seen[$proc/$proto/$port]:-} ]] && continue
    seen[$proc/$proto/$port]=1
    if [[ $allowed == *" $proc "* ]]; then
      ((++count))
      continue
    fi
    pkg=$(pkg_of_pid "$pid")
    result_warn "Unbekannter Dienst lauscht öffentlich: $proc auf $proto/$port (Paket: $pkg) – abschalten oder in SERVICES_ALLOWED eintragen"
  done < <(net_listeners)
  result_ok "Erlaubte öffentlich lauschende Dienste: $(net_listeners | awk -v a="$allowed" 'index(a, " " $3 " ") { print $3 }' | sort -u | paste -sd ' ' | sed 's/^$/keine/')"
}

# --- Unwanted services ---------------------------------------------------------

_svc_check_unwanted() {
  local name active=()
  for name in $(_svc_unwanted); do
    if _svc_running "$name"; then active+=("$name"); fi
  done
  if ((${#active[@]})); then
    result_warn "Unnötige Dienste aktiv: ${active[*]} – 'srvctl configure services'"
  else
    result_ok "Keine unnötigen Dienste aktiv"
  fi
}

_svc_apply_unwanted() {
  local name unit
  local -a active=() masked=()
  for name in $(_svc_unwanted); do
    if _svc_running "$name"; then active+=("$name"); fi
  done
  ((${#active[@]})) || return 0
  if ! confirm "Diese Dienste stoppen, deaktivieren und sperren (mask): ${active[*]}?"; then
    result_warn "Übersprungen: ${active[*]}"
    return 0
  fi
  for name in "${active[@]}"; do
    for unit in $(_svc_units "$name"); do
      run_cmd systemctl disable --now "$unit" || true
      run_cmd systemctl mask "$unit"
      masked+=("$unit")
    done
  done
  # Remember for rollback (unmask); keeps earlier entries
  local state content=""
  state=$(state_path services masked)
  [[ -r $state ]] && content=$(<"$state")$'\n'
  content+=$(printf '%s\n' "${masked[@]}")
  write_file "$state" 0600 <<<"$(grep . <<<"$content" | sort -u)"
  result_ok "Abgeschaltet und gesperrt: ${active[*]}"
}

# --- cron and at ---------------------------------------------------------------

_svc_cron_installed() { [[ -f /etc/crontab ]] || pkg_installed cron || pkg_installed cronie; }
_svc_at_installed() { pkg_installed at; }

# _svc_check_allow NAME FILE DENY - cron/at restricted to root?
_svc_check_allow() {
  local name=$1 allow=$2 deny=$3
  if [[ -f $allow && $(grep -v '^#' "$allow" | grep . | paste -sd ' ') == root ]] && [[ ! -e $deny ]]; then
    result_ok "$name nur für root ($allow)"
  else
    result_warn "$name ist nicht auf root beschränkt ($allow fehlt oder $deny vorhanden)"
  fi
}

_svc_check_cron() {
  if _svc_cron_installed; then
    _svc_check_allow cron /etc/cron.allow /etc/cron.deny
    local bad=() path mode
    if [[ -f /etc/crontab ]]; then
      mode=$(stat -c '%U %a' /etc/crontab)
      [[ $mode == "root 600" ]] || bad+=("/etc/crontab ($mode)")
    fi
    for path in $_SVC_CRON_DIRS; do
      [[ -d $path ]] || continue
      mode=$(stat -c '%U %a' "$path")
      [[ $mode == "root 700" ]] || bad+=("$path ($mode)")
    done
    if ((${#bad[@]})); then
      result_warn "cron-Dateien zu offen: ${bad[*]}"
    else
      result_ok "cron-Dateien nur für root lesbar"
    fi
  else
    result_ok "cron ist nicht installiert"
  fi
  if _svc_at_installed; then
    _svc_check_allow at /etc/at.allow /etc/at.deny
  fi
}

# _svc_apply_allow ALLOW DENY
_svc_apply_allow() {
  write_file "$1" 0600 root:root <<<"root"
  if [[ -e $2 ]]; then
    backup_file "$2"
    run_cmd rm -f -- "$2"
  fi
}

_svc_apply_cron() {
  if _svc_cron_installed; then
    _svc_apply_allow /etc/cron.allow /etc/cron.deny
    local path changed=0
    if [[ -f /etc/crontab && $(stat -c '%U %a' /etc/crontab) != "root 600" ]]; then
      backup_file /etc/crontab
      run_cmd chown root:root /etc/crontab
      run_cmd chmod 600 /etc/crontab
      changed=1
    fi
    for path in $_SVC_CRON_DIRS; do
      [[ -d $path ]] || continue
      if [[ $(stat -c '%U %a' "$path") != "root 700" ]]; then
        run_cmd chown root:root "$path"
        run_cmd chmod 700 "$path"
        changed=1
      fi
    done
    if ((changed)); then result_ok "cron-Dateien auf root beschränkt"; fi
  fi
  if _svc_at_installed; then
    _svc_apply_allow /etc/at.allow /etc/at.deny
  fi
}

# --- Mail server ---------------------------------------------------------------

_svc_mta() {
  if pkg_installed postfix; then
    echo postfix
  elif pkg_installed exim4-base; then
    echo exim4
  fi
}

_svc_check_mta() {
  local mta public
  mta=$(_svc_mta)
  public=$(net_listeners | awk '$1 == "tcp" && $2 == 25 { print $3 }' | sort -u | paste -sd ' ')
  if [[ -n $public ]]; then
    result_warn "Mailserver lauscht öffentlich auf Port 25 ($public) – 'srvctl configure services' beschränkt ihn auf localhost"
  elif [[ -n $mta ]]; then
    result_ok "Mailserver ($mta) lauscht nur lokal"
  else
    result_ok "Kein Mailserver installiert"
  fi
}

_svc_apply_mta() {
  case $(_svc_mta) in
    postfix)
      if [[ $(postconf -h inet_interfaces 2>/dev/null) != loopback-only ]]; then
        backup_file /etc/postfix/main.cf
        run_cmd postconf -e inet_interfaces=loopback-only
        svc_restart postfix
        result_ok "Postfix lauscht nur noch auf localhost"
      fi
      ;;
    exim4)
      local conf=/etc/exim4/update-exim4.conf.conf
      conf_set "$conf" dc_local_interfaces "'127.0.0.1 ; ::1'" "="
      if ((FILE_CHANGED)); then
        run_cmd update-exim4.conf
        svc_restart exim4
        result_ok "Exim lauscht nur noch auf localhost"
      fi
      ;;
  esac
}

# --- Actions -------------------------------------------------------------------

services::check() {
  _svc_validate || return 0
  _svc_check_listeners
  _svc_check_unwanted
  _svc_check_cron
  _svc_check_mta
}

services::setup() {
  services::configure
}

services::configure() {
  _svc_validate || return 1
  _svc_apply_unwanted
  _svc_apply_cron
  _svc_apply_mta
}

# Restores files (cron.allow, mail config, ...) and unmasks the services
# srvctl masked. They are not started again automatically.
services::rollback() {
  local state unit
  state=$(state_path services masked)
  local -a masked=()
  if [[ -r $state ]]; then mapfile -t masked <"$state"; fi
  backup_restore_module services
  for unit in "${masked[@]}"; do
    [[ -n $unit ]] || continue
    run_cmd systemctl unmask "$unit"
  done
  if ((${#masked[@]})); then
    log_info "Entsperrt (nicht gestartet): ${masked[*]}"
  fi
}
