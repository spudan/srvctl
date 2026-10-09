# shellcheck shell=bash
# Confirmation timer against lock-outs. After risky changes (SSH, firewall) a
# module calls revert_timer_arm. At the end of the run a systemd timer starts;
# unless "srvctl confirm" is run from a NEW login session in time, the timer
# runs "srvctl _revert RUN_ID", which restores the module's files of that run
# and calls <module>::after_revert (e.g. to reload a service).
#
# Pending runs: STATE_DIR/pending/<RUN_ID> with lines
#   module=<name>   (one per armed module, in order)
#   unit=<name>     (systemd unit, once the timer is running)
#   session=<id>    (audit session ID of the login that made the change)

readonly _UNSET_SESSION=4294967295

_pending_file() { printf '%s\n' "${STATE_DIR}/pending/$1"; }

_current_session() {
  local id
  id=$(cat /proc/self/sessionid 2>/dev/null) || id=""
  [[ -n $id && $id != "$_UNSET_SESSION" ]] && echo "$id"
  return 0
}

# revert_timer_arm - registers CURRENT_MODULE's changes of this run for the
# confirmation timer. Call it after the risky change has been applied.
revert_timer_arm() {
  local mod=${CURRENT_MODULE:?revert_timer_arm braucht ein Modul} file
  if ((DRY_RUN)); then
    log_dry "Bestätigungs-Timer für $mod ($(_revert_timeout) s)"
    return 0
  fi
  (umask 077 && mkdir -p -- "${STATE_DIR}/pending") || return 1
  file=$(_pending_file "$RUN_ID")
  grep -qxF "module=$mod" "$file" 2>/dev/null || echo "module=$mod" >>"$file"
  log_info "Bestätigungs-Timer vorgemerkt"
}

_revert_timeout() { echo "${SRVCTL_CONFIRM_TIMEOUT:-300}"; }

# revert_finalize - starts the timer for this run, if modules armed it.
# Runs at the end of every run and from the EXIT trap (also on abort).
revert_finalize() {
  [[ -n $STATE_DIR && -n $RUN_ID ]] || return 0
  local file unit timeout deadline mods
  file=$(_pending_file "$RUN_ID")
  [[ -f $file ]] || return 0
  grep -q '^unit=' "$file" && return 0

  unit="srvctl-revert-${RUN_ID}"
  timeout=$(_revert_timeout)
  # The revert must see the same configuration (backup and state paths).
  local -a args=(--yes --no-color --host "$CONFIG_HOST")
  [[ -n $CONFIG_EXTRA ]] && args+=(--config "$(realpath -- "$CONFIG_EXTRA")")
  if ! systemd-run --quiet --unit="$unit" --on-active="${timeout}s" --timer-property=AccuracySec=1s \
    --description="srvctl: Änderungen von Lauf ${RUN_ID} zurücksetzen" \
    "${SRVCTL_ROOT}/srvctl" "${args[@]}" _revert "$RUN_ID"; then
    log_error "Bestätigungs-Timer konnte nicht gestartet werden – Änderungen werden sofort zurückgesetzt"
    revert_run "$RUN_ID"
    return 1
  fi
  printf 'unit=%s\nsession=%s\n' "$unit" "$(_current_session)" >>"$file"
  _log_file REVERT "Timer $unit gestartet (${timeout} s)"

  deadline=$(date -d "+${timeout} seconds" '+%H:%M:%S')
  mods=$(sed -n 's/^module=//p' "$file" | paste -sd ' ')
  {
    printf '\n%s!!! Änderungen an [%s] müssen bestätigt werden !!!%s\n' "${C_BOLD}${C_YELLOW}" "$mods" "$C_RESET"
    printf '    Bitte JETZT in einem NEUEN Terminal neu anmelden und ausführen:\n'
    printf '        sudo srvctl confirm\n'
    printf '    Ohne Bestätigung wird um %s automatisch zurückgesetzt.\n' "$deadline"
    printf '    Diese Sitzung bitte bis dahin offen lassen.\n'
  } >&2
}

# revert_confirm - stops all pending timers. Refuses runs whose change came
# from the current login session, because that proves nothing about a new login.
revert_confirm() {
  local file run unit session current mods found=0
  current=$(_current_session)
  for file in "${STATE_DIR}/pending"/*; do
    [[ -f $file ]] || continue
    found=1
    run=$(basename -- "$file")
    unit=$(sed -n 's/^unit=//p' "$file")
    session=$(sed -n 's/^session=//p' "$file")
    mods=$(sed -n 's/^module=//p' "$file" | paste -sd ' ')
    if [[ -n $current && $session == "$current" ]]; then
      result_fail "Lauf $run ($mods): Bestätigung aus derselben Sitzung wie die Änderung – bitte aus einer NEUEN Anmeldung bestätigen"
      continue
    fi
    if [[ -n $unit ]]; then
      systemctl stop "${unit}.timer" 2>/dev/null || true
    fi
    rm -f -- "$file"
    result_ok "Änderungen von Lauf $run bestätigt ($mods)"
  done
  ((found)) || log_info "Keine ausstehenden Bestätigungen"
}

# revert_run RUN_ID - restores the armed modules of RUN_ID (newest first)
revert_run() {
  local run=$1 file mod
  file=$(_pending_file "$run")
  if [[ ! -f $file ]]; then
    log_info "Lauf $run wurde bereits bestätigt – nichts zurückzusetzen"
    return 0
  fi
  lock_acquire 120
  wall "srvctl: Änderungen von Lauf $run wurden nicht bestätigt und werden zurückgesetzt." 2>/dev/null || true
  _log_file REVERT "Lauf $run wird zurückgesetzt"

  local -a mods
  mapfile -t mods < <(sed -n 's/^module=//p' "$file" | tac)
  for mod in "${mods[@]}"; do
    log_step "${mod}: Zurücksetzen (Lauf $run nicht bestätigt)"
    CURRENT_MODULE=$mod
    backup_restore_run "$mod" "$run"
    CURRENT_MODULE=""
    if module_has_action "$mod" after_revert; then
      module_run "$mod" after_revert
    fi
  done
  rm -f -- "$file"
}

# Prints a hint about unconfirmed runs (used by status).
revert_pending_notice() {
  local file mods
  for file in "${STATE_DIR}/pending"/*; do
    [[ -f $file ]] || continue
    mods=$(sed -n 's/^module=//p' "$file" | paste -sd ' ')
    printf '%s!!! Unbestätigte Änderungen:%s Lauf %s (%s) – sudo srvctl confirm\n' \
      "${C_BOLD}${C_YELLOW}" "$C_RESET" "$(basename -- "$file")" "$mods"
  done
}
