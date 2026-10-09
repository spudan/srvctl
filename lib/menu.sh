# shellcheck shell=bash
# Interactive whiptail menu, used when srvctl is started without arguments.

# _wt ARGS... - runs whiptail and prints the selection to stdout
_wt() {
  whiptail --title "srvctl ${SRVCTL_VERSION} – ${CONFIG_HOST}" "$@" 3>&1 1>&2 2>&3
}

menu_main() {
  if [[ ! -t 0 || ! -t 1 ]]; then
    usage_error "Kein Terminal – bitte eine Aktion angeben"
  fi
  if ! cmd_exists whiptail; then
    log_warn "whiptail ist nicht installiert (apt install whiptail) – Menü nicht verfügbar"
    usage
    return 0
  fi

  local action
  action=$(_wt --menu "Aktion wählen:" 16 64 6 \
    check "System prüfen" \
    setup "Module einrichten" \
    configure "Module konfigurieren" \
    rollback "Letzte Änderungen zurücksetzen" \
    list "Module anzeigen" \
    backups "Backups anzeigen") || return 0

  case $action in
    list) modules_list && return 0 ;;
    backups) backup_list && return 0 ;;
  esac

  local -a items=()
  local name
  for name in "${MOD_NAMES[@]}"; do
    if [[ $action == rollback ]] || module_has_action "$name" "$action"; then
      items+=("$name" "${MOD_DESC[$name]}" OFF)
    fi
  done
  if ((${#items[@]} == 0)); then
    _wt --msgbox "Kein Modul unterstützt die Aktion '$action'." 8 60
    return 0
  fi

  local selection
  selection=$(_wt --separate-output --checklist "Module für '$action' (Leertaste = auswählen):" \
    20 72 12 "${items[@]}") || return 0
  local -a mods
  mapfile -t mods <<<"$selection"
  [[ -n ${mods[0]:-} ]] || return 0

  if [[ $action != check ]]; then
    local mode
    mode=$(_wt --radiolist "Ausführungsmodus:" 12 64 2 \
      dry "Probelauf – nur anzeigen (--dry-run)" ON \
      run "Ausführen" OFF) || return 0
    [[ $mode == dry ]] && DRY_RUN=1
  fi

  clear
  run_action "$action" "${mods[@]}"
}
