# shellcheck shell=bash
# Module handling: discovery, dependency resolution and execution.
#
# A module is modules/<name>.sh defining MODULE_NAME (= <name>), MODULE_DESC,
# optional MODULE_DEPENDS=(...) and functions <name>::check, ::setup,
# ::configure, ::rollback (all optional).

readonly MODULE_ACTIONS=(check setup configure rollback)

declare -A MOD_FILE=() MOD_DESC=() MOD_DEPENDS=()
MOD_NAMES=()
RESOLVED=()

modules_load() {
  local file name dep
  for file in "${SRVCTL_ROOT}"/modules/*.sh; do
    name=$(basename -- "$file" .sh)
    if [[ ! $name =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
      log_warn "Ungültiger Modulname, übersprungen: $file"
      continue
    fi
    MODULE_NAME="" MODULE_DESC="" MODULE_DEPENDS=()
    # shellcheck source=/dev/null
    if ! source "$file"; then
      log_warn "Modul $name konnte nicht geladen werden"
      continue
    fi
    if [[ $MODULE_NAME != "$name" ]]; then
      log_warn "Modul $file: MODULE_NAME='$MODULE_NAME' passt nicht zum Dateinamen – übersprungen"
      continue
    fi
    MOD_FILE[$name]=$file
    MOD_DESC[$name]=$MODULE_DESC
    MOD_DEPENDS[$name]="${MODULE_DEPENDS[*]}"
    MOD_NAMES+=("$name")
  done
  unset MODULE_NAME MODULE_DESC MODULE_DEPENDS

  for name in "${MOD_NAMES[@]}"; do
    for dep in ${MOD_DEPENDS[$name]}; do
      [[ -n ${MOD_FILE[$dep]:-} ]] || log_warn "Modul $name: unbekannte Abhängigkeit '$dep'"
    done
  done
}

# module_has_action MODULE ACTION
module_has_action() { declare -F "${1}::${2}" >/dev/null; }

# Prints the modules "all" stands for (MODULES_ENABLED minus MODULES_DISABLED).
modules_enabled() {
  local -a list
  local name
  read -ra list <<<"${MODULES_ENABLED:-}"
  ((${#list[@]})) || list=("${MOD_NAMES[@]}")
  for name in "${list[@]}"; do
    [[ " ${MODULES_DISABLED:-} " == *" $name "* ]] || echo "$name"
  done
}

# modules_expand OUT_ARRAY NAME... - expands "all", validates names, dedups
modules_expand() {
  local -n _me_out=$1
  shift
  local name
  local -A seen=()
  local -a names=()
  for name; do
    if [[ $name == all ]]; then
      mapfile -t -O "${#names[@]}" names < <(modules_enabled)
    else
      names+=("$name")
    fi
  done
  _me_out=()
  for name in "${names[@]}"; do
    [[ -n ${MOD_FILE[$name]:-} ]] || usage_error "Unbekanntes Modul: $name (verfügbar: ${MOD_NAMES[*]:-keine})"
    [[ -n ${seen[$name]:-} ]] && continue
    seen[$name]=1
    _me_out+=("$name")
  done
}

# modules_resolve WITH_DEPS NAME... - topological order into RESOLVED.
# WITH_DEPS=1 adds missing dependencies; otherwise only orders the given ones.
modules_resolve() {
  local with_deps=$1
  shift
  local -A _state=() _wanted=()
  local name
  for name; do _wanted[$name]=1; done
  RESOLVED=()
  for name; do
    _modules_visit "$name" || return 1
  done
}

_modules_visit() {
  local mod=$1 dep
  case ${_state[$mod]:-} in
    done) return 0 ;;
    visiting)
      log_error "Zyklische Abhängigkeit bei Modul $mod"
      return 1
      ;;
  esac
  _state[$mod]=visiting
  for dep in ${MOD_DEPENDS[$mod]}; do
    if [[ -z ${MOD_FILE[$dep]:-} ]]; then
      log_error "Modul $mod benötigt unbekanntes Modul '$dep'"
      return 1
    fi
    if ((with_deps)) || [[ -n ${_wanted[$dep]:-} ]]; then
      _modules_visit "$dep" || return 1
    fi
  done
  _state[$mod]=done
  RESOLVED+=("$mod")
}

# module_run MODULE ACTION - runs one action in a subshell. Non-check actions
# run with errexit, so the first failing command aborts the module.
# Must not be called in a conditional context ("if", "||", "&&", "!"), as bash
# then ignores errexit inside the module.
module_run() {
  local mod=$1 action=$2 rc=0 fails_before results_before
  fails_before=$(results_count FAIL "$mod")
  results_before=$(results_count "" "$mod")

  (
    CURRENT_MODULE=$mod
    CURRENT_ACTION=$action
    if [[ $action != check ]]; then
      set -o errexit -o errtrace
      trap 'log_error "Befehl fehlgeschlagen (Exit-Code $?): $BASH_COMMAND"' ERR
    fi
    if module_has_action "$mod" "$action"; then
      "${mod}::${action}"
    else
      backup_restore_module "$mod" # default rollback
    fi
  )
  rc=$? # not "|| rc=$?": errexit is ignored in that context, also in subshells

  ((rc == 130)) && exit 130
  CURRENT_MODULE=$mod
  if ((rc != 0)) && (($(results_count FAIL "$mod") == fails_before)); then
    result_fail "$action abgebrochen (Exit-Code $rc)"
  elif [[ $action != check ]] && (($(results_count "" "$mod") == results_before)); then
    result_ok "$action abgeschlossen"
  fi
  CURRENT_MODULE=""

  ((rc == 0 && $(results_count FAIL "$mod") == fails_before))
}

# run_action ACTION NAME... - resolves modules and runs ACTION on each
run_action() {
  local action=$1
  shift
  local -a requested=() run=()
  local -A is_requested=() failed=()
  local mod dep i with_deps=0

  modules_expand requested "$@"
  [[ $action == setup || $action == configure ]] && with_deps=1
  modules_resolve "$with_deps" "${requested[@]}" || exit 3
  for mod in "${requested[@]}"; do is_requested[$mod]=1; done

  local -a order=("${RESOLVED[@]}")
  if [[ $action == rollback ]]; then
    order=()
    for ((i = ${#RESOLVED[@]} - 1; i >= 0; i--)); do order+=("${RESOLVED[i]}"); done
  fi

  for mod in "${order[@]}"; do
    if [[ $action == rollback ]] || module_has_action "$mod" "$action"; then
      run+=("$mod")
    elif [[ -n ${is_requested[$mod]:-} ]]; then
      CURRENT_MODULE=$mod result_skip "Aktion '$action' wird nicht unterstützt"
    else
      log_debug "Abhängigkeit $mod hat keine Aktion '$action'"
    fi
  done
  ((${#run[@]})) || return 0

  if [[ $action != check ]]; then
    lock_acquire
    if ((!DRY_RUN && !ASSUME_YES)); then
      log_step "Geplant: $action"
      for mod in "${run[@]}"; do
        if [[ -n ${is_requested[$mod]:-} ]]; then
          log_info "$mod"
        else
          log_info "$mod (Abhängigkeit)"
        fi
      done
      confirm "Fortfahren?" || {
        log_warn "Abgebrochen – keine Bestätigung"
        exit 1
      }
    fi
  fi

  for mod in "${run[@]}"; do
    for dep in ${MOD_DEPENDS[$mod]}; do
      if [[ -n ${failed[$dep]:-} ]]; then
        CURRENT_MODULE=$mod result_skip "Übersprungen – Abhängigkeit $dep ist fehlgeschlagen"
        failed[$mod]=1
        continue 2
      fi
    done
    log_step "${mod}: ${action} – ${MOD_DESC[$mod]}"
    module_run "$mod" "$action"
    (($? == 0)) || failed[$mod]=1
  done

  if [[ $action != check ]] && ((!DRY_RUN)); then
    backup_prune
  fi
}

modules_list() {
  if ((${#MOD_NAMES[@]} == 0)); then
    log_info "Keine Module in ${SRVCTL_ROOT}/modules gefunden"
    return 0
  fi
  local -a enabled
  mapfile -t enabled < <(modules_enabled)
  local name action actions deps note
  printf '%s%-16s %-32s %-16s %s%s\n' "$C_BOLD" "Modul" "Aktionen" "Abhängig von" "Beschreibung" "$C_RESET"
  for name in "${MOD_NAMES[@]}"; do
    actions=""
    for action in "${MODULE_ACTIONS[@]}"; do
      module_has_action "$name" "$action" && actions+="$action "
    done
    deps=${MOD_DEPENDS[$name]:--}
    note=""
    [[ " ${enabled[*]} " == *" $name "* ]] || note=" ${C_DIM}(nicht in 'all')${C_RESET}"
    printf '%-16s %-32s %-16s %s%s\n' "$name" "${actions% }" "$deps" "${MOD_DESC[$name]}" "$note"
  done
}

module_info() {
  local name=$1 action other
  [[ -n ${MOD_FILE[$name]:-} ]] || usage_error "Unbekanntes Modul: $name"
  local -a actions=() dependents=()
  for action in "${MODULE_ACTIONS[@]}"; do
    module_has_action "$name" "$action" && actions+=("$action")
  done
  for other in "${MOD_NAMES[@]}"; do
    [[ " ${MOD_DEPENDS[$other]} " == *" $name "* ]] && dependents+=("$other")
  done
  printf '%sModul:%s          %s\n' "$C_BOLD" "$C_RESET" "$name"
  printf 'Beschreibung:   %s\n' "${MOD_DESC[$name]}"
  printf 'Datei:          %s\n' "${MOD_FILE[$name]}"
  printf 'Aktionen:       %s\n' "${actions[*]:-keine}"
  module_has_action "$name" rollback || printf '                (rollback: Standard – stellt Backups wieder her)\n'
  printf 'Abhängig von:   %s\n' "${MOD_DEPENDS[$name]:--}"
  printf 'Benötigt von:   %s\n' "${dependents[*]:--}"
}
