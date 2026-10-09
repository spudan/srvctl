# shellcheck shell=bash
# Local module state in STATE_DIR (default /var/lib/srvctl, root only).
# Holds what the system itself cannot tell (e.g. known key fingerprints),
# the last applied action per module and pending confirmations.

STATE_DIR=""

state_init() {
  STATE_DIR=${SRVCTL_STATE_DIR:-/var/lib/srvctl}
}

# state_path MODULE [NAME] - prints the path of a module's state file.
# Creates the module directory (0700) unless in dry-run mode. Write state
# files with write_file, so they are backed up and respect --dry-run.
state_path() {
  local dir="${STATE_DIR}/$1"
  if [[ ! -d $dir ]] && ((!DRY_RUN)); then
    (umask 077 && mkdir -p -- "$dir") || return 1
  fi
  printf '%s\n' "${dir}${2:+/$2}"
}

# state_record_action MODULE ACTION - remembers the last applied action.
# A new setup/configure/rollback clears a previous "reverted by timer" mark.
state_record_action() {
  ((DRY_RUN)) && return 0
  local file
  file=$(state_path "$1" .last-action) || return 1
  printf '%(%Y-%m-%d %H:%M)T\t%s\t%s\n' -1 "$2" "$RUN_ID" >"$file"
  case $2 in
    setup | configure | rollback) rm -f -- "${STATE_DIR}/$1/.reverted" ;;
  esac
}

# state_mark_reverted MODULE RUN_ID - the confirmation timer reverted RUN_ID
state_mark_reverted() {
  local file
  file=$(state_path "$1" .reverted) || return 1
  printf '%(%Y-%m-%d %H:%M)T\t%s\n' -1 "$2" >"$file"
  state_record_action "$1" "zurückgesetzt (Timer)"
}

# state_reverted MODULE - prints "DATE<TAB>RUN_ID" if the last change was reverted
state_reverted() {
  local file="${STATE_DIR}/$1/.reverted"
  [[ -r $file ]] && cat -- "$file"
  return 0
}

# state_reverted_notice MODULE - WARN result if the last change was reverted
state_reverted_notice() {
  local info when run
  info=$(state_reverted "$1")
  [[ -n $info ]] || return 0
  IFS=$'\t' read -r when run <<<"$info"
  CURRENT_MODULE=$1 result_warn "Letzte Änderung (Lauf $run) wurde nicht bestätigt und am $when automatisch zurückgesetzt – erneut anwenden und danach 'srvctl confirm'"
}

# state_last_action MODULE - prints "DATE<TAB>ACTION<TAB>RUN_ID" or nothing
state_last_action() {
  local file="${STATE_DIR}/$1/.last-action"
  [[ -r $file ]] && cat -- "$file"
  return 0
}
