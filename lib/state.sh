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

# state_record_action MODULE ACTION - remembers the last applied action
state_record_action() {
  ((DRY_RUN)) && return 0
  local file
  file=$(state_path "$1" .last-action) || return 1
  printf '%(%Y-%m-%d %H:%M)T\t%s\t%s\n' -1 "$2" "$RUN_ID" >"$file"
}

# state_last_action MODULE - prints "DATE<TAB>ACTION<TAB>RUN_ID" or nothing
state_last_action() {
  local file="${STATE_DIR}/$1/.last-action"
  [[ -r $file ]] && cat -- "$file"
  return 0
}
