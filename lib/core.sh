# shellcheck shell=bash
# Core: root check, run context, OS detection, locking and self-check.

RUN_ID=""
RUN_DIR=""
RESULTS_FILE=""
OS_ID="" OS_LIKE="" OS_VERSION="" OS_CODENAME="" OS_NAME=""
LOCK_FD=""

# require_root ARGS... - re-executes via sudo if not root.
require_root() {
  ((EUID == 0)) && return 0
  if command -v sudo >/dev/null 2>&1; then
    log_info "Root-Rechte erforderlich – starte neu mit sudo ..."
    exec sudo -- "${SRVCTL_ROOT}/srvctl" "$@"
  fi
  die "srvctl muss als root ausgeführt werden."
}

core_init() {
  RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
  RUN_DIR=$(mktemp -d "${TMPDIR:-/tmp}/srvctl.XXXXXXXX") || die "Temporäres Verzeichnis konnte nicht angelegt werden"
  RESULTS_FILE="${RUN_DIR}/results"
  : >"$RESULTS_FILE"
  trap core_cleanup EXIT
  trap core_interrupted INT TERM
}

core_cleanup() {
  if [[ -n $RUN_DIR && -d $RUN_DIR ]]; then
    rm -rf -- "$RUN_DIR"
  fi
}

core_interrupted() {
  echo >&2
  log_error "Abgebrochen"
  exit 130
}

os_detect() {
  [[ -r /etc/os-release ]] || die "/etc/os-release nicht gefunden – unbekanntes System"
  local -a info
  mapfile -t info < <(
    # shellcheck source=/dev/null
    . /etc/os-release
    printf '%s\n' "${ID:-}" "${ID_LIKE:-}" "${VERSION_ID:-}" "${VERSION_CODENAME:-}" "${PRETTY_NAME:-}"
  )
  OS_ID=${info[0]:-} OS_LIKE=${info[1]:-} OS_VERSION=${info[2]:-}
  OS_CODENAME=${info[3]:-} OS_NAME=${info[4]:-unbekannt}

  case $OS_ID in
    debian | ubuntu) ;;
    *)
      if [[ " $OS_LIKE " == *" debian "* || " $OS_LIKE " == *" ubuntu "* ]]; then
        log_warn "$OS_NAME wird nicht offiziell unterstützt (Debian-Derivat) – fahre fort"
      else
        die "Nicht unterstütztes System: $OS_NAME (unterstützt: Debian, Ubuntu)"
      fi
      ;;
  esac
  readonly OS_ID OS_LIKE OS_VERSION OS_CODENAME OS_NAME
}

# os_is ID - e.g. os_is ubuntu
os_is() { [[ $OS_ID == "$1" ]]; }

# os_version_ge VERSION - e.g. os_version_ge 12
os_version_ge() { dpkg --compare-versions "${OS_VERSION:-0}" ge "$1"; }

# Prevents concurrent modifying runs.
lock_acquire() {
  [[ -n $LOCK_FD ]] && return 0
  local lock=/run/lock/srvctl.lock
  exec {LOCK_FD}>"$lock" || die "Lock-Datei $lock konnte nicht geöffnet werden"
  flock -n "$LOCK_FD" || die "Eine andere srvctl-Instanz läuft bereits (Lock: $lock)"
}

# _insecure_mode OCTAL - true if group/other writable
_insecure_mode() { (((8#$1 & 8#022) != 0)); }

# Root executes everything below SRVCTL_ROOT, so nothing in it may be
# writable by other users.
security_check_tree() {
  local -a bad=()
  local f
  while IFS= read -r -d '' f; do
    bad+=("$f")
  done < <(find "$SRVCTL_ROOT" -path "${SRVCTL_ROOT}/.git" -prune -o \
    ! -type l \( ! -user root -o -perm /022 \) -print0)

  if ((${#bad[@]})); then
    log_error "Unsichere Dateirechte in ${SRVCTL_ROOT} (müssen root gehören, nicht für Gruppe/andere beschreibbar):"
    printf '    %s\n' "${bad[@]:0:10}" >&2
    ((${#bad[@]} > 10)) && printf '    ... und %d weitere\n' $((${#bad[@]} - 10)) >&2
    die "Abhilfe: chown -R root:root ${SRVCTL_ROOT} && chmod -R go-w ${SRVCTL_ROOT}"
  fi

  [[ ${SRVCTL_IGNORE_PATH_WARNING:-0} == 1 ]] && return 0
  local dir owner mode
  dir=$(dirname -- "$SRVCTL_ROOT")
  while :; do
    read -r owner mode < <(stat -c '%u %a' -- "$dir")
    if [[ $owner != 0 ]] || _insecure_mode "$mode"; then
      log_warn "Übergeordnetes Verzeichnis $dir ist nicht nur für root beschreibbar – ein anderer Benutzer könnte srvctl austauschen. Empfehlung: srvctl nach /opt/srvctl verschieben."
      break
    fi
    [[ $dir == / ]] && break
    dir=$(dirname -- "$dir")
  done
}
