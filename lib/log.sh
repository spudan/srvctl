# shellcheck shell=bash
# Output, colors, log file and result tracking (OK/WARN/FAIL/SKIP).

C_RESET="" C_BOLD="" C_DIM="" C_RED="" C_GREEN="" C_YELLOW="" C_BLUE="" C_CYAN=""
LOG_FILE=""
CURRENT_MODULE=""
CURRENT_ACTION=""

log_init_colors() {
  if [[ $USE_COLOR == auto ]]; then
    if [[ -t 1 && -z ${NO_COLOR:-} && ${TERM:-dumb} != dumb ]]; then
      USE_COLOR=1
    else
      USE_COLOR=0
    fi
  fi
  if [[ $USE_COLOR == 1 ]]; then
    C_RESET=$'\e[0m' C_BOLD=$'\e[1m' C_DIM=$'\e[2m'
    C_RED=$'\e[31m' C_GREEN=$'\e[32m' C_YELLOW=$'\e[33m' C_BLUE=$'\e[34m' C_CYAN=$'\e[36m'
  fi
}

# Opens the log file (SRVCTL_LOG_FILE, default /var/log/srvctl.log).
log_open_file() {
  local file=${SRVCTL_LOG_FILE:-/var/log/srvctl.log}
  if (umask 027 && : >>"$file") 2>/dev/null; then
    LOG_FILE=$file
  else
    log_warn "Logdatei $file ist nicht beschreibbar – es wird nur ins Terminal geschrieben"
  fi
}

# _log_file LEVEL MESSAGE
_log_file() {
  [[ -n $LOG_FILE ]] || return 0
  printf '%(%Y-%m-%d %H:%M:%S)T [%s] %-7s %s%s\n' -1 "${RUN_ID:-}" "$1" \
    "${CURRENT_MODULE:+${CURRENT_MODULE}: }" "$2" >>"$LOG_FILE"
}

log_file_only() { _log_file INFO "$1"; }

log_step() {
  _log_file STEP "$1"
  ((QUIET)) || printf '\n%s==> %s%s\n' "${C_BOLD}${C_BLUE}" "$1" "$C_RESET"
}

log_info() {
  _log_file INFO "$1"
  ((QUIET)) || printf '    %s\n' "$1"
}

log_debug() {
  ((VERBOSE)) || return 0
  _log_file DEBUG "$1"
  printf '    %s%s%s\n' "$C_DIM" "$1" "$C_RESET"
}

log_warn() {
  _log_file WARN "$1"
  printf '%sWARNUNG:%s %s\n' "${C_BOLD}${C_YELLOW}" "$C_RESET" "$1" >&2
}

log_error() {
  _log_file ERROR "$1"
  printf '%sFEHLER:%s %s\n' "${C_BOLD}${C_RED}" "$C_RESET" "$1" >&2
}

log_dry() {
  _log_file DRY "$1"
  ((QUIET)) || printf '    %s[DRY]%s %s\n' "$C_CYAN" "$C_RESET" "$1"
}

# die MESSAGE [EXIT_CODE]
die() {
  log_error "$1"
  exit "${2:-3}"
}

# --- Results -----------------------------------------------------------------
# Every check result is recorded in RESULTS_FILE (status<TAB>module<TAB>message),
# so results from module subshells reach the summary.

_result() {
  local status=$1 color=$2 msg=${3//$'\n'/ }
  local mod=${CURRENT_MODULE:-srvctl}
  printf '%s\t%s\t%s\n' "$status" "$mod" "$msg" >>"$RESULTS_FILE"
  _log_file "$status" "$msg"
  if ((QUIET)) && [[ $status == OK || $status == SKIP ]]; then
    return 0
  fi
  local label
  case $status in
    OK) label=" OK " ;;
    *) label=$status ;;
  esac
  printf '%s[%s]%s %s: %s\n' "$color" "$label" "$C_RESET" "$mod" "$msg"
}

result_ok() { _result OK "$C_GREEN" "$1"; }
result_warn() { _result WARN "$C_YELLOW" "$1"; }
result_fail() { _result FAIL "$C_RED" "$1"; }
result_skip() { _result SKIP "$C_DIM" "$1"; }

# results_count STATUS|"" [MODULE] - number of recorded results
results_count() {
  awk -F'\t' -v s="$1" -v m="${2:-}" \
    '(s == "" || $1 == s) && (m == "" || $2 == m) { n++ } END { print n + 0 }' "$RESULTS_FILE"
}

summary_print() {
  [[ -n ${RESULTS_FILE:-} && -s $RESULTS_FILE ]] || return 0
  local ok warn fail skip
  read -r ok warn fail skip < <(awk -F'\t' '{ c[$1]++ }
    END { printf "%d %d %d %d\n", c["OK"], c["WARN"], c["FAIL"], c["SKIP"] }' "$RESULTS_FILE")
  _log_file SUMMARY "OK=$ok WARN=$warn FAIL=$fail SKIP=$skip"

  if ((QUIET)) && ((warn + fail == 0)); then
    return 0
  fi

  printf '\n%s=== Zusammenfassung ===%s\n' "$C_BOLD" "$C_RESET"
  if ((warn + fail > 0)); then
    local status mod msg
    while IFS=$'\t' read -r status mod msg; do
      case $status in
        WARN) printf '%s[WARN]%s %s: %s\n' "$C_YELLOW" "$C_RESET" "$mod" "$msg" ;;
        FAIL) printf '%s[FAIL]%s %s: %s\n' "$C_RED" "$C_RESET" "$mod" "$msg" ;;
      esac
    done <"$RESULTS_FILE"
    echo
  fi
  printf '%sOK: %d%s  %sWARN: %d%s  %sFAIL: %d%s  SKIP: %d\n' \
    "$C_GREEN" "$ok" "$C_RESET" "$C_YELLOW" "$warn" "$C_RESET" "$C_RED" "$fail" "$C_RESET" "$skip"
  if ((DRY_RUN)); then
    printf '%sProbelauf (--dry-run): Es wurden keine Änderungen vorgenommen.%s\n' "$C_CYAN" "$C_RESET"
  fi
}

# Prints 2 if any FAIL, 1 if any WARN, otherwise 0.
summary_exit_code() {
  if [[ -z ${RESULTS_FILE:-} || ! -s $RESULTS_FILE ]]; then
    echo 0
    return
  fi
  awk -F'\t' '$1 == "FAIL" { f = 1 } $1 == "WARN" { w = 1 }
    END { print (f ? 2 : (w ? 1 : 0)) }' "$RESULTS_FILE"
}
