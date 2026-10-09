# shellcheck shell=bash
# Interactive input: single values, passwords, multi-line text and choices.
# Prompts read from /dev/tty, so they also work while output is redirected.
# Without a terminal they fail (return 1); with --yes, ask uses its default.
#
# VALIDATOR arguments name a function that gets the value, returns 0 if it is
# valid and otherwise explains the problem via log_warn.

has_tty() { (: </dev/tty) 2>/dev/null; }

_input_no_tty() {
  log_error "Eingabe erforderlich, aber kein Terminal vorhanden: $1"
  return 1
}

# ask VAR PROMPT [DEFAULT] [VALIDATOR] - reads one line into VAR
ask() {
  local _ask_var=$1 _ask_prompt=$2 _ask_default=${3-} _ask_validator=${4-} _ask_value
  if ((ASSUME_YES)) && [[ -n $_ask_default ]]; then
    printf -v "$_ask_var" '%s' "$_ask_default"
    _log_file INPUT "${_ask_prompt}: ${_ask_default} (Standard, --yes)"
    return 0
  fi
  has_tty || _input_no_tty "$_ask_prompt" || return 1

  while :; do
    read -r -p "${C_BOLD}?${C_RESET} ${_ask_prompt}${_ask_default:+ [${_ask_default}]}: " _ask_value </dev/tty || return 1
    _ask_value=${_ask_value:-$_ask_default}
    if [[ -z $_ask_value ]]; then
      log_warn "Eingabe darf nicht leer sein"
    elif [[ -z $_ask_validator ]] || "$_ask_validator" "$_ask_value"; then
      break
    fi
  done
  printf -v "$_ask_var" '%s' "$_ask_value"
  _log_file INPUT "${_ask_prompt}: ${_ask_value}"
}

# ask_password VAR PROMPT [VALIDATOR] - hidden input, entered twice
ask_password() {
  local _ap_var=$1 _ap_prompt=$2 _ap_validator=${3-} _ap_first _ap_second
  has_tty || _input_no_tty "$_ap_prompt" || return 1

  while :; do
    read -r -s -p "${C_BOLD}?${C_RESET} ${_ap_prompt}: " _ap_first </dev/tty || return 1
    echo >/dev/tty
    if [[ -z $_ap_first ]]; then
      log_warn "Passwort darf nicht leer sein"
      continue
    fi
    if [[ -n $_ap_validator ]] && ! "$_ap_validator" "$_ap_first"; then
      continue
    fi
    read -r -s -p "${C_BOLD}?${C_RESET} Wiederholen: " _ap_second </dev/tty || return 1
    echo >/dev/tty
    [[ $_ap_first == "$_ap_second" ]] && break
    log_warn "Eingaben stimmen nicht überein"
  done
  printf -v "$_ap_var" '%s' "$_ap_first"
  _log_file INPUT "${_ap_prompt}: (verdeckt)"
}

# ask_lines VAR PROMPT [VALIDATOR] - reads lines until an empty line. Invalid
# lines are rejected individually. VAR gets the valid lines, newline-separated.
ask_lines() {
  local _al_var=$1 _al_prompt=$2 _al_validator=${3-} _al_line _al_result="" _al_count=0
  has_tty || _input_no_tty "$_al_prompt" || return 1

  printf '%s?%s %s (leere Zeile = fertig):\n' "$C_BOLD" "$C_RESET" "$_al_prompt" >/dev/tty
  while read -r _al_line </dev/tty; do
    [[ -z $_al_line ]] && break
    if [[ -n $_al_validator ]] && ! "$_al_validator" "$_al_line"; then
      continue
    fi
    _al_result+="${_al_line}"$'\n'
    ((++_al_count))
  done
  printf -v "$_al_var" '%s' "${_al_result%$'\n'}"
  _log_file INPUT "${_al_prompt}: ${_al_count} Zeile(n)"
}

# ask_choice VAR PROMPT KEY DESC [KEY DESC ...] - numbered selection, VAR = KEY
ask_choice() {
  local _ac_var=$1 _ac_prompt=$2
  shift 2
  local -a _ac_keys=() _ac_descs=()
  while (($# >= 2)); do
    _ac_keys+=("$1")
    _ac_descs+=("$2")
    shift 2
  done
  has_tty || _input_no_tty "$_ac_prompt" || return 1

  local _ac_i _ac_answer
  printf '%s?%s %s\n' "$C_BOLD" "$C_RESET" "$_ac_prompt" >/dev/tty
  for _ac_i in "${!_ac_keys[@]}"; do
    printf '    %d) %s\n' $((_ac_i + 1)) "${_ac_descs[_ac_i]}" >/dev/tty
  done
  while :; do
    read -r -p "    Auswahl [1-${#_ac_keys[@]}]: " _ac_answer </dev/tty || return 1
    if [[ $_ac_answer =~ ^[0-9]+$ ]] && ((_ac_answer >= 1 && _ac_answer <= ${#_ac_keys[@]})); then
      break
    fi
    log_warn "Bitte eine Zahl zwischen 1 und ${#_ac_keys[@]} eingeben"
  done
  printf -v "$_ac_var" '%s' "${_ac_keys[_ac_answer - 1]}"
  _log_file INPUT "${_ac_prompt}: ${_ac_keys[_ac_answer - 1]}"
}
