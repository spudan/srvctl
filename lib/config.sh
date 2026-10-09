# shellcheck shell=bash
# Configuration: config/default.conf -> config/hosts/<host>.conf ->
# config/local.conf -> --config FILE (later files override earlier ones).

CONFIG_HOST=""
CONFIG_FILES_LOADED=()

config_load() {
  local host=${HOST_NAME:-$(hostname -s)}
  [[ $host =~ ^[A-Za-z0-9._-]+$ ]] || die "Ungültiger Hostname: $host"
  CONFIG_HOST=$host

  local f
  for f in "${SRVCTL_ROOT}/config/default.conf" \
    "${SRVCTL_ROOT}/config/hosts/${host}.conf" \
    "${SRVCTL_ROOT}/config/local.conf"; do
    [[ -f $f ]] && _config_source "$f"
  done

  if [[ -n $CONFIG_EXTRA ]]; then
    [[ -f $CONFIG_EXTRA ]] || die "Konfigurationsdatei nicht gefunden: $CONFIG_EXTRA"
    _config_source "$CONFIG_EXTRA"
  fi
}

_config_source() {
  local file=$1 owner mode
  read -r owner mode < <(stat -Lc '%u %a' -- "$file")
  if [[ $owner != 0 ]] || _insecure_mode "$mode"; then
    die "Unsichere Konfigurationsdatei $file (muss root gehören, nicht für Gruppe/andere beschreibbar)"
  fi
  # shellcheck source=/dev/null
  source "$file" || die "Fehler beim Laden von $file"
  CONFIG_FILES_LOADED+=("$file")
}

# cfg_get NAME [DEFAULT] - prints the config value or DEFAULT
cfg_get() {
  if [[ -v $1 ]]; then
    printf '%s' "${!1}"
  else
    printf '%s' "${2-}"
  fi
}

# cfg_require NAME... - records FAIL and returns 1 if a value is empty
cfg_require() {
  local name
  local -a missing=()
  for name; do
    [[ -n ${!name:-} ]] || missing+=("$name")
  done
  ((${#missing[@]} == 0)) && return 0
  result_fail "Fehlende Konfiguration: ${missing[*]}"
  return 1
}
