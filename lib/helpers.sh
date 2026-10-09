# shellcheck shell=bash
# Helpers for modules: packages, services, config files, templates and
# ready-made checks. All modifying helpers respect --dry-run.

cmd_exists() { command -v "$1" >/dev/null 2>&1; }

# --- Packages ----------------------------------------------------------------

pkg_installed() {
  dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q 'install ok installed'
}

# Runs "apt-get update" at most once per srvctl run.
pkg_update_once() {
  local marker="${RUN_DIR}/apt-updated"
  [[ -e $marker ]] && return 0
  run_cmd env DEBIAN_FRONTEND=noninteractive apt-get update -q || return 1
  : >"$marker"
}

# pkg_install PKG... - installs missing packages only
pkg_install() {
  local pkg
  local -a missing=()
  for pkg; do
    pkg_installed "$pkg" || missing+=("$pkg")
  done
  ((${#missing[@]})) || return 0
  pkg_update_once || return 1
  log_info "Installiere: ${missing[*]}"
  run_cmd env DEBIAN_FRONTEND=noninteractive apt-get install -y -q "${missing[@]}"
}

# pkg_remove PKG... - removes installed packages only
pkg_remove() {
  local pkg
  local -a present=()
  for pkg; do
    pkg_installed "$pkg" && present+=("$pkg")
  done
  ((${#present[@]})) || return 0
  log_info "Entferne: ${present[*]}"
  run_cmd env DEBIAN_FRONTEND=noninteractive apt-get remove -y -q "${present[@]}"
}

# pkg_purge PKG... - removes installed packages including their configuration
pkg_purge() {
  local pkg
  local -a present=()
  for pkg; do
    if pkg_installed "$pkg" || dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q 'config-files'; then
      present+=("$pkg")
    fi
  done
  ((${#present[@]})) || return 0
  log_info "Entferne vollständig: ${present[*]}"
  run_cmd env DEBIAN_FRONTEND=noninteractive apt-get purge -y -q "${present[@]}"
}

# Packages that were removed but left configuration files behind ("rc")
pkg_residual() { dpkg-query -W -f='${db:Status-Abbrev} ${Package}\n' 2>/dev/null | awk '$1 == "rc" { print $2 }'; }

# --- Services ----------------------------------------------------------------

svc_exists() { systemctl cat "$1" >/dev/null 2>&1; }
svc_is_active() { systemctl is-active --quiet "$1"; }
svc_is_enabled() { systemctl is-enabled --quiet "$1" 2>/dev/null; }

# svc_enable SERVICE - enables and starts the service if necessary
svc_enable() {
  svc_is_enabled "$1" && svc_is_active "$1" && return 0
  run_cmd systemctl enable --now "$1"
}

svc_disable() {
  svc_is_enabled "$1" || svc_is_active "$1" || return 0
  run_cmd systemctl disable --now "$1"
}

svc_restart() { run_cmd systemctl restart "$1"; }
svc_reload() { run_cmd systemctl reload-or-restart "$1"; }

# --- Config files ------------------------------------------------------------
# Lines are "KEY VALUE" (SEP=" ", e.g. sshd_config) or "KEY<SEP>VALUE"
# (e.g. SEP="=" or " = "). Blanks around SEP are ignored when matching; new
# lines are written with SEP as given. Keys are matched case-sensitively.

# shellcheck disable=SC2016
_CONF_AWK_LIB='
function conf_match(s,    l, rest) {
  l = s; sub(/^[ \t]+/, "", l)
  if (substr(l, 1, length(K)) != K) return 0
  rest = substr(l, length(K) + 1)
  if (T == "") return (rest ~ /^[ \t]/)
  sub(/^[ \t]+/, "", rest)
  return (substr(rest, 1, length(T)) == T)
}
function conf_value(s,    l) {
  l = s; sub(/^[ \t]+/, "", l); l = substr(l, length(K) + 1)
  if (T != "") { sub(/^[ \t]+/, "", l); l = substr(l, length(T) + 1) }
  sub(/^[ \t]+/, "", l); sub(/[ \t]+$/, "", l)
  return l
}
# S: separator as written (e.g. "=", " = ", " "); T: S without blanks for matching
BEGIN { K = ENVIRON["_CK"]; V = ENVIRON["_CV"]; S = ENVIRON["_CS"]; T = S; gsub(/[ \t]/, "", T) }
'

# conf_get FILE KEY [SEP] - prints the value of the first active KEY line
conf_get() {
  local file=$1 key=$2 sep=${3:- }
  [[ -r $file ]] || return 1
  _CK=$key _CS=$sep awk "$_CONF_AWK_LIB"'
    conf_match($0) { print conf_value($0); found = 1; exit }
    END { exit !found }' "$file"
}

# conf_set FILE KEY VALUE [SEP] - sets KEY idempotently. Replaces all active
# KEY lines; otherwise uncomments "#KEY ..." or appends the line.
conf_set() {
  local file=$1 key=$2 value=$3 sep=${4:- } src=$1 content
  [[ -f $file ]] || src=/dev/null
  content=$(_CK=$key _CV=$value _CS=$sep awk "$_CONF_AWK_LIB"'
    { line[NR] = $0 }
    END {
      out = K S V
      for (i = 1; i <= NR; i++) if (conf_match(line[i])) { line[i] = out; done = 1 }
      if (!done) for (i = 1; i <= NR; i++) {
        c = line[i]
        if (c !~ /^[ \t]*#/) continue
        sub(/^[ \t]*#/, "", c)
        if (conf_match(c)) { line[i] = out; done = 1; break }
      }
      for (i = 1; i <= NR; i++) print line[i]
      if (!done) print out
    }' "$src") || return 1
  write_file "$file" <<<"$content"
}

# ensure_line FILE LINE - appends LINE unless it already exists exactly
ensure_line() {
  local file=$1 line=$2 content=""
  if [[ -f $file ]] && grep -qxF -- "$line" "$file"; then
    FILE_CHANGED=0
    return 0
  fi
  [[ -f $file ]] && content=$(<"$file")
  [[ -n $content ]] && content+=$'\n'
  write_file "$file" <<<"${content}${line}"
}

# file_sed FILE SED_EXPR... - edits FILE with "sed -E" expressions via
# write_file (backup, dry-run, FILE_CHANGED). Missing files count as empty.
file_sed() {
  local file=$1 content
  shift
  local -a args=()
  local expr
  for expr; do args+=(-e "$expr"); done
  if [[ -f $file ]]; then
    content=$(sed -E "${args[@]}" -- "$file") || return 1
  else
    content=$(sed -E "${args[@]}" </dev/null) || return 1
  fi
  write_file "$file" <<<"$content"
}

# template_render FILE - prints FILE with {{NAME}} replaced by variable NAME.
# Fails if a referenced variable is not set.
template_render() {
  local tpl=$1 content name
  [[ -r $tpl ]] || {
    log_error "Template nicht gefunden: $tpl"
    return 1
  }
  content=$(<"$tpl")
  while [[ $content =~ \{\{([A-Za-z_][A-Za-z0-9_]*)\}\} ]]; do
    name=${BASH_REMATCH[1]}
    [[ -v $name ]] || {
      log_error "Template $tpl: Variable $name ist nicht gesetzt"
      return 1
    }
    content=${content//"{{${name}}}"/${!name}}
  done
  printf '%s\n' "$content"
}

# --- Ready-made checks -------------------------------------------------------

check_pkg() {
  if pkg_installed "$1"; then
    result_ok "Paket $1 ist installiert"
  else
    result_fail "Paket $1 ist nicht installiert"
  fi
}

check_service() {
  if ! svc_exists "$1"; then
    result_fail "Dienst $1 existiert nicht"
  elif svc_is_active "$1" && svc_is_enabled "$1"; then
    result_ok "Dienst $1 läuft und ist aktiviert"
  elif svc_is_active "$1"; then
    result_warn "Dienst $1 läuft, startet aber nicht automatisch"
  else
    result_fail "Dienst $1 läuft nicht"
  fi
}

# check_conf FILE KEY EXPECTED [SEP]
check_conf() {
  local file=$1 key=$2 expected=$3 sep=${4:- } actual
  if [[ ! -r $file ]]; then
    result_fail "$file fehlt"
  elif ! actual=$(conf_get "$file" "$key" "$sep"); then
    result_fail "$file: $key nicht gesetzt (erwartet: $expected)"
  elif [[ $actual == "$expected" ]]; then
    result_ok "$file: $key = $actual"
  else
    result_fail "$file: $key = $actual (erwartet: $expected)"
  fi
}

# --- Network -----------------------------------------------------------------

# net_listeners - sockets listening on non-loopback addresses, one per line:
# "PROTO PORT PROCESS PID ADDRESS" (DHCP clients are left out)
net_listeners() {
  ss -Htulnp 2>/dev/null | awk '{
    proto = $1; local = $5
    port = local; sub(/.*:/, "", port)
    addr = local; sub(/:[^:]*$/, "", addr)
    if (addr ~ /^(127\.|\[::1\]|::1)/ || addr ~ /%lo$/) next
    if ($0 ~ /"(dhclient|dhcpcd|systemd-network)"/) next # DHCP clients, no services
    proc = "?"; pid = "?"
    if (match($0, /users:\(\("[^"]+"/)) proc = substr($0, RSTART + 9, RLENGTH - 10)
    if (match($0, /pid=[0-9]+/)) pid = substr($0, RSTART + 4, RLENGTH - 4)
    print proto, port, proc, pid, addr
  }' | sort -u
}

# pkg_of_pid PID - Debian package owning the executable of PID (or "?")
pkg_of_pid() {
  local exe pkg
  exe=$(readlink -f "/proc/$1/exe" 2>/dev/null) || {
    echo "?"
    return 0
  }
  pkg=$(dpkg -S "$exe" 2>/dev/null || dpkg -S "${exe#/usr}" 2>/dev/null) || pkg=""
  echo "${pkg%%:*}" | grep . || echo "?"
}

# --- Firewall rules from other modules ---------------------------------------

FIREWALL_RULES_FILE=/etc/srvctl/nftables/srvctl.nft
firewall_dir() { echo "${SRVCTL_FIREWALL_DIR:-/etc/srvctl/firewall.d}"; }

# firewall_rules MODULE <RULES - sets the nftables rules MODULE contributes to
# the input chain of "table inet srvctl" (e.g. 'tcp dport { 80, 443 } accept').
# Empty input removes them. If the firewall is active it is reloaded; invalid
# rules are rejected and the previous file is restored.
firewall_rules() {
  local mod=$1 file content
  file="$(firewall_dir)/${mod}.nft"
  content=$(cat)
  FILE_CHANGED=0
  if [[ -z ${content//[[:space:]]/} ]]; then
    [[ -e $file ]] || return 0
    backup_file "$file" || return 1
    run_cmd rm -f -- "$file" || return 1
    FILE_CHANGED=1
  else
    write_file "$file" 0600 <<<"# Verwaltet von srvctl (Modul: ${mod})"$'\n'"${content}" || return 1
  fi
  ((FILE_CHANGED)) || return 0
  firewall_reload || {
    backup_restore "$file" "$RUN_ID"
    return 1
  }
}

# firewall_reload - reloads the srvctl table if the firewall is set up
firewall_reload() {
  [[ -f $FIREWALL_RULES_FILE ]] || return 0
  if ((DRY_RUN)); then
    log_dry "nft -f $FIREWALL_RULES_FILE"
    return 0
  fi
  local out
  if ! out=$(nft -c -f "$FIREWALL_RULES_FILE" 2>&1); then
    result_fail "Firewall-Regeln ungültig, nicht geladen: $out"
    return 1
  fi
  run_cmd nft -f "$FIREWALL_RULES_FILE"
}
