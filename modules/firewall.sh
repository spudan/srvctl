# shellcheck shell=bash
# firewall - nftables with an own table "inet srvctl": incoming and forwarded
# traffic dropped by default, SSH (rate limited) and configured ports open,
# rules from other modules included. Never "flush ruleset", so tables of
# CrowdSec, Docker or Tailscale stay intact. Protected by the confirmation
# timer. Decisions: docs/PLAN.md, section "4. firewall".

MODULE_NAME="firewall"
MODULE_DESC="Firewall (nftables): eingehend alles zu außer SSH und freigegebenen Ports"
MODULE_DEPENDS=()

readonly _FW_NFTCONF=/etc/nftables.conf
readonly _FW_UNIT_DROPIN=/etc/systemd/system/nftables.service.d/srvctl.conf
readonly _FW_HEADER="Verwaltet von srvctl (Modul: firewall) – manuelle Änderungen werden überschrieben"

# --- Configuration -------------------------------------------------------------

_fw_ssh_port() { cfg_get SSH_PORT 22; }
_fw_output_policy() { cfg_get FIREWALL_OUTPUT_POLICY accept; }

# _fw_set LIST - "80 443" -> "{ 80, 443 }" (nft anonymous set)
_fw_set() {
  local -a items
  local joined
  read -ra items <<<"$1"
  printf -v joined '%s, ' "${items[@]}"
  echo "{ ${joined%, } }"
}

_fw_validate() {
  local ok=0 port var addr
  for var in FIREWALL_TCP_PORTS FIREWALL_UDP_PORTS FIREWALL_OUT_TCP_PORTS FIREWALL_OUT_UDP_PORTS; do
    for port in $(cfg_get "$var" ""); do
      if [[ ! $port =~ ^[0-9]{1,5}(-[0-9]{1,5})?$ ]]; then
        result_fail "$var: '$port' ist kein Port oder Bereich (z. B. 443 oder 8000-8100)"
        ok=1
      fi
    done
  done
  for addr in $(cfg_get FIREWALL_SSH_ALLOW ""); do
    if [[ ! $addr =~ ^[0-9A-Fa-f:.]+(/[0-9]{1,3})?$ ]]; then
      result_fail "FIREWALL_SSH_ALLOW: '$addr' ist keine IP-Adresse oder kein Netz"
      ok=1
    fi
  done
  if [[ ! $(_fw_output_policy) =~ ^(accept|drop)$ ]]; then
    result_fail "FIREWALL_OUTPUT_POLICY: '$(_fw_output_policy)' ist ungültig (accept oder drop)"
    ok=1
  fi
  if [[ ! $(cfg_get FIREWALL_SSH_RATE 10/minute) =~ ^[0-9]+/(second|minute|hour)$ ]]; then
    result_fail "FIREWALL_SSH_RATE: '$(cfg_get FIREWALL_SSH_RATE)' ist ungültig (z. B. 10/minute)"
    ok=1
  fi
  return "$ok"
}

# --- Ruleset -------------------------------------------------------------------

# _fw_ruleset [MODULE_DIR] - prints the complete srvctl table
_fw_ruleset() {
  local dir=${1:-$(firewall_dir)} port rate addr
  local -a v4=() v6=()
  port=$(_fw_ssh_port)
  rate=$(cfg_get FIREWALL_SSH_RATE 10/minute)
  for addr in $(cfg_get FIREWALL_SSH_ALLOW ""); do
    if [[ $addr == *:* ]]; then v6+=("$addr"); else v4+=("$addr"); fi
  done

  cat <<EOF
#!/usr/sbin/nft -f
# ${_FW_HEADER}
# Ersetzt nur die eigene Tabelle; Tabellen anderer Programme bleiben unberührt.
table inet srvctl
delete table inet srvctl

table inet srvctl {
	# Neue SSH-Verbindungen pro Quell-IP begrenzen
	set ssh_v4 { type ipv4_addr; flags dynamic, timeout; timeout 1m; }
	set ssh_v6 { type ipv6_addr; flags dynamic, timeout; timeout 1m; }

	chain input {
		type filter hook input priority filter; policy drop;

		ct state established,related accept
		ct state invalid drop
		iif "lo" accept

		# ICMP: für IPv6 unverzichtbare Typen, Ping begrenzt
		meta l4proto ipv6-icmp icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert, mld-listener-query, mld-listener-report, mld2-listener-report } accept
		meta l4proto icmp icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
		icmp type echo-request limit rate 5/second accept
		icmpv6 type echo-request limit rate 5/second accept
		# DHCPv6-Antworten (Link-lokal)
		ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept

		# SSH
		tcp dport ${port} ct state new update @ssh_v4 { ip saddr limit rate over ${rate} burst 10 packets } counter drop
		tcp dport ${port} ct state new update @ssh_v6 { ip6 saddr limit rate over ${rate} burst 10 packets } counter drop
EOF
  if ((${#v4[@]} + ${#v6[@]} == 0)); then
    printf '\t\ttcp dport %s accept\n' "$port"
  else
    printf '\t\t# SSH nur von FIREWALL_SSH_ALLOW\n'
    ((${#v4[@]})) && printf '\t\ttcp dport %s ip saddr %s accept\n' "$port" "$(_fw_set "${v4[*]}")"
    ((${#v6[@]})) && printf '\t\ttcp dport %s ip6 saddr %s accept\n' "$port" "$(_fw_set "${v6[*]}")"
  fi

  local tcp udp
  tcp=$(cfg_get FIREWALL_TCP_PORTS "")
  udp=$(cfg_get FIREWALL_UDP_PORTS "")
  if [[ -n $tcp || -n $udp ]]; then
    printf '\n\t\t# Freigegebene Ports (FIREWALL_TCP_PORTS / FIREWALL_UDP_PORTS)\n'
    [[ -n $tcp ]] && printf '\t\ttcp dport %s accept\n' "$(_fw_set "$tcp")"
    [[ -n $udp ]] && printf '\t\tudp dport %s accept\n' "$(_fw_set "$udp")"
  fi

  printf '\n\t\t# Regeln anderer srvctl-Module\n'
  printf '\t\tinclude "%s/*.nft"\n\n' "$dir"
  if [[ $(cfg_get FIREWALL_LOG_DROPS 0) == 1 ]]; then
    printf '\t\tlimit rate 5/minute log prefix "srvctl-drop: " level info\n'
  fi
  printf '\t\tcounter comment "eingehend verworfen"\n\t}\n\n'

  printf '\tchain forward {\n\t\ttype filter hook forward priority filter; policy drop;\n'
  printf '\t\tcounter comment "weitergeleitet verworfen"\n\t}\n'

  if [[ $(_fw_output_policy) == drop ]]; then
    local out_tcp out_udp
    out_tcp="53 80 443 4460 $(cfg_get FIREWALL_OUT_TCP_PORTS "")"
    out_udp="53 67 123 547 $(cfg_get FIREWALL_OUT_UDP_PORTS "")"
    cat <<EOF

	chain output {
		type filter hook output priority filter; policy drop;
		ct state established,related accept
		oif "lo" accept
		meta l4proto { icmp, ipv6-icmp } accept
		# DNS, HTTP(S), NTP/NTS, DHCP + FIREWALL_OUT_*_PORTS
		tcp dport $(_fw_set "$out_tcp") accept
		udp dport $(_fw_set "$out_udp") accept
		counter comment "ausgehend verworfen"
	}
EOF
  fi
  echo "}"
}

# --- Helpers -------------------------------------------------------------------

# IP of the SSH client that runs srvctl (also through sudo)
_fw_client_ip() {
  local ip
  ip=$(who -m 2>/dev/null | sed -n 's/.*(\([0-9A-Fa-f:.]*\)).*/\1/p')
  [[ -z $ip && -n ${SSH_CLIENT:-} ]] && ip=${SSH_CLIENT%% *}
  echo "$ip"
}

# _fw_ip_in IP NET... - true if IP lies in one of the networks
_fw_ip_in() {
  python3 - "$@" <<'EOF' 2>/dev/null
import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
sys.exit(0 if any(ip in ipaddress.ip_network(n, strict=False) for n in sys.argv[2:]) else 1)
EOF
}

# Ports opened in the srvctl table: "tcp 22", "udp 51820", ...
_fw_open_ports() {
  local proto entry
  echo "tcp $(_fw_ssh_port)"
  for entry in $(cfg_get FIREWALL_TCP_PORTS ""); do echo "tcp $entry"; done
  for entry in $(cfg_get FIREWALL_UDP_PORTS ""); do echo "udp $entry"; done
  local file
  for file in "$(firewall_dir)"/*.nft; do
    [[ -f $file ]] || continue
    for proto in tcp udp; do
      grep -oE "${proto} dport (\{[^}]*\}|[0-9-]+)" "$file" | sed -E "s/^${proto} dport //; s/[{},]/ /g" |
        tr ' ' '\n' | grep . | sed "s/^/${proto} /"
    done
  done
}

# _fw_port_open PROTO PORT
_fw_port_open() {
  local proto=$1 port=$2 p entry
  while read -r p entry; do
    [[ $p == "$proto" ]] || continue
    if [[ $entry == *-* ]]; then
      ((port >= ${entry%-*} && port <= ${entry#*-})) && return 0
    elif [[ $entry == "$port" ]]; then
      return 0
    fi
  done < <(_fw_open_ports)
  return 1
}

# Public listeners: "PROTO PORT PROCESS"
_fw_listeners() { net_listeners | awk '{ print $1, $2, $3 }' | sort -u; }

# --- Checks --------------------------------------------------------------------

_fw_check_rules() {
  if ! pkg_installed nftables; then
    result_fail "nftables ist nicht installiert – 'srvctl setup firewall'"
    return 0
  fi
  local table
  if ! table=$(nft list table inet srvctl 2>/dev/null); then
    result_fail "Firewall-Tabelle 'inet srvctl' ist nicht geladen – 'srvctl setup firewall'"
    return 0
  fi
  if grep -q 'hook input priority filter; policy drop;' <<<"$table"; then
    result_ok "Eingehend: alles blockiert außer Freigaben"
  else
    result_fail "Eingehend ist nicht standardmäßig blockiert (policy drop fehlt)"
  fi
  if grep -q 'hook forward priority filter; policy drop;' <<<"$table"; then
    result_ok "Weiterleitung blockiert"
  else
    result_warn "Weiterleitung ist nicht blockiert"
  fi
  if grep -qE "tcp dport $(_fw_ssh_port) .*accept" <<<"$table"; then
    result_ok "SSH (Port $(_fw_ssh_port)) erreichbar$([[ -n $(cfg_get FIREWALL_SSH_ALLOW "") ]] && echo " nur von FIREWALL_SSH_ALLOW"), mit Ratenlimit"
  else
    result_fail "Keine Freigabe für SSH-Port $(_fw_ssh_port) geladen – Gefahr des Aussperrens"
  fi

  local expected
  expected=$(mktemp "${RUN_DIR}/fw.XXXXXX")
  _fw_ruleset >"$expected"
  if [[ -f $FIREWALL_RULES_FILE ]] && ! cmp -s "$expected" "$FIREWALL_RULES_FILE"; then
    result_warn "Regeldatei weicht von der Konfiguration ab – 'srvctl configure firewall'"
  fi

  local modules
  modules=$(find "$(firewall_dir)" -maxdepth 1 -name '*.nft' -printf '%f\n' 2>/dev/null | sed 's/\.nft$//' | paste -sd ' ')
  if [[ -n $modules ]]; then
    result_ok "Regeln von Modulen eingebunden: $modules"
  fi
}

_fw_check_system() {
  if grep -qE '^[[:space:]]*flush[[:space:]]+ruleset' "$_FW_NFTCONF" 2>/dev/null; then
    result_fail "$_FW_NFTCONF enthält 'flush ruleset' – löscht beim Laden auch fremde Tabellen (CrowdSec, Docker)"
  fi
  if [[ -f $_FW_UNIT_DROPIN ]]; then
    result_ok "nftables.service löscht beim Stoppen nur die eigene Tabelle"
  else
    result_warn "nftables.service würde beim Stoppen alle Regeln löschen (flush ruleset)"
  fi
  if ! svc_is_enabled nftables; then
    result_fail "nftables.service ist nicht aktiviert – Firewall fehlt nach einem Neustart"
  fi
  local other
  for other in ufw firewalld; do
    if svc_is_active "$other"; then
      result_warn "$other ist zusätzlich aktiv – zwei Firewall-Verwaltungen stören sich"
    fi
  done
  if cmd_exists docker || svc_exists docker; then
    if [[ -z ${MOD_FILE[docker]:-} ]]; then
      result_fail "Docker ist installiert, aber es gibt kein srvctl-Modul 'docker' – veröffentlichte Container-Ports umgehen die Firewall"
    fi
  fi
}

_fw_check_listeners() {
  local proto port proc
  local -A seen=()
  while read -r proto port proc; do
    [[ -n ${seen[$proto$port]:-} ]] && continue
    seen[$proto$port]=1
    if _fw_port_open "$proto" "$port"; then
      continue
    fi
    log_info "Hinweis: $proc lauscht auf $proto/$port, ist von außen aber blockiert"
  done < <(_fw_listeners)

  local entry
  while read -r proto entry; do
    [[ $entry == *-* ]] && continue
    if ! _fw_listeners | awk -v p="$proto" -v n="$entry" '$1 == p && $2 == n { f = 1 } END { exit !f }'; then
      result_warn "Port $proto/$entry ist freigegeben, aber kein Dienst lauscht darauf"
    fi
  done < <(_fw_open_ports | sort -u)
}

# --- Apply ---------------------------------------------------------------------

_fw_precheck() {
  local allow client
  allow=$(cfg_get FIREWALL_SSH_ALLOW "")
  [[ -n $allow ]] || return 0
  client=$(_fw_client_ip)
  if [[ -z $client ]]; then
    result_fail "Abgebrochen: FIREWALL_SSH_ALLOW ist gesetzt, aber die IP dieser Sitzung ist unbekannt"
    return 1
  fi
  # shellcheck disable=SC2086
  if ! _fw_ip_in "$client" $allow; then
    result_fail "Abgebrochen: Diese Sitzung ($client) ist nicht in FIREWALL_SSH_ALLOW – du würdest dich aussperren"
    return 1
  fi
}

firewall::check() {
  _fw_validate || return 0
  _fw_check_system
  _fw_check_rules
  _fw_check_listeners
}

firewall::setup() {
  pkg_install nftables
  firewall::configure
}

firewall::configure() {
  _fw_validate || return 1
  _fw_precheck || return 1
  local changed=0 candidate out moddir
  moddir=$(firewall_dir)

  if [[ ! -d $moddir ]]; then
    run_cmd install -d -m 0700 "$moddir"
  fi

  candidate=$(mktemp "${RUN_DIR}/fw.XXXXXX")
  _fw_ruleset "$moddir" >"$candidate"
  if ! out=$(nft -c -f "$candidate" 2>&1); then
    result_fail "Firewall-Regeln ungültig: $out"
    return 1
  fi
  write_file "$FIREWALL_RULES_FILE" 0600 <"$candidate"
  if ((FILE_CHANGED)); then changed=1; fi

  write_file "$_FW_NFTCONF" 0755 <<<"#!/usr/sbin/nft -f
# ${_FW_HEADER}
# Kein 'flush ruleset': Tabellen anderer Programme (CrowdSec, Docker, Tailscale) bleiben erhalten.
include \"${FIREWALL_RULES_FILE%/*}/*.nft\""

  write_file "$_FW_UNIT_DROPIN" 0644 <<<"# ${_FW_HEADER}
# Beim Stoppen nur die eigene Tabelle entfernen statt 'flush ruleset'
[Service]
ExecStop=
ExecStop=-/usr/sbin/nft delete table inet srvctl"
  if ((FILE_CHANGED)); then
    run_cmd systemctl daemon-reload
  fi

  if ! nft list table inet srvctl >/dev/null 2>&1; then
    changed=1
  fi
  if ((changed)); then
    run_cmd nft -f "$FIREWALL_RULES_FILE"
    revert_timer_arm
    result_ok "Firewall geladen: eingehend nur SSH$([[ -n $(cfg_get FIREWALL_TCP_PORTS "")$(cfg_get FIREWALL_UDP_PORTS "") ]] && echo " + $(cfg_get FIREWALL_TCP_PORTS "") $(cfg_get FIREWALL_UDP_PORTS "")") und Modul-Regeln"
  else
    result_ok "Firewall-Regeln sind aktuell"
  fi
  svc_enable nftables
}

firewall::after_revert() {
  run_cmd systemctl daemon-reload
  if [[ -f $FIREWALL_RULES_FILE ]]; then
    run_cmd nft -f "$FIREWALL_RULES_FILE"
  else
    run_cmd nft delete table inet srvctl || true
  fi
}
