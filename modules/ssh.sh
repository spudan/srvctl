# shellcheck shell=bash
# ssh - OpenSSH server hardening: key-only login for admins (group sshusers),
# no root, modern crypto incl. post-quantum hybrid key exchange, restricted
# forwarding. Changes are protected by the confirmation timer.
# Decisions: docs/PLAN.md, section "3. ssh".

MODULE_NAME="ssh"
MODULE_DESC="SSH-Härtung: nur Schlüssel, kein root, moderne Kryptografie"
MODULE_DEPENDS=(users)
MODULE_LISTEN=(sshd)

readonly _SSH_DROPIN=/etc/ssh/sshd_config.d/00-srvctl.conf
readonly _SSH_BANNER=/etc/ssh/srvctl-banner
readonly _SSH_RSA_KEY=/etc/ssh/ssh_host_rsa_key
readonly _SSH_HEADER="Verwaltet von srvctl (Modul: ssh) – manuelle Änderungen werden überschrieben"

readonly _SSH_KEX="mlkem768x25519-sha256,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com,curve25519-sha256,curve25519-sha256@libssh.org"
readonly _SSH_CIPHERS="chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
readonly _SSH_MACS="hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
readonly _SSH_HOSTKEY_ALGS="ssh-ed25519,rsa-sha2-512,rsa-sha2-256"
readonly _SSH_PUBKEY_ALGS="ssh-ed25519,sk-ssh-ed25519@openssh.com,rsa-sha2-512,rsa-sha2-256,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,sk-ecdsa-sha2-nistp256@openssh.com"
readonly _SSH_PUBKEY_ALGS_SK="sk-ssh-ed25519@openssh.com,sk-ecdsa-sha2-nistp256@openssh.com"

# --- Configuration -------------------------------------------------------------

_ssh_port() { cfg_get SSH_PORT 22; }
_ssh_require_sk() { [[ $(cfg_get SSH_REQUIRE_SK 0) == 1 ]]; }

_ssh_pubkey_algs() {
  if _ssh_require_sk; then echo "$_SSH_PUBKEY_ALGS_SK"; else echo "$_SSH_PUBKEY_ALGS"; fi
}

# Expected effective values (sshd -T keys are lowercase)
_ssh_expected() {
  cat <<EOF
port $(_ssh_port)
permitrootlogin no
passwordauthentication no
kbdinteractiveauthentication no
pubkeyauthentication yes
authenticationmethods publickey
allowgroups $_USERS_GROUP
maxauthtries 3
logingracetime 30
maxstartups 10:30:60
permitemptypasswords no
hostbasedauthentication no
ignorerhosts yes
permituserenvironment no
loglevel VERBOSE
kexalgorithms $_SSH_KEX
ciphers $_SSH_CIPHERS
macs $_SSH_MACS
hostkeyalgorithms $_SSH_HOSTKEY_ALGS
pubkeyacceptedalgorithms $(_ssh_pubkey_algs)
requiredrsasize 3072
allowtcpforwarding $(cfg_get SSH_ALLOW_TCP_FORWARDING local)
allowagentforwarding $(cfg_get SSH_ALLOW_AGENT_FORWARDING no)
allowstreamlocalforwarding no
x11forwarding no
permittunnel no
gatewayports no
clientaliveinterval $(cfg_get SSH_CLIENT_ALIVE_INTERVAL 300)
clientalivecountmax 3
banner $_SSH_BANNER
debianbanner no
EOF
}

_ssh_validate() {
  local ok=0 port fwd agent
  port=$(_ssh_port)
  fwd=$(cfg_get SSH_ALLOW_TCP_FORWARDING local)
  agent=$(cfg_get SSH_ALLOW_AGENT_FORWARDING no)
  if [[ ! $port =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
    result_fail "SSH_PORT: '$port' ist kein gültiger Port"
    ok=1
  fi
  if [[ ! $fwd =~ ^(no|local|remote|yes|all)$ ]]; then
    result_fail "SSH_ALLOW_TCP_FORWARDING: '$fwd' ist ungültig (no, local, remote, yes)"
    ok=1
  fi
  if [[ ! $agent =~ ^(no|yes)$ ]]; then
    result_fail "SSH_ALLOW_AGENT_FORWARDING: '$agent' ist ungültig (no, yes)"
    ok=1
  fi
  return "$ok"
}

# Renders the drop-in (sshd_config syntax; first match wins, so it is "00-")
_ssh_dropin() {
  local key value
  echo "# ${_SSH_HEADER}"
  echo "# Siehe docs/PLAN.md, Abschnitt 3. Wirksame Werte: sshd -T"
  while read -r key value; do
    case $key in
      port) echo "Port $value" ;;
      permitrootlogin) echo "PermitRootLogin $value" ;;
      passwordauthentication) echo "PasswordAuthentication $value" ;;
      kbdinteractiveauthentication) echo "KbdInteractiveAuthentication $value" ;;
      pubkeyauthentication) echo "PubkeyAuthentication $value" ;;
      authenticationmethods) echo "AuthenticationMethods $value" ;;
      allowgroups) echo "AllowGroups $value" ;;
      maxauthtries) echo "MaxAuthTries $value" ;;
      logingracetime) echo "LoginGraceTime $value" ;;
      maxstartups) echo "MaxStartups $value" ;;
      permitemptypasswords) echo "PermitEmptyPasswords $value" ;;
      hostbasedauthentication) echo "HostbasedAuthentication $value" ;;
      ignorerhosts) echo "IgnoreRhosts $value" ;;
      permituserenvironment) echo "PermitUserEnvironment $value" ;;
      loglevel) echo "LogLevel $value" ;;
      kexalgorithms)
        echo
        echo "# Kryptografie: hybride Post-Quanten-Verfahren, nur AEAD-Chiffren und ETM-MACs"
        echo "HostKey /etc/ssh/ssh_host_ed25519_key"
        echo "HostKey ${_SSH_RSA_KEY}"
        echo "KexAlgorithms $value"
        ;;
      ciphers) echo "Ciphers $value" ;;
      macs) echo "MACs $value" ;;
      hostkeyalgorithms) echo "HostKeyAlgorithms $value" ;;
      pubkeyacceptedalgorithms) echo "PubkeyAcceptedAlgorithms $value" ;;
      requiredrsasize) echo "RequiredRSASize $value" ;;
      allowtcpforwarding)
        echo
        echo "# Weiterleitungen und Sitzungen"
        echo "AllowTcpForwarding $value"
        ;;
      allowagentforwarding) echo "AllowAgentForwarding $value" ;;
      allowstreamlocalforwarding) echo "AllowStreamLocalForwarding $value" ;;
      x11forwarding) echo "X11Forwarding $value" ;;
      permittunnel) echo "PermitTunnel $value" ;;
      gatewayports) echo "GatewayPorts $value" ;;
      clientaliveinterval) echo "ClientAliveInterval $value" ;;
      clientalivecountmax) echo "ClientAliveCountMax $value" ;;
      banner) echo "Banner $value" ;;
      debianbanner) echo "DebianBanner $value" ;;
    esac
  done < <(_ssh_expected)
}

# --- Checks --------------------------------------------------------------------

_ssh_effective() { sshd -T 2>/dev/null; }

_ssh_check_config() {
  local effective key want have bad=0
  if ! effective=$(_ssh_effective); then
    result_fail "sshd -T schlägt fehl – Konfiguration ungültig?"
    return 0
  fi
  if [[ ! -f $_SSH_DROPIN ]]; then
    result_fail "$_SSH_DROPIN fehlt – 'srvctl setup ssh'"
  fi
  while read -r key want; do
    have=$(awk -v k="$key" '$1 == k { $1 = ""; sub(/^ /, ""); print; exit }' <<<"$effective")
    if [[ $have != "$want" ]]; then
      if [[ $key == *algorithms || $key == ciphers || $key == macs ]]; then
        have=$(_ssh_list_diff "$have" "$want")
        [[ -z $have ]] && continue # same entries, different order
        want="Vorgabe"
      fi
      case $key in
        permitrootlogin | passwordauthentication | kbdinteractiveauthentication | authenticationmethods | \
          allowgroups | permitemptypasswords | kexalgorithms | ciphers | macs | pubkeyacceptedalgorithms)
          result_fail "$key: ${have:-?} (erwartet: $want)"
          ;;
        *) result_warn "$key: ${have:-?} (erwartet: $want)" ;;
      esac
      bad=1
    fi
  done < <(_ssh_expected)
  if ((!bad)); then
    result_ok "Wirksame sshd-Konfiguration entspricht der Vorgabe (nur Schlüssel, kein root, PQ-Kryptografie)"
  fi

  local hostkeys
  hostkeys=$(awk '$1 == "hostkey" { print $2 }' <<<"$effective" | paste -sd ' ')
  if [[ $hostkeys != "/etc/ssh/ssh_host_ed25519_key ${_SSH_RSA_KEY}" ]]; then
    result_warn "Host-Keys: ${hostkeys:-?} (erwartet: nur Ed25519 und RSA)"
  fi
}

# _ssh_list_diff HAVE WANT - describes the difference of two comma lists
_ssh_list_diff() {
  local extra missing
  extra=$(comm -23 <(tr ',' '\n' <<<"$1" | sort) <(tr ',' '\n' <<<"$2" | sort) | paste -sd ',')
  missing=$(comm -13 <(tr ',' '\n' <<<"$1" | sort) <(tr ',' '\n' <<<"$2" | sort) | paste -sd ',')
  [[ -z $extra && -z $missing ]] && return 0
  echo "${extra:+zusätzlich erlaubt: $extra}${extra:+${missing:+; }}${missing:+fehlt: $missing}"
}

_ssh_rsa_bits() {
  ssh-keygen -l -f "${_SSH_RSA_KEY}.pub" 2>/dev/null | awk '{ print $1 }'
}

_ssh_check_hostkeys() {
  local bits
  bits=$(_ssh_rsa_bits)
  if [[ -z $bits ]]; then
    result_fail "RSA-Host-Key fehlt (${_SSH_RSA_KEY})"
  elif ((bits < 4096)); then
    result_warn "RSA-Host-Key hat $bits Bit (erwartet 4096) – 'srvctl configure ssh'"
  else
    result_ok "Host-Keys: Ed25519 und RSA-$bits"
  fi
}

_ssh_check_admins() {
  local ready
  ready=$(_users_ready_admins | paste -sd ' ')
  if [[ -n $ready ]]; then
    result_ok "Anmeldung möglich für: $ready"
  else
    result_fail "Kein Admin mit Passwort und bekanntem Schlüssel in $_USERS_GROUP – Gefahr des Aussperrens"
  fi
  if _ssh_require_sk && [[ -z $(_ssh_sk_admins) ]]; then
    result_fail "SSH_REQUIRE_SK=1, aber kein Admin hat einen FIDO2-Schlüssel"
  fi
}

# Admins with at least one FIDO2 (sk-*) key
_ssh_sk_admins() {
  local user
  while IFS= read -r user; do
    if _users_file_keys "$(_users_keyfile "$user")" | cut -f3 | grep -q -- '-SK$'; then
      echo "$user"
    fi
  done < <(_users_ready_admins)
}

_ssh_check_audit() {
  cmd_exists ssh-audit || return 0
  local out rc=0
  out=$(timeout 60 ssh-audit -n -b -p "$(_ssh_port)" 127.0.0.1 2>&1) || rc=$?
  # ssh-audit exit codes: 0 good, 1 connection error, 2 warnings, 3 failures
  case $rc in
    0) result_ok "ssh-audit: keine Beanstandungen" ;;
    2) result_warn "ssh-audit: Warnungen – Details: ssh-audit -p $(_ssh_port) 127.0.0.1" ;;
    3) result_fail "ssh-audit: Fehler – Details: ssh-audit -p $(_ssh_port) 127.0.0.1" ;;
    *) result_warn "ssh-audit konnte nicht prüfen (Exit-Code $rc)" ;;
  esac
  if ((rc == 2 || rc == 3)); then
    grep -E '\((fin|rec|kex|key|enc|mac)\).*\[(fail|warn)\]' <<<"$out" | head -n 5 | while IFS= read -r line; do
      log_info "  ${line}"
    done
  fi
}

# --- Apply ---------------------------------------------------------------------

# Refuses changes that could lock everybody out.
_ssh_precheck() {
  if [[ -z $(_users_ready_admins) ]] && ((!DRY_RUN)); then
    result_fail "Abgebrochen: kein Admin mit Passwort und bekanntem Schlüssel – zuerst 'srvctl setup users'"
    return 1
  fi
  if _ssh_require_sk && [[ -z $(_ssh_sk_admins) ]]; then
    result_fail "Abgebrochen: SSH_REQUIRE_SK=1, aber kein Admin hat einen FIDO2-Schlüssel"
    return 1
  fi
  if [[ $(_ssh_port) != 22 ]] && svc_is_active ssh.socket; then
    result_fail "Abgebrochen: ssh.socket ist aktiv – ein anderer Port als 22 wird so nicht wirksam"
    return 1
  fi
}

# Regenerates the RSA host key if shorter than 4096 bit. Sets _SSH_CHANGED.
_ssh_apply_hostkeys() {
  local bits
  bits=$(_ssh_rsa_bits)
  if [[ -n $bits ]] && ((bits >= 4096)); then
    return 0
  fi
  log_info "RSA-Host-Key hat ${bits:-0} Bit – wird mit 4096 Bit neu erzeugt (Clients sehen einmalig eine Warnung, falls sie den RSA-Key nutzen)"
  backup_file "$_SSH_RSA_KEY"
  backup_file "${_SSH_RSA_KEY}.pub"
  run_cmd rm -f -- "$_SSH_RSA_KEY" "${_SSH_RSA_KEY}.pub"
  run_cmd ssh-keygen -q -t rsa -b 4096 -N '' -C "root@$(hostname -s)" -f "$_SSH_RSA_KEY"
  _SSH_CHANGED=1
}

# Validates a candidate drop-in against the full configuration
_ssh_test_dropin() {
  local candidate=$1 test_conf out
  test_conf=$(mktemp "${RUN_DIR}/sshd_config.XXXXXX")
  { cat -- "$candidate"; echo "Include /etc/ssh/sshd_config"; } >"$test_conf"
  if ! out=$(sshd -t -f "$test_conf" 2>&1); then
    result_fail "Neue sshd-Konfiguration ist ungültig: $out"
    return 1
  fi
}

ssh::check() {
  _ssh_validate || return 0
  check_service ssh
  _ssh_check_admins
  _ssh_check_config
  _ssh_check_hostkeys
  _ssh_check_audit
}

ssh::setup() {
  pkg_install openssh-server ssh-audit
  ssh::configure
}

ssh::configure() {
  _ssh_validate || return 1
  _ssh_precheck || return 1
  _SSH_CHANGED=0

  _ssh_apply_hostkeys

  write_file "$_SSH_BANNER" 0644 <<<"$(cfg_get SSH_BANNER_TEXT "Zugriff nur für berechtigte Personen. Alle Aktivitäten werden protokolliert.")"
  if ((FILE_CHANGED)); then _SSH_CHANGED=1; fi

  local candidate
  candidate=$(mktemp "${RUN_DIR}/dropin.XXXXXX")
  _ssh_dropin >"$candidate"
  _ssh_test_dropin "$candidate"
  write_file "$_SSH_DROPIN" 0644 <"$candidate"
  if ((FILE_CHANGED)); then _SSH_CHANGED=1; fi

  if ((!_SSH_CHANGED)); then
    result_ok "SSH-Konfiguration ist aktuell"
    return 0
  fi
  if ((!DRY_RUN)) && ! sshd -t; then
    result_fail "sshd -t schlägt nach dem Schreiben fehl – Änderungen werden zurückgesetzt"
    backup_restore_run ssh "$RUN_ID"
    return 1
  fi
  svc_reload ssh
  revert_timer_arm
  result_ok "SSH gehärtet und neu geladen – bestehende Sitzungen bleiben offen"
}

ssh::after_revert() {
  svc_reload ssh
}
