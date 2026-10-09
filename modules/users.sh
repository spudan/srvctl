# shellcheck shell=bash
# users - admin accounts with SSH keys, sudo, root account, password policy
# and account hygiene. Decisions: docs/PLAN.md, section "2. users".
#
# Admins are members of the groups "sudo" and "sshusers". Names, keys and
# passwords are entered interactively and never stored in the repository.
# Only key fingerprints are kept locally (STATE_DIR/users/admins) so check can
# detect keys that were not added through srvctl.

MODULE_NAME="users"
MODULE_DESC="Admins mit SSH-Schlüssel, sudo, root-Konto, Passwortregeln"
MODULE_DEPENDS=()

readonly _USERS_GROUP=sshusers
readonly _USERS_SUDOERS=/etc/sudoers.d/srvctl
readonly _USERS_PWQUALITY=/etc/security/pwquality.conf.d/srvctl.conf
readonly _USERS_FAILLOCK_CONF=/etc/security/faillock.conf
readonly _USERS_PAM_FAILLOCK=/usr/share/pam-configs/srvctl-faillock
readonly _USERS_PAM_FAILLOCK_NOTIFY=/usr/share/pam-configs/srvctl-faillock-notify
readonly _USERS_UMASK_PROFILE=/etc/profile.d/srvctl-umask.sh
readonly _USERS_HEADER="Verwaltet von srvctl (Modul: users) – manuelle Änderungen werden überschrieben"
readonly _USERS_PAM_FILES="/etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password /etc/pam.d/common-session /etc/pam.d/common-session-noninteractive"

# --- Helpers -------------------------------------------------------------------

# _users_pwq_existing KEY - pwquality value set outside srvctl (last file wins)
_users_pwq_existing() {
  local file value="" found
  for file in /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf; do
    [[ -f $file && $file != "$_USERS_PWQUALITY" ]] || continue
    if found=$(conf_get "$file" "$1" "="); then value=$found; fi
  done
  echo "$value"
}

# Minimum length: configured value, or a stricter existing one
_users_minlen() {
  local want existing
  want=$(cfg_get USERS_PASS_MINLEN 14)
  existing=$(_users_pwq_existing minlen)
  if [[ $existing =~ ^[0-9]+$ ]] && ((existing > want)); then want=$existing; fi
  echo "$want"
}

# _users_pwq_keep KEY DEFAULT - keeps a stricter existing value: higher minclass,
# negative credits (= required character classes)
_users_pwq_keep() {
  local existing
  existing=$(_users_pwq_existing "$1")
  case $1 in
    minclass) [[ $existing =~ ^[0-9]+$ ]] && ((existing > $2)) && { echo "$existing"; return; } ;;
    *credit) [[ $existing =~ ^-[0-9]+$ ]] && { echo "$existing"; return; } ;;
  esac
  echo "$2"
}

_users_state() { state_path users admins; }

_users_home() {
  local entry
  if entry=$(getent passwd "$1"); then
    cut -d: -f6 <<<"$entry"
  else
    echo "/home/$1" # not created yet (useradd default)
  fi
}

_users_keyfile() { echo "$(_users_home "$1")/.ssh/authorized_keys"; }

# Members of the admin group (sshusers)
_users_admins() {
  getent group "$_USERS_GROUP" | cut -d: -f4 | tr ',' '\n' | grep . || true
}

_users_group_members() {
  getent group "$1" | cut -d: -f4 | tr ',' '\n' | grep . || true
}

# _users_key_info KEYLINE - prints "BITS<TAB>FINGERPRINT<TAB>TYPE<TAB>COMMENT"
_users_key_info() {
  ssh-keygen -l -f /dev/stdin <<<"$1" 2>/dev/null | awk '{
    type = $NF; gsub(/[()]/, "", type)
    comment = ""; for (i = 3; i < NF; i++) comment = comment (i > 3 ? " " : "") $i
    print $1 "\t" $2 "\t" type "\t" comment
  }'
}

# _users_file_keys FILE - prints key info for every key in an authorized_keys file
_users_file_keys() {
  [[ -s $1 ]] || return 0
  local line
  while IFS= read -r line; do
    [[ -z $line || $line == \#* ]] && continue
    _users_key_info "$line"
  done <"$1"
}

# _users_known_fps USER - fingerprints registered via srvctl
_users_known_fps() {
  local state
  state=$(_users_state)
  [[ -r $state ]] || return 0
  awk -F'\t' -v u="$1" '$1 == u { print $2 }' "$state"
}

_users_password_status() { passwd -S "$1" 2>/dev/null | awk '{ print $2 }'; }

# Admins with sudo password and at least one known key (safe to lock root)
_users_ready_admins() {
  local user fp
  while IFS= read -r user; do
    [[ $(_users_password_status "$user") == P ]] || continue
    while IFS=$'\t' read -r _ fp _ _; do
      if _users_known_fps "$user" | grep -qxF "$fp"; then
        echo "$user"
        break
      fi
    done < <(_users_file_keys "$(_users_keyfile "$user")")
  done < <(_users_admins)
}

# --- Validators (used by ask*) ------------------------------------------------

_users_valid_name() {
  if [[ ! $1 =~ ^[a-z_][a-z0-9_-]{0,31}$ ]]; then
    log_warn "Ungültiger Name (erlaubt: Kleinbuchstaben, Ziffern, _ und -; Beginn mit Buchstabe)"
    return 1
  fi
  if [[ $1 == root ]]; then
    log_warn "root kann kein Admin im Sinne von srvctl sein"
    return 1
  fi
  local uid
  uid=$(id -u "$1" 2>/dev/null) || return 0
  if ((uid < 1000)); then
    log_warn "$1 ist ein Systemkonto (UID $uid)"
    return 1
  fi
}

_users_valid_key() {
  local key=$1 info bits fp type
  if [[ ! $key =~ ^(ssh-ed25519|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com|ecdsa-sha2-nistp(256|384|521)|ssh-rsa)[[:space:]]+[A-Za-z0-9+/]+=*([[:space:]].*)?$ ]]; then
    log_warn "Kein unterstützter öffentlicher Schlüssel (ssh-ed25519, sk-ssh-ed25519, ecdsa, ssh-rsa ≥ 3072; ohne Optionen davor)"
    return 1
  fi
  info=$(_users_key_info "$key")
  if [[ -z $info ]]; then
    log_warn "Schlüssel ist beschädigt (ssh-keygen kann ihn nicht lesen)"
    return 1
  fi
  IFS=$'\t' read -r bits fp type _ <<<"$info"
  if [[ $type == RSA ]] && ((bits < 3072)); then
    log_warn "RSA-Schlüssel mit $bits Bit ist zu kurz (mindestens 3072, besser Ed25519)"
    return 1
  fi
  log_info "Schlüssel gültig: $type $fp"
}

_USERS_CURRENT_NAME=""
_users_valid_password() {
  local minlen out
  minlen=$(_users_minlen)
  if ((${#1} < minlen)); then
    log_warn "Passwort ist zu kurz (mindestens $minlen Zeichen)"
    return 1
  fi
  if cmd_exists pwscore; then
    if ! out=$(pwscore "$_USERS_CURRENT_NAME" <<<"$1" 2>&1); then
      log_warn "Passwort abgelehnt: $(tail -n 1 <<<"$out" | sed 's/^ *//')"
      return 1
    fi
  fi
}

# --- Admins and keys -----------------------------------------------------------

_users_ensure_group() {
  getent group "$_USERS_GROUP" >/dev/null && return 0
  run_cmd groupadd --system "$_USERS_GROUP"
}

# _users_write_keys USER KEYLINES... - writes authorized_keys (existing keys
# plus new ones, without duplicates) and registers the new fingerprints.
_users_write_keys() {
  local user=$1
  shift
  local file dir group line fp content=""
  local -A seen=()
  file=$(_users_keyfile "$user")
  dir=${file%/*}
  group=$(id -gn "$user" 2>/dev/null || echo "$user")

  if [[ -s $file ]]; then
    while IFS= read -r line; do
      [[ -z $line ]] && continue
      fp=$(_users_key_info "$line" | cut -f2)
      [[ -n $fp ]] && seen[$fp]=1
      content+="${line}"$'\n'
    done <"$file"
  fi
  local -a new_fps=()
  for line; do
    fp=$(_users_key_info "$line" | cut -f2)
    new_fps+=("$fp")
    [[ -n ${seen[$fp]:-} ]] && continue
    seen[$fp]=1
    content+="${line}"$'\n'
  done

  if [[ ! -d $dir ]]; then
    run_cmd install -d -m 0700 -o "$user" -g "$group" "$dir"
  fi
  write_file "$file" 0600 "${user}:${group}" <<<"${content%$'\n'}"
  _users_register_fps "$user" "${new_fps[@]}"
}

# _users_register_fps USER FINGERPRINT... - adds fingerprints to the state file
_users_register_fps() {
  local user=$1 state content="" fp
  shift
  state=$(_users_state)
  [[ -r $state ]] && content=$(<"$state")$'\n'
  for fp; do
    if ! grep -qxF "${user}"$'\t'"${fp}" <<<"$content"; then
      content+="${user}"$'\t'"${fp}"$'\n'
    fi
  done
  content=$(grep . <<<"$content" | sort -u)
  write_file "$state" 0600 <<<"$content"
}

# _users_unregister USER [FINGERPRINT] - removes one or all fingerprints of USER
_users_unregister() {
  local state content
  state=$(_users_state)
  [[ -r $state ]] || return 0
  if [[ -n ${2:-} ]]; then
    content=$(awk -F'\t' -v u="$1" -v f="$2" '!($1 == u && $2 == f)' "$state")
  else
    content=$(awk -F'\t' -v u="$1" '$1 != u' "$state")
  fi
  write_file "$state" 0600 <<<"$content"
}

_users_set_password() {
  local user=$1 password
  _USERS_CURRENT_NAME=$user
  ask_password password "sudo-Passwort für $user (mindestens $(_users_minlen) Zeichen)" _users_valid_password
  run_cmd chpasswd <<<"${user}:${password}"
  result_ok "sudo-Passwort für $user gesetzt"
}

_users_add_admin() {
  local name keys
  local -a key_lines
  ask name "Benutzername des neuen Admins" "" _users_valid_name
  ask_lines keys "Öffentliche SSH-Schlüssel für $name einfügen (eine Zeile pro Schlüssel)" _users_valid_key
  if [[ -z $keys ]]; then
    result_fail "Kein gültiger Schlüssel eingegeben – $name wurde nicht angelegt"
    return 1
  fi
  mapfile -t key_lines <<<"$keys"

  _users_ensure_group
  if id "$name" >/dev/null 2>&1; then
    log_info "Benutzer $name existiert bereits – wird zum Admin"
    run_cmd usermod -aG "sudo,${_USERS_GROUP}" "$name"
  else
    run_cmd useradd --create-home --shell /bin/bash --groups "sudo,${_USERS_GROUP}" --comment "Admin (srvctl)" "$name"
  fi
  _users_write_keys "$name" "${key_lines[@]}"
  if [[ $(_users_password_status "$name") == P ]] && confirm "Bestehendes Passwort von $name behalten (für sudo)?"; then
    log_info "Passwort von $name bleibt unverändert"
  else
    _users_set_password "$name"
  fi
  result_ok "Admin $name eingerichtet (${#key_lines[@]} Schlüssel)"
  log_info "Bitte jetzt in einem NEUEN Terminal testen: ssh ${name}@<server> und dort 'sudo -v'"
}

_users_choose_admin() { # VAR PROMPT
  local -a admins choices=()
  local admin
  mapfile -t admins < <(_users_admins)
  if ((${#admins[@]} == 0)); then
    log_warn "Es gibt noch keinen Admin"
    return 1
  fi
  for admin in "${admins[@]}"; do choices+=("$admin" "$admin"); done
  ask_choice "$1" "$2" "${choices[@]}"
}

_users_menu_add_key() {
  local user keys
  local -a key_lines
  _users_choose_admin user "Schlüssel hinzufügen für:" || return 0
  ask_lines keys "Öffentliche SSH-Schlüssel für $user einfügen" _users_valid_key
  [[ -n $keys ]] || return 0
  mapfile -t key_lines <<<"$keys"
  _users_write_keys "$user" "${key_lines[@]}"
  result_ok "$user: ${#key_lines[@]} Schlüssel hinzugefügt"
}

_users_menu_remove_key() {
  local user file choice line fp remaining=0 content=""
  local -a choices=()
  _users_choose_admin user "Schlüssel entfernen bei:" || return 0
  file=$(_users_keyfile "$user")
  while IFS=$'\t' read -r _ fp type comment; do
    choices+=("$fp" "$type $fp ${comment}")
  done < <(_users_file_keys "$file")
  if ((${#choices[@]} == 0)); then
    log_warn "$user hat keine Schlüssel"
    return 0
  fi
  ask_choice choice "Welchen Schlüssel entfernen?" "${choices[@]}"
  while IFS= read -r line; do
    [[ -z $line ]] && continue
    fp=$(_users_key_info "$line" | cut -f2)
    if [[ $fp == "$choice" ]]; then continue; fi
    content+="${line}"$'\n'
    if [[ -n $fp ]]; then ((++remaining)); fi
  done <"$file"
  if ((remaining == 0)) && [[ $(_users_ready_admins | grep -vxF "$user" | grep -c .) == 0 ]]; then
    result_fail "Abgebrochen: $user ist der letzte Admin und hätte danach keinen Schlüssel mehr"
    return 0
  fi
  write_file "$file" <<<"${content%$'\n'}"
  _users_unregister "$user" "$choice"
  result_ok "$user: Schlüssel $choice entfernt"
}

_users_menu_accept_keys() {
  local user fp type comment count=0
  local -a fps=()
  _users_choose_admin user "Unbekannte Schlüssel übernehmen bei:" || return 0
  while IFS=$'\t' read -r _ fp type comment; do
    _users_known_fps "$user" | grep -qxF "$fp" && continue
    log_info "Unbekannt: $type $fp $comment"
    fps+=("$fp")
  done < <(_users_file_keys "$(_users_keyfile "$user")")
  if ((${#fps[@]} == 0)); then
    log_info "$user hat keine unbekannten Schlüssel"
    return 0
  fi
  confirm "Diese ${#fps[@]} Schlüssel als rechtmäßig übernehmen?" || return 0
  _users_register_fps "$user" "${fps[@]}"
  result_ok "$user: ${#fps[@]} Schlüssel übernommen"
}

_users_menu_remove_admin() {
  local user
  _users_choose_admin user "Welchen Admin entfernen (Konto wird gesperrt, nicht gelöscht)?" || return 0
  if [[ $(_users_ready_admins | grep -vxF "$user" | grep -c .) == 0 ]]; then
    result_fail "Abgebrochen: $user ist der letzte Admin"
    return 0
  fi
  confirm "$user sperren und aus sudo/${_USERS_GROUP} entfernen?" || return 0
  run_cmd gpasswd -d "$user" sudo
  run_cmd gpasswd -d "$user" "$_USERS_GROUP"
  run_cmd usermod --lock --expiredate 1 "$user"
  _users_unregister "$user"
  result_ok "Admin $user gesperrt (Home-Verzeichnis bleibt erhalten)"
}

_users_menu() {
  local choice
  while :; do
    ask_choice choice "Admins verwalten:" \
      done "Fertig" \
      add "Admin hinzufügen" \
      key "Schlüssel hinzufügen" \
      unkey "Schlüssel entfernen" \
      accept "Unbekannte Schlüssel übernehmen" \
      password "sudo-Passwort ändern" \
      remove "Admin entfernen (sperren)"
    case $choice in
      done) return 0 ;;
      add) _users_add_admin ;;
      key) _users_menu_add_key ;;
      unkey) _users_menu_remove_key ;;
      accept) _users_menu_accept_keys ;;
      password)
        local user
        if _users_choose_admin user "Passwort ändern für:"; then _users_set_password "$user"; fi
        ;;
      remove) _users_menu_remove_admin ;;
    esac
  done
}

_users_check_admins() {
  local -a admins
  mapfile -t admins < <(_users_admins)
  if ((${#admins[@]} == 0)); then
    result_fail "Kein Admin vorhanden (Gruppe $_USERS_GROUP leer) – 'srvctl setup users'"
    return 0
  fi

  local user status file bits fp type comment total unknown weak
  for user in "${admins[@]}"; do
    if ! id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qx sudo; then
      result_warn "$user ist in $_USERS_GROUP, aber nicht in sudo"
    fi
    status=$(_users_password_status "$user")
    if [[ $status != P ]]; then
      result_warn "$user hat kein sudo-Passwort (Status: ${status:-?}) – 'srvctl configure users'"
    fi
    file=$(_users_keyfile "$user")
    total=0 unknown=0 weak=0
    while IFS=$'\t' read -r bits fp type comment; do
      ((++total))
      if [[ $type == DSA ]] || { [[ $type == RSA ]] && ((bits < 3072)); }; then
        result_fail "$user: schwacher Schlüssel $type-$bits $fp (${comment})"
        ((++weak))
      fi
      if ! _users_known_fps "$user" | grep -qxF "$fp"; then
        result_fail "$user: unbekannter Schlüssel $type $fp (${comment}) – nicht über srvctl eingetragen"
        ((++unknown))
      fi
    done < <(_users_file_keys "$file")
    if ((total == 0)); then
      result_fail "$user hat keine SSH-Schlüssel"
    elif ((unknown + weak == 0)); then
      result_ok "$user: $total Schlüssel, alle bekannt"
    fi
    if [[ -e $file ]] && [[ $(stat -c '%U %a' "$file") != "$user 600" ]]; then
      result_warn "$file: Besitzer/Rechte sollten '$user 600' sein"
    fi
  done

  local member
  for member in $(_users_group_members sudo); do
    if [[ " ${admins[*]} " != *" $member "* ]]; then
      result_warn "$member ist in der Gruppe sudo, aber kein srvctl-Admin"
    fi
  done
}

# --- Policies ------------------------------------------------------------------

_users_backup_pam() {
  local file
  for file in $_USERS_PAM_FILES; do
    backup_file "$file"
  done
}

_users_apply_pwquality() {
  write_file "$_USERS_PWQUALITY" 0644 <<<"# ${_USERS_HEADER}
# Lang statt kompliziert (NIST SP 800-63B / BSI): keine Zeichenklassen erzwungen
# Strengere bestehende Werte werden übernommen, nicht abgeschwächt
minlen = $(_users_minlen)
minclass = $(_users_pwq_keep minclass 0)
dcredit = $(_users_pwq_keep dcredit 0)
ucredit = $(_users_pwq_keep ucredit 0)
lcredit = $(_users_pwq_keep lcredit 0)
ocredit = $(_users_pwq_keep ocredit 0)
dictcheck = 1
usercheck = 1
retry = 3
enforce_for_root"
}

_users_apply_faillock() {
  conf_set "$_USERS_FAILLOCK_CONF" deny "$(cfg_get USERS_FAILLOCK_DENY 5)" "="
  conf_set "$_USERS_FAILLOCK_CONF" unlock_time "$(cfg_get USERS_FAILLOCK_UNLOCK 900)" "="
  conf_set "$_USERS_FAILLOCK_CONF" fail_interval 900 "="

  local changed=0
  write_file "$_USERS_PAM_FAILLOCK" 0644 <<<"Name: srvctl: Konto nach Fehlversuchen sperren (pam_faillock authfail)
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail"
  if ((FILE_CHANGED)); then changed=1; fi
  write_file "$_USERS_PAM_FAILLOCK_NOTIFY" 0644 <<<"Name: srvctl: Fehlversuche zählen (pam_faillock preauth/account)
Default: yes
Priority: 1024
Auth-Type: Primary
Auth:
	requisite	pam_faillock.so preauth
Account-Type: Primary
Account:
	required	pam_faillock.so"
  if ((FILE_CHANGED)); then changed=1; fi

  if ((changed)) || ! grep -q 'pam_faillock.so preauth' /etc/pam.d/common-auth; then
    run_cmd pam-auth-update --enable srvctl-faillock srvctl-faillock-notify
    if ((!DRY_RUN)) && ! grep -q 'pam_faillock.so preauth' /etc/pam.d/common-auth; then
      result_fail "pam-auth-update hat pam_faillock nicht aktiviert (lokale Änderungen in /etc/pam.d/common-*?)"
      return 1
    fi
  fi
}

_users_apply_logindefs() {
  conf_set /etc/login.defs UMASK "$(cfg_get USERS_UMASK 027)"
  local mode
  mode=$(conf_get /etc/login.defs HOME_MODE 2>/dev/null) || mode=""
  if [[ $mode != 0700 && $mode != 0750 ]]; then
    conf_set /etc/login.defs HOME_MODE 0750
  fi
  if [[ $(conf_get /etc/login.defs ENCRYPT_METHOD 2>/dev/null) != YESCRYPT ]]; then
    conf_set /etc/login.defs ENCRYPT_METHOD YESCRYPT
  fi
  write_file "$_USERS_UMASK_PROFILE" 0644 <<<"# ${_USERS_HEADER}
umask $(cfg_get USERS_UMASK 027)"
}

_users_apply_sudo() {
  local content tmp
  content="# ${_USERS_HEADER}
Defaults	use_pty
Defaults	logfile=\"/var/log/sudo.log\"
Defaults	timestamp_timeout=$(cfg_get USERS_SUDO_TIMEOUT 5)
Defaults	passwd_tries=3"
  tmp=$(mktemp "${RUN_DIR}/sudoers.XXXXXX")
  printf '%s\n' "$content" >"$tmp"
  if ! visudo -cqf "$tmp" >/dev/null 2>&1; then
    rm -f -- "$tmp"
    result_fail "sudoers-Datei ist ungültig (visudo) – nicht geschrieben"
    return 1
  fi
  rm -f -- "$tmp"
  write_file "$_USERS_SUDOERS" 0440 root:root <<<"$content"
}

_users_apply_su() {
  local file=/etc/pam.d/su
  [[ -f $file ]] || return 0
  if grep -qE '^auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*group=sudo' "$file"; then
    return 0
  fi
  if grep -qE '^#[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so[[:space:]]*$' "$file"; then
    file_sed "$file" 's/^#[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so[[:space:]]*$/auth       required   pam_wheel.so use_uid group=sudo/'
  else
    file_sed "$file" 's/^(auth[[:space:]]+sufficient[[:space:]]+pam_rootok\.so.*)$/\1\nauth       required   pam_wheel.so use_uid group=sudo/'
  fi
  result_ok "su ist auf die Gruppe sudo beschränkt"
}

_users_apply_policies() {
  _users_apply_pwquality
  _users_apply_faillock
  _users_apply_logindefs
  _users_apply_sudo
  _users_apply_su
  result_ok "Richtlinien angewendet (Passwörter ≥ $(_users_minlen) Zeichen, Sperre nach Fehlversuchen, sudo-Protokoll, umask $(cfg_get USERS_UMASK 027))"
}

_users_check_policies() {
  if [[ -f $_USERS_PWQUALITY ]] && grep -qE "^minlen = $(_users_minlen)$" "$_USERS_PWQUALITY" &&
    grep -q pam_pwquality /etc/pam.d/common-password; then
    result_ok "Passwortregeln aktiv (mindestens $(_users_minlen) Zeichen, Wörterbuchprüfung)"
  else
    result_fail "Passwortregeln (pam_pwquality) nicht aktiv"
  fi
  if grep -q 'pam_unix.so.*yescrypt' /etc/pam.d/common-password &&
    [[ $(conf_get /etc/login.defs ENCRYPT_METHOD 2>/dev/null) == YESCRYPT ]]; then
    result_ok "Passwort-Hashes: yescrypt"
  else
    result_warn "Passwort-Hashverfahren ist nicht yescrypt"
  fi
  if grep -q 'pam_faillock.so preauth' /etc/pam.d/common-auth &&
    grep -q 'pam_faillock.so authfail' /etc/pam.d/common-auth; then
    result_ok "Kontosperre nach $(cfg_get USERS_FAILLOCK_DENY 5) Fehlversuchen aktiv (pam_faillock)"
  else
    result_fail "Kontosperre nach Fehlversuchen (pam_faillock) nicht aktiv"
  fi
  if grep -q 'pam_tmpdir' /etc/pam.d/common-session 2>/dev/null; then
    result_ok "Eigenes Temp-Verzeichnis pro Benutzer (pam_tmpdir)"
  else
    result_warn "pam_tmpdir nicht aktiv (gemeinsames /tmp für alle Sitzungen) – 'srvctl setup users'"
  fi
  if [[ $(conf_get /etc/login.defs UMASK 2>/dev/null) == "$(cfg_get USERS_UMASK 027)" && -f $_USERS_UMASK_PROFILE ]]; then
    result_ok "Standard-umask $(cfg_get USERS_UMASK 027)"
  else
    result_warn "Standard-umask ist nicht $(cfg_get USERS_UMASK 027)"
  fi

  if ! pkg_installed sudo; then
    result_fail "sudo ist nicht installiert"
  elif [[ -f $_USERS_SUDOERS ]] && grep -q 'logfile=' "$_USERS_SUDOERS"; then
    result_ok "sudo: Protokoll, use_pty, Passwort-Zeitfenster $(cfg_get USERS_SUDO_TIMEOUT 5) min"
  else
    result_warn "sudo-Härtung ($_USERS_SUDOERS) fehlt"
  fi
  # NOPASSWD for root itself is harmless (e.g. cloud-init's 90-cloud-init-users)
  local nopasswd
  nopasswd=$(awk '/^[^#]*NOPASSWD/ && $1 != "root" { print FILENAME; nextfile }' \
    /etc/sudoers /etc/sudoers.d/* 2>/dev/null | paste -sd ' ')
  if [[ -n $nopasswd ]]; then
    result_warn "sudo ohne Passwort (NOPASSWD) erlaubt in: $nopasswd"
  fi

  if grep -qE '^auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*group=sudo' /etc/pam.d/su 2>/dev/null; then
    result_ok "su nur für die Gruppe sudo"
  else
    result_warn "su ist für alle Benutzer erlaubt (pam_wheel fehlt)"
  fi
}

# --- root ----------------------------------------------------------------------

_users_check_root() {
  case $(_users_password_status root) in
    L) result_ok "root-Passwort ist gesperrt" ;;
    NP) result_fail "root hat kein Passwort (leer)" ;;
    *) result_warn "root-Passwort ist aktiv – wird gesperrt, sobald ein Admin mit Passwort und Schlüssel existiert" ;;
  esac
}

_users_apply_root() {
  if [[ $(_users_password_status root) == L ]]; then
    return 0
  fi
  local ready
  ready=$(_users_ready_admins | paste -sd ' ')
  if [[ -z $ready ]] && ((!DRY_RUN)); then
    result_warn "root-Passwort bleibt aktiv, bis ein Admin mit Passwort und bekanntem Schlüssel existiert"
    return 0
  fi
  run_cmd passwd --lock root
  write_file "$(state_path users root-locked)" 0600 <<<"$RUN_ID"
  result_ok "root-Passwort gesperrt (root nur noch über sudo; Admins: ${ready:-neuer Admin})"
}

# --- Account hygiene -----------------------------------------------------------

_users_empty_passwords() { awk -F: '$2 == "" { print $1 }' /etc/shadow; }

# System accounts (UID 1-999) with a login shell. Accounts that need their
# shell stay out: with SSH keys (e.g. git for Gitea), in SSH_ALLOW_GROUPS or
# listed in USERS_SHELL_OK (default: postgres).
_users_system_shells() {
  local user home ok groups
  ok=" $(cfg_get USERS_SHELL_OK "postgres") "
  groups=$(cfg_get SSH_ALLOW_GROUPS "")
  awk -F: '$3 > 0 && $3 < 1000 && $1 !~ /^(sync|shutdown|halt)$/ &&
    $7 !~ /(nologin|false)$/ && $7 != "" { print $1 ":" $6 }' /etc/passwd |
    while IFS=: read -r user home; do
      [[ $ok == *" $user "* ]] && continue
      [[ -s $home/.ssh/authorized_keys ]] && continue
      if [[ -n $groups ]] && id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qxF -f <(tr ' ' '\n' <<<"$groups"); then
        continue
      fi
      echo "$user"
    done
}

# System accounts that keep their shell (for the pre-check)
_users_system_shells_kept() {
  comm -23 <(awk -F: '$3 > 0 && $3 < 1000 && $1 !~ /^(sync|shutdown|halt)$/ &&
    $7 !~ /(nologin|false)$/ && $7 != "" { print $1 }' /etc/passwd | sort) <(_users_system_shells | sort)
}

# Home directories of regular users accessible by others or writable by group
_users_open_homes() {
  local user uid home mode
  while IFS=: read -r user _ uid _ _ home _; do
    ((uid >= 1000 && uid < 65534)) || continue
    [[ -d $home ]] || continue
    mode=$(stat -c '%a' "$home")
    (((8#$mode & 8#027) != 0)) || continue
    _users_home_serves_web "$user" "$home" && continue
    echo "$user:$home:$mode"
  done </etc/passwd
}

# Homes a web server reads from (public_html etc., group www-data) or listed
# in USERS_HOME_OPEN_OK stay accessible
_users_home_serves_web() {
  local user=$1 home=$2 dir
  [[ " $(cfg_get USERS_HOME_OPEN_OK "") " == *" $user "* ]] && return 0
  [[ $(stat -c '%G' "$home") == www-data ]] && return 0
  for dir in public_html www htdocs web; do
    [[ -d $home/$dir ]] && return 0
  done
  return 1
}

_users_check_accounts() {
  local list
  list=$(_users_empty_passwords | paste -sd ' ')
  if [[ -n $list ]]; then result_fail "Konten mit leerem Passwort: $list"; fi
  list=$(awk -F: '$3 == 0 && $1 != "root" { print $1 }' /etc/passwd | paste -sd ' ')
  if [[ -n $list ]]; then result_fail "Weitere Konten mit UID 0: $list"; fi
  list=$(cut -d: -f3 /etc/passwd | sort | uniq -d | paste -sd ' ')
  if [[ -n $list ]]; then result_fail "Doppelte UIDs: $list"; fi
  list=$(cut -d: -f1 /etc/passwd | sort | uniq -d | paste -sd ' ')
  if [[ -n $list ]]; then result_fail "Doppelte Benutzernamen: $list"; fi
  list=$(cut -d: -f3 /etc/group | sort | uniq -d | paste -sd ' ')
  if [[ -n $list ]]; then result_fail "Doppelte GIDs: $list"; fi
  list=$(_users_system_shells | paste -sd ' ')
  if [[ -n $list ]]; then result_warn "Systemkonten mit Login-Shell: $list"; fi
  list=$(_users_open_homes | cut -d: -f1,3 | paste -sd ' ')
  if [[ -n $list ]]; then result_warn "Home-Verzeichnisse für andere zugänglich (Benutzer:Rechte): $list"; fi
}

_users_fix_accounts() {
  local -a items
  local item

  mapfile -t items < <(_users_empty_passwords)
  if ((${#items[@]})) && confirm "Konten mit leerem Passwort sperren: ${items[*]}?"; then
    for item in "${items[@]}"; do run_cmd passwd --lock "$item"; done
    result_ok "Gesperrt: ${items[*]}"
  fi

  mapfile -t items < <(_users_system_shells)
  if ((${#items[@]})) && confirm "Systemkonten ohne Login-Shell setzen (nologin): ${items[*]}?"; then
    for item in "${items[@]}"; do run_cmd usermod --shell /usr/sbin/nologin "$item"; done
    result_ok "Login-Shell entfernt: ${items[*]}"
  fi

  mapfile -t items < <(_users_open_homes)
  if ((${#items[@]})) && confirm "Home-Verzeichnisse auf 750 beschränken: ${items[*]%%:*}?"; then
    for item in "${items[@]}"; do
      item=${item#*:}
      run_cmd chmod g-w,o-rwx "${item%:*}"
    done
    result_ok "Home-Verzeichnisse beschränkt"
  fi
}

# --- Pre-check against the existing system ----------------------------------------

users::precheck() {
  local key existing kept="" list
  for key in minlen minclass dcredit ucredit lcredit ocredit; do
    existing=$(_users_pwq_existing "$key")
    [[ -n $existing ]] || continue
    if [[ $key == minlen ]]; then
      [[ $existing =~ ^[0-9]+$ ]] && ((existing > $(cfg_get USERS_PASS_MINLEN 14))) && kept+="$key=$existing "
    elif [[ $(_users_pwq_keep "$key" 0) == "$existing" && $existing != 0 ]]; then
      kept+="$key=$existing "
    fi
  done
  if [[ -n $kept ]]; then
    precheck_info "Strengere bestehende Passwortregeln bleiben: ${kept% }"
  fi
  list=$(_users_system_shells_kept | paste -sd ' ')
  if [[ -n $list ]]; then
    precheck_info "Dienstkonten behalten ihre Shell (SSH-Schlüssel, SSH_ALLOW_GROUPS oder USERS_SHELL_OK): $list"
  fi
  local user home others=()
  while IFS=: read -r user _ _ _ _ home _; do
    [[ -d $home ]] || continue
    _users_home_serves_web "$user" "$home" && others+=("$user")
  done < <(awk -F: '$3 >= 1000 && $3 < 65534' /etc/passwd)
  if ((${#others[@]})); then
    precheck_info "Home-Verzeichnisse mit Webinhalten bleiben zugänglich: ${others[*]}"
  fi
  local sudoers admins
  admins=" $(_users_admins | paste -sd ' ') "
  sudoers=$(_users_group_members sudo | while read -r user; do [[ $admins == *" $user "* ]] || echo "$user"; done | paste -sd ' ')
  if [[ -n $sudoers ]]; then
    precheck_info "Bestehende sudo-Benutzer ($sudoers) bleiben unverändert – als srvctl-Admin übernehmen: 'srvctl configure users' → Admin hinzufügen (Passwort kann bleiben)"
  fi
  local su_users
  su_users=$(awk -F: '$3 >= 1000 && $3 < 65534 && $7 !~ /(nologin|false)$/ { print $1 }' /etc/passwd |
    while read -r user; do id -nG "$user" | tr ' ' '\n' | grep -qx sudo || echo "$user"; done | paste -sd ' ')
  if [[ -n $su_users ]] && ! grep -qE '^auth[[:space:]]+required[[:space:]]+pam_wheel' /etc/pam.d/su 2>/dev/null; then
    precheck_warn "su ist danach nur noch für die Gruppe sudo erlaubt – betroffen: $su_users"
  fi
}

# --- Actions -------------------------------------------------------------------

users::check() {
  _users_check_admins
  _users_check_root
  _users_check_policies
  _users_check_accounts
}

users::setup() {
  _users_backup_pam
  pkg_install sudo libpam-pwquality libpwquality-tools cracklib-runtime libpam-tmpdir
  _users_apply_policies

  local ready
  ready=$(_users_ready_admins | paste -sd ' ')
  if [[ -n $ready ]]; then
    result_ok "Admin(s) vorhanden: $ready – weitere über 'srvctl configure users'"
  elif has_tty; then
    _users_add_admin
  else
    result_fail "Kein Admin vorhanden – 'srvctl setup users' im Terminal ausführen (Eingaben nötig)"
    return 1
  fi
  _users_apply_root
}

users::configure() {
  if ((!DRY_RUN)); then
    local pkg
    for pkg in sudo libpam-pwquality; do
      if ! pkg_installed "$pkg"; then
        result_fail "Paket $pkg fehlt – zuerst 'srvctl setup users'"
        return 1
      fi
    done
  fi
  _users_backup_pam
  _users_apply_policies
  _users_fix_accounts
  if has_tty && ((!ASSUME_YES && !DRY_RUN)); then
    _users_menu
  fi
  _users_apply_root
}

# Restores the changed files (default rollback) and unlocks root again if
# srvctl locked it. Created admins and password changes are not reverted.
users::rollback() {
  local locked=0
  if [[ -f $(state_path users root-locked) ]]; then locked=1; fi
  backup_restore_module users
  if ((locked)) && [[ ! -f $(state_path users root-locked) ]]; then
    run_cmd passwd --unlock root
    result_ok "root-Passwort wieder entsperrt"
  fi
}
