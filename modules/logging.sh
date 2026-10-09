# shellcheck shell=bash
# logging - persistent journald with retention, auditd with a CIS-based rule
# set (optionally immutable), audit=1 at boot, log rotation for srvctl and sudo.
# Decisions: docs/PLAN.md, section "8. logging".

MODULE_NAME="logging"
MODULE_DESC="Protokollierung: journald dauerhaft, auditd mit CIS-Regeln, Logrotation"
MODULE_DEPENDS=()

readonly _LOG_JOURNALD=/etc/systemd/journald.conf.d/srvctl.conf
readonly _LOG_AUDIT_RULES=/etc/audit/rules.d/50-srvctl.rules
readonly _LOG_AUDIT_FINAL=/etc/audit/rules.d/99-srvctl-finalize.rules
readonly _LOG_AUDITD_CONF=/etc/audit/auditd.conf
readonly _LOG_GRUB=/etc/default/grub.d/srvctl-audit.cfg
readonly _LOG_LOGROTATE=/etc/logrotate.d/srvctl
readonly _LOG_HEADER="Verwaltet von srvctl (Modul: logging) – manuelle Änderungen werden überschrieben"
readonly _LOG_KEYS="time-change identity system-locale scope sshd logins session perm_mod access mounts delete kernel_modules MAC-policy privileged user_emulation"

# --- Configuration -------------------------------------------------------------

_log_retention() { cfg_get LOGGING_RETENTION 90d; }
_log_max_use() { cfg_get LOGGING_MAX_USE 1G; }
_log_immutable() { [[ $(cfg_get LOGGING_AUDIT_IMMUTABLE 0) == 1 ]]; }

_log_validate() {
  local ok=0
  [[ $(_log_retention) =~ ^[0-9]+(d|week|month|year)$ ]] || {
    result_fail "LOGGING_RETENTION: '$(_log_retention)' ist ungültig (z. B. 90d)"
    ok=1
  }
  [[ $(_log_max_use) =~ ^[0-9]+[KMG]$ ]] || {
    result_fail "LOGGING_MAX_USE: '$(_log_max_use)' ist ungültig (z. B. 1G)"
    ok=1
  }
  return "$ok"
}

# --- Audit rules ---------------------------------------------------------------

# _log_syscall_rule ARGS... - prints the rule for b64 and, on x86_64, b32
_log_syscall_rule() {
  echo "-a always,exit -F arch=b64 $*"
  if [[ $(uname -m) == x86_64 ]]; then
    echo "-a always,exit -F arch=b32 $*"
  fi
}

# _log_watch PATH PERMS KEY - watch only paths that exist
_log_watch() {
  [[ -e $1 ]] && echo "-w $1 -p $2 -k $3"
  return 0
}

_log_audit_rules() {
  local path user="-F auid>=1000 -F auid!=unset"
  echo "# ${_LOG_HEADER}"
  echo "# CIS-basierter Regelsatz; Suche z. B. mit: ausearch -k identity"
  echo
  echo "## Zeit"
  _log_syscall_rule "-S adjtimex,settimeofday,clock_settime -k time-change"
  _log_watch /etc/localtime wa time-change
  echo "## Benutzer, Gruppen, Passwörter, PAM"
  for path in /etc/group /etc/passwd /etc/gshadow /etc/shadow /etc/security/opasswd /etc/nsswitch.conf /etc/pam.conf /etc/pam.d /etc/security; do
    _log_watch "$path" wa identity
  done
  echo "## Netzwerk und Rechnername"
  _log_syscall_rule "-S sethostname,setdomainname -k system-locale"
  for path in /etc/issue /etc/issue.net /etc/hosts /etc/hostname /etc/network /etc/systemd/network /etc/netplan /etc/nftables.conf /etc/srvctl; do
    _log_watch "$path" wa system-locale
  done
  echo "## sudo"
  _log_watch /etc/sudoers wa scope
  _log_watch /etc/sudoers.d wa scope
  _log_watch /var/log/sudo.log wa scope
  echo "## SSH"
  _log_watch /etc/ssh/sshd_config wa sshd
  _log_watch /etc/ssh/sshd_config.d wa sshd
  echo "## Anmeldungen und Sitzungen"
  _log_watch /var/log/lastlog wa logins
  _log_watch /var/run/faillock wa logins
  _log_watch /var/run/utmp wa session
  _log_watch /var/log/wtmp wa session
  _log_watch /var/log/btmp wa session
  echo "## Rechteänderungen durch Benutzer"
  _log_syscall_rule "-S chmod,fchmod,fchmodat $user -k perm_mod"
  _log_syscall_rule "-S chown,fchown,lchown,fchownat $user -k perm_mod"
  _log_syscall_rule "-S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr $user -k perm_mod"
  echo "## Verweigerte Dateizugriffe"
  _log_syscall_rule "-S creat,open,openat,truncate,ftruncate -F exit=-EACCES $user -k access"
  _log_syscall_rule "-S creat,open,openat,truncate,ftruncate -F exit=-EPERM $user -k access"
  echo "## Mounts und Löschungen durch Benutzer"
  _log_syscall_rule "-S mount $user -k mounts"
  _log_syscall_rule "-S unlink,unlinkat,rename,renameat $user -k delete"
  echo "## Kernelmodule"
  _log_syscall_rule "-S init_module,finit_module,delete_module -k kernel_modules"
  _log_watch /usr/bin/kmod x kernel_modules
  echo "## AppArmor"
  _log_watch /etc/apparmor wa MAC-policy
  _log_watch /etc/apparmor.d wa MAC-policy
  echo "## Befehle mit fremder Identität (sudo -u, su)"
  _log_syscall_rule "-C euid!=uid -F auid!=unset -S execve -k user_emulation"
  echo "## Privilegierte Programme (setuid/setgid)"
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort | while IFS= read -r path; do
    echo "-a always,exit -F path=${path} -F perm=x $user -k privileged"
  done
}

# Audit status: "enabled" value (0 off, 1 on, 2 immutable)
_log_audit_enabled() { auditctl -s 2>/dev/null | awk '$1 == "enabled" { print $2 }'; }

# --- Checks --------------------------------------------------------------------

_log_check_journald() {
  if [[ -f $_LOG_JOURNALD ]] && grep -q "^MaxRetentionSec=$(_log_retention)$" "$_LOG_JOURNALD"; then
    result_ok "journald: dauerhaft, $(_log_retention) Aufbewahrung, max. $(_log_max_use) ($(journalctl --disk-usage 2>/dev/null | grep -oE '[0-9.]+[KMGT]?B?' | head -n 1) belegt)"
  else
    result_warn "journald-Aufbewahrung nicht eingerichtet ($_LOG_JOURNALD)"
  fi
  if [[ ! -d /var/log/journal ]]; then
    result_fail "journald speichert nicht dauerhaft (/var/log/journal fehlt) – Logs gehen beim Neustart verloren"
  fi
}

_log_check_audit() {
  if ! pkg_installed auditd; then
    result_fail "auditd ist nicht installiert – 'srvctl setup logging'"
    return 0
  fi
  check_service auditd
  local enabled count key missing=()
  enabled=$(_log_audit_enabled)
  local loaded
  loaded=$(auditctl -l 2>/dev/null)
  # Watches are listed as "-k KEY", syscall rules as "-F key=KEY"
  count=$(grep -cE '(-k |key=)[^ ]+$' <<<"$loaded")
  for key in $_LOG_KEYS; do
    grep -qE "(-k |key=)${key}\$" <<<"$loaded" || missing+=("$key")
  done
  if ((${#missing[@]})); then
    result_warn "Audit-Regeln fehlen: ${missing[*]} ($count Regeln geladen)"
  else
    result_ok "Audit-Regeln aktiv ($count Regeln, alle Kategorien)"
  fi
  case $enabled in
    2) result_ok "Audit-Regeln unveränderbar (-e 2) – Änderungen erst nach Neustart" ;;
    1)
      if _log_immutable; then
        result_warn "Audit-Regeln sollen unveränderbar sein, sind es aber noch nicht (Neustart nötig)"
      else
        result_ok "Audit-Regeln änderbar (LOGGING_AUDIT_IMMUTABLE=0)"
      fi
      ;;
    *) result_fail "Kernel-Auditing ist aus (auditctl -s: enabled ${enabled:-?})" ;;
  esac
  if [[ " $(</proc/cmdline) " == *" audit=1 "* ]]; then
    result_ok "Auditing ab dem Systemstart (audit=1)"
  else
    result_warn "Prozesse vor dem Start von auditd werden nicht erfasst (audit=1 fehlt – wirkt nach 'configure' und Neustart)"
  fi
}

_log_check_rotation() {
  if [[ -f $_LOG_LOGROTATE ]]; then
    result_ok "Logrotation für srvctl.log und sudo.log"
  else
    result_warn "Keine Logrotation für srvctl.log und sudo.log ($_LOG_LOGROTATE)"
  fi
  local file mode bad=()
  for file in /var/log/srvctl.log /var/log/sudo.log; do
    [[ -f $file ]] || continue
    mode=$(stat -c '%a' "$file")
    (((8#$mode & 8#037) == 0)) || bad+=("$file ($mode)")
  done
  # The directory is excluded from AIDE (its timestamps change on rotation),
  # so its ownership and mode are checked here.
  if [[ -d /var/log/audit ]]; then
    mode=$(stat -c '%U %a' /var/log/audit)
    [[ $mode == "root 700" || $mode == "root 750" ]] || bad+=("/var/log/audit ($mode)")
  fi
  if ((${#bad[@]})); then
    result_warn "Logdateien zu offen: ${bad[*]}"
  fi
}

# --- Apply ---------------------------------------------------------------------

_log_apply_journald() {
  write_file "$_LOG_JOURNALD" 0644 <<<"# ${_LOG_HEADER}
[Journal]
Storage=persistent
Compress=yes
SystemMaxUse=$(_log_max_use)
MaxRetentionSec=$(_log_retention)"
  if ((FILE_CHANGED)); then
    if [[ ! -d /var/log/journal ]]; then
      run_cmd install -d -m 2755 -g systemd-journal /var/log/journal
    fi
    run_cmd systemctl restart systemd-journald
    run_cmd journalctl --flush
    result_ok "journald: dauerhaft, $(_log_retention) Aufbewahrung, max. $(_log_max_use)"
  fi
}

_log_apply_audit() {
  local changed=0 rules
  conf_set "$_LOG_AUDITD_CONF" max_log_file "$(cfg_get LOGGING_AUDIT_LOG_MB 50)" " = "
  if ((FILE_CHANGED)); then changed=1; fi
  conf_set "$_LOG_AUDITD_CONF" num_logs "$(cfg_get LOGGING_AUDIT_LOG_FILES 10)" " = "
  if ((FILE_CHANGED)); then changed=1; fi
  if ((changed)); then svc_restart auditd; fi

  rules=$(_log_audit_rules)
  write_file "$_LOG_AUDIT_RULES" 0640 <<<"$rules"
  if ((FILE_CHANGED)); then changed=1; fi

  if _log_immutable; then
    write_file "$_LOG_AUDIT_FINAL" 0640 <<<"# ${_LOG_HEADER}
# Regeln bis zum nächsten Neustart unveränderbar (auch für root)
-e 2"
    if ((FILE_CHANGED)); then changed=1; fi
  elif [[ -f $_LOG_AUDIT_FINAL ]]; then
    backup_file "$_LOG_AUDIT_FINAL"
    run_cmd rm -f -- "$_LOG_AUDIT_FINAL"
    changed=1
  fi

  ((changed)) || return 0
  if [[ $(_log_audit_enabled) == 2 ]] && ((!DRY_RUN)); then
    result_warn "Audit-Regeln sind derzeit unveränderbar – die neuen Regeln gelten nach dem nächsten Neustart"
    return 0
  fi
  run_cmd augenrules --load
  result_ok "Audit-Regeln geladen ($(grep -c '^-[aw]' <<<"$rules") Regeln)"
}

_log_apply_boot() {
  if [[ ! -f /etc/default/grub ]] || ! cmd_exists update-grub; then
    log_info "Kein GRUB gefunden – audit=1 wird nicht gesetzt"
    return 0
  fi
  write_file "$_LOG_GRUB" 0644 <<<"# ${_LOG_HEADER}
# Auditing ab dem Systemstart, größerer Puffer für Ereignisse vor auditd
GRUB_CMDLINE_LINUX=\"\$GRUB_CMDLINE_LINUX audit=1 audit_backlog_limit=8192\""
  if ((FILE_CHANGED)); then
    run_cmd update-grub
    result_ok "audit=1 für den Systemstart gesetzt (wirkt nach dem nächsten Neustart)"
  fi
}

_log_apply_rotation() {
  write_file "$_LOG_LOGROTATE" 0644 <<<"# ${_LOG_HEADER}
/var/log/srvctl.log /var/log/sudo.log {
	monthly
	rotate 12
	compress
	delaycompress
	missingok
	notifempty
	create 0640 root adm
}"
  local file
  for file in /var/log/srvctl.log /var/log/sudo.log; do
    if [[ -f $file ]] && (((8#$(stat -c '%a' "$file") & 8#037) != 0)); then
      run_cmd chmod 0640 "$file"
    fi
  done
}

# --- Actions -------------------------------------------------------------------

logging::check() {
  _log_validate || return 0
  _log_check_journald
  _log_check_audit
  _log_check_rotation
}

logging::setup() {
  _log_validate || return 1
  pkg_install auditd logrotate
  logging::configure
}

logging::configure() {
  _log_validate || return 1
  if ((!DRY_RUN)) && ! pkg_installed auditd; then
    result_fail "auditd ist nicht installiert – zuerst 'srvctl setup logging'"
    return 1
  fi
  _log_apply_journald
  if pkg_installed auditd; then
    _log_apply_audit
  else
    log_dry "Audit-Regeln werden nach der Installation von auditd geladen"
  fi
  _log_apply_boot
  _log_apply_rotation
}

logging::rollback() {
  backup_restore_module logging
  run_cmd systemctl restart systemd-journald
  if pkg_installed auditd && [[ $(_log_audit_enabled) != 2 ]]; then
    run_cmd augenrules --load
  fi
  if cmd_exists update-grub; then run_cmd update-grub; fi
}
