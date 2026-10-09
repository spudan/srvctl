# shellcheck shell=bash
# Example module - template for new modules. Harmless: it only performs
# read-only checks and manages EXAMPLE_CONF_FILE (/etc/srvctl/example.conf).
#
# Rules for modules:
# - Function names are <module>::<action>; all actions are optional.
# - setup/configure must be idempotent (safe to run repeatedly).
# - setup/configure/rollback run with errexit: the first failing command aborts.
#   Use "if"/"||" for commands that may fail on purpose.
# - Report results with result_ok/result_warn/result_fail/result_skip.
# - Change files only via write_file/conf_set/ensure_line (backup + dry-run)
#   and run commands via run_cmd.
# - Do not call "exit"; use "return".

MODULE_NAME="example"
MODULE_DESC="Beispielmodul (Vorlage für eigene Module)"
MODULE_DEPENDS=()

example::check() {
  local warn fail usage file greeting
  warn=$(cfg_get EXAMPLE_DISK_WARN 80)
  fail=$(cfg_get EXAMPLE_DISK_FAIL 90)
  usage=$(df --output=pcent / | tail -n 1 | tr -dc '0-9')
  if ((usage >= fail)); then
    result_fail "Root-Dateisystem zu ${usage}% belegt (Grenze ${fail}%)"
  elif ((usage >= warn)); then
    result_warn "Root-Dateisystem zu ${usage}% belegt (Warnung ab ${warn}%)"
  else
    result_ok "Root-Dateisystem zu ${usage}% belegt"
  fi

  if [[ $(timedatectl show -p NTPSynchronized --value 2>/dev/null) == yes ]]; then
    result_ok "Systemzeit ist per NTP synchronisiert"
  else
    result_warn "Systemzeit ist nicht per NTP synchronisiert"
  fi

  file=$(cfg_get EXAMPLE_CONF_FILE /etc/srvctl/example.conf)
  greeting=$(cfg_get EXAMPLE_GREETING "Hallo")
  if [[ -f $file ]]; then
    check_conf "$file" GREETING "$greeting" "="
  else
    result_warn "$file fehlt – 'srvctl setup example' ausführen"
  fi
}

example::setup() {
  local file content
  file=$(cfg_get EXAMPLE_CONF_FILE /etc/srvctl/example.conf)
  content=$(template_render "${SRVCTL_ROOT}/templates/example/example.conf.tpl")

  if [[ -f $file ]]; then
    result_ok "$file ist bereits vorhanden"
    return 0
  fi
  write_file "$file" 0644 <<<"$content"
  result_ok "$file angelegt"
}

example::configure() {
  local file greeting
  file=$(cfg_get EXAMPLE_CONF_FILE /etc/srvctl/example.conf)
  greeting=$(cfg_get EXAMPLE_GREETING "Hallo")

  if [[ ! -f $file ]]; then
    result_fail "$file fehlt – zuerst 'srvctl setup example' ausführen"
    return 1
  fi

  conf_set "$file" GREETING "$greeting" "="
  if ((FILE_CHANGED)); then
    result_ok "GREETING auf '$greeting' gesetzt"
  else
    result_ok "GREETING ist bereits '$greeting'"
  fi
}

# No example::rollback defined: the framework restores the files this module
# changed in its last run. Define it to add custom steps, e.g.:
#   example::rollback() { backup_restore_module example; svc_reload foo; }
