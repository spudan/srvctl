# shellcheck shell=bash
# apparmor - AppArmor active, profiles of server services in enforce mode,
# publicly listening services without a profile are reported.
# Decisions: docs/PLAN.md, section "9. apparmor".
#
# apparmor-profiles-extra is not installed: for Debian 13 it only contains
# desktop programs. Server profiles come with the service packages.

MODULE_NAME="apparmor"
MODULE_DESC="AppArmor: aktiv, Profile im Enforce-Modus, ungeschützte Dienste melden"
MODULE_DEPENDS=()

# --- Configuration -------------------------------------------------------------

_aa_enforce_list() { cfg_get APPARMOR_ENFORCE ""; }

# Processes that may listen publicly without a profile (sshd has to start
# arbitrary shells, so Debian ships no enforcing profile for it)
_aa_unconfined_ok() { cfg_get APPARMOR_UNCONFINED_OK "sshd"; }

_aa_validate() {
  local ok=0 name
  for name in $(_aa_enforce_list); do
    if [[ ! $name =~ ^[A-Za-z0-9._-]+$ ]]; then
      result_fail "APPARMOR_ENFORCE: '$name' ist kein Profilname (Datei in /etc/apparmor.d)"
      ok=1
    elif [[ ! -f /etc/apparmor.d/$name ]]; then
      result_warn "APPARMOR_ENFORCE: Profil /etc/apparmor.d/$name gibt es nicht"
    fi
  done
  return "$ok"
}

# --- Helpers -------------------------------------------------------------------

# Profile modes as "MODE NAME" lines (aa-status --json)
_aa_profiles() {
  aa-status --json 2>/dev/null | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
except ValueError:
    sys.exit(0)
for name, mode in sorted((data.get("profiles") or {}).items()):
    print(mode, name)
' 2>/dev/null
}

# _aa_confinement PID - "unconfined", "enforce", "complain", ... of a process
_aa_confinement() {
  local label
  label=$(cat "/proc/$1/attr/apparmor/current" 2>/dev/null || cat "/proc/$1/attr/current" 2>/dev/null)
  case $label in
    "" | unconfined) echo unconfined ;;
    *"(enforce)"*) echo enforce ;;
    *"(complain)"*) echo complain ;;
    *"(kill)"*) echo kill ;;
    *) echo "${label##* }" | tr -d '()' ;;
  esac
}

# _aa_profile_mode FILE - mode of the profile defined in /etc/apparmor.d/FILE
_aa_profile_mode() {
  local file=/etc/apparmor.d/$1 name
  # Profile name: "profile NAME" or the path in the first rule header
  name=$(grep -m1 -oE '^\s*(profile\s+[^ {]+|/[^ {]+)' "$file" 2>/dev/null | awk '{ print $NF }')
  [[ -n $name ]] || return 0
  _aa_profiles | awk -v n="$name" '$2 == n { print $1; exit }'
}

# --- Checks --------------------------------------------------------------------

_aa_check_active() {
  if [[ $(aa-enabled 2>/dev/null) == Yes ]] ||
    [[ $(cat /sys/module/apparmor/parameters/enabled 2>/dev/null) == Y ]]; then
    result_ok "AppArmor ist im Kernel aktiv"
  else
    result_fail "AppArmor ist nicht aktiv"
    return 1
  fi
  if ! svc_is_enabled apparmor; then
    result_warn "apparmor.service ist nicht aktiviert – Profile fehlen nach einem Neustart"
  fi
  if ! pkg_installed apparmor-utils; then
    result_warn "apparmor-utils fehlt (aa-status, aa-enforce) – 'srvctl setup apparmor'"
  fi
}

_aa_check_profiles() {
  local profiles enforce complain
  profiles=$(_aa_profiles)
  enforce=$(grep -c '^enforce ' <<<"$profiles")
  complain=$(grep -c '^complain ' <<<"$profiles")
  result_ok "Profile: $enforce im Enforce-Modus, $complain im Complain-Modus (Details: aa-status)"

  local name mode
  for name in $(_aa_enforce_list); do
    [[ -f /etc/apparmor.d/$name ]] || continue
    mode=$(_aa_profile_mode "$name")
    if [[ $mode == enforce ]]; then
      result_ok "Profil $name: enforce"
    else
      result_warn "Profil $name: ${mode:-nicht geladen} (soll enforce sein) – 'srvctl configure apparmor'"
    fi
  done
}

_aa_check_listeners() {
  local proto port proc pid addr mode ok_list
  local -A seen=()
  ok_list=" $(_aa_unconfined_ok) "
  while read -r proto port proc pid addr; do
    [[ -n ${seen[$proc]:-} ]] && continue
    seen[$proc]=1
    mode=$(_aa_confinement "$pid")
    case $mode in
      enforce) result_ok "$proc (öffentlich auf $proto/$port) ist durch AppArmor eingeschränkt" ;;
      unconfined)
        if [[ $ok_list == *" $proc "* ]]; then
          continue
        fi
        result_warn "$proc lauscht öffentlich auf $proto/$port ohne AppArmor-Profil"
        ;;
      *) result_warn "$proc lauscht öffentlich auf $proto/$port, Profil nur im Modus '$mode'" ;;
    esac
  done < <(net_listeners)
}

# --- Apply ---------------------------------------------------------------------

_aa_apply_enforce() {
  local name mode state content="" changed=()
  state=$(state_path apparmor enforced)
  [[ -r $state ]] && content=$(<"$state")$'\n'
  for name in $(_aa_enforce_list); do
    [[ -f /etc/apparmor.d/$name ]] || continue
    mode=$(_aa_profile_mode "$name")
    [[ $mode == enforce ]] && continue
    run_cmd aa-enforce "/etc/apparmor.d/$name"
    changed+=("$name")
    content+="${name}"$'\n'
  done
  ((${#changed[@]})) || return 0
  write_file "$state" 0600 <<<"$(grep . <<<"$content" | sort -u)"
  result_ok "Auf enforce gestellt: ${changed[*]}"
}

# --- Actions -------------------------------------------------------------------

apparmor::check() {
  _aa_validate || return 0
  _aa_check_active || return 0
  _aa_check_profiles
  _aa_check_listeners
}

apparmor::setup() {
  _aa_validate || return 1
  pkg_install apparmor apparmor-utils
  svc_enable apparmor
  apparmor::configure
}

apparmor::configure() {
  _aa_validate || return 1
  if [[ $(aa-enabled 2>/dev/null) != Yes ]] && ((!DRY_RUN)); then
    result_fail "AppArmor ist im Kernel nicht aktiv – Bootparameter prüfen (apparmor=1 security=apparmor)"
    return 1
  fi
  _aa_apply_enforce
}

# Profiles srvctl switched to enforce go back to complain mode.
apparmor::rollback() {
  local state name
  local -a names=()
  state=$(state_path apparmor enforced)
  if [[ -r $state ]]; then mapfile -t names <"$state"; fi
  backup_restore_module apparmor
  for name in "${names[@]}"; do
    [[ -n $name && -f /etc/apparmor.d/$name ]] || continue
    run_cmd aa-complain "/etc/apparmor.d/$name"
  done
}
