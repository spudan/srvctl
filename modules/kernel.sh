# shellcheck shell=bash
# kernel - sysctl hardening (network and kernel), blocked kernel modules,
# mount options for /dev/shm, /tmp and /var/tmp, no core dumps.
# Decisions: docs/PLAN.md, section "6. kernel".
#
# Note: kernel.kexec_load_disabled=1 and kernel.unprivileged_bpf_disabled=1
# cannot be reverted at runtime; a rollback takes effect after a reboot.

MODULE_NAME="kernel"
MODULE_DESC="Kernel-Härtung: sysctl, gesperrte Kernelmodule, Mount-Optionen, keine Core-Dumps"
MODULE_DEPENDS=()

readonly _KERNEL_SYSCTL=/etc/sysctl.d/90-srvctl.conf
readonly _KERNEL_MODPROBE=/etc/modprobe.d/srvctl-blacklist.conf
readonly _KERNEL_LIMITS=/etc/security/limits.d/srvctl-coredump.conf
readonly _KERNEL_COREDUMP=/etc/systemd/coredump.conf.d/srvctl.conf
readonly _KERNEL_SYSTEMD_LIMITS=/etc/systemd/system.conf.d/srvctl-coredump.conf
readonly _KERNEL_TMP_DROPIN=/etc/systemd/system/tmp.mount.d/srvctl.conf
readonly _KERNEL_VARTMP_UNIT=/etc/systemd/system/var-tmp.mount
readonly _KERNEL_HEADER="Verwaltet von srvctl (Modul: kernel) – manuelle Änderungen werden überschrieben"

readonly _KERNEL_BLACKLIST="cramfs freevxfs hfs hfsplus jffs2 udf dccp sctp rds tipc usb-storage firewire-core bluetooth"

# --- Configuration -------------------------------------------------------------

_kernel_tmp_noexec() { [[ $(cfg_get KERNEL_TMP_NOEXEC 0) == 1 ]]; }

# Expected sysctl values: "key value" per line
_kernel_sysctls() {
  local key
  # Network
  for key in all default; do
    echo "net.ipv4.conf.${key}.rp_filter 1"
    echo "net.ipv4.conf.${key}.accept_redirects 0"
    echo "net.ipv4.conf.${key}.secure_redirects 0"
    echo "net.ipv4.conf.${key}.send_redirects 0"
    echo "net.ipv4.conf.${key}.accept_source_route 0"
    echo "net.ipv4.conf.${key}.log_martians 1"
    echo "net.ipv6.conf.${key}.accept_redirects 0"
    echo "net.ipv6.conf.${key}.accept_source_route 0"
  done
  cat <<EOF
net.ipv4.tcp_syncookies 1
net.ipv4.icmp_echo_ignore_broadcasts 1
net.ipv4.icmp_ignore_bogus_error_responses 1
net.ipv4.tcp_rfc1337 1
kernel.kptr_restrict 2
kernel.dmesg_restrict 1
kernel.unprivileged_bpf_disabled 1
net.core.bpf_jit_harden 2
kernel.kexec_load_disabled 1
kernel.perf_event_paranoid 3
kernel.sysrq 0
dev.tty.ldisc_autoload 0
kernel.randomize_va_space 2
kernel.yama.ptrace_scope $(cfg_get KERNEL_PTRACE_SCOPE 1)
fs.suid_dumpable 0
fs.protected_hardlinks 1
fs.protected_symlinks 1
fs.protected_fifos 2
fs.protected_regular 2
EOF
  if [[ $(cfg_get KERNEL_UNPRIV_USERNS 1) == 0 ]]; then
    echo "kernel.unprivileged_userns_clone 0"
  fi
}

# Only keys the running kernel knows (e.g. no IPv6 when disabled)
_kernel_sysctls_supported() {
  local key value
  while read -r key value; do
    [[ -e /proc/sys/${key//.//} ]] && echo "$key $value"
  done < <(_kernel_sysctls)
}

_kernel_blacklist() { echo "$_KERNEL_BLACKLIST $(cfg_get KERNEL_BLACKLIST_EXTRA "")"; }

_kernel_validate() {
  local ok=0 mod
  [[ $(cfg_get KERNEL_PTRACE_SCOPE 1) =~ ^[0-3]$ ]] || {
    result_fail "KERNEL_PTRACE_SCOPE: '$(cfg_get KERNEL_PTRACE_SCOPE)' ist ungültig (0–3)"
    ok=1
  }
  for mod in $(_kernel_blacklist); do
    [[ $mod =~ ^[A-Za-z0-9_-]+$ ]] || {
      result_fail "KERNEL_BLACKLIST_EXTRA: '$mod' ist kein Modulname"
      ok=1
    }
  done
  for mod in overlay br_netfilter nf_conntrack wireguard; do
    if [[ " $(cfg_get KERNEL_BLACKLIST_EXTRA "") " == *" $mod "* ]]; then
      result_fail "KERNEL_BLACKLIST_EXTRA: '$mod' wird von Docker/Firewall/WireGuard gebraucht"
      ok=1
    fi
  done
  return "$ok"
}

# --- Mount helpers ---------------------------------------------------------------

_kernel_mount_opts() { findmnt -no OPTIONS --target "$1" 2>/dev/null; }
_kernel_mount_fstype() { findmnt -no FSTYPE --mountpoint "$1" 2>/dev/null; }

# _kernel_has_opts PATH OPT... - true if PATH is mounted with all options
_kernel_has_opts() {
  local path=$1 opts opt
  shift
  opts=",$(_kernel_mount_opts "$path"),"
  for opt; do
    [[ $opts == *",$opt,"* ]] || return 1
  done
}

_kernel_wanted_tmp_opts() {
  echo "nodev nosuid$(_kernel_tmp_noexec && echo " noexec")"
}

# --- Checks --------------------------------------------------------------------

_kernel_check_sysctl() {
  local key want have bad=0 total=0
  while read -r key want; do
    ((++total))
    have=$(sysctl -n "$key" 2>/dev/null)
    if [[ $have != "$want" ]]; then
      result_warn "sysctl $key = ${have:-?} (erwartet: $want)"
      bad=1
    fi
  done < <(_kernel_sysctls_supported)
  ((bad)) || result_ok "Alle $total sysctl-Werte gesetzt (Netzwerk und Kernel)"
  if [[ ! -f $_KERNEL_SYSCTL ]]; then
    result_warn "$_KERNEL_SYSCTL fehlt – Werte gehen beim Neustart verloren"
  fi
}

_kernel_check_modules() {
  local mod loaded=() open=()
  for mod in $(_kernel_blacklist); do
    if lsmod | awk '{ print $1 }' | grep -qx "${mod//-/_}"; then
      loaded+=("$mod")
    fi
    if ! modprobe -n -v "$mod" 2>/dev/null | grep -q 'install /bin/false'; then
      open+=("$mod")
    fi
  done
  if ((${#open[@]})); then
    result_warn "Nicht gesperrte Kernelmodule: ${open[*]}"
  else
    result_ok "Ungenutzte Kernelmodule gesperrt ($(wc -w <<<"$(_kernel_blacklist)") Module)"
  fi
  if ((${#loaded[@]})); then
    result_warn "Gesperrte Module sind noch geladen (Neustart nötig): ${loaded[*]}"
  fi
}

_kernel_check_mounts() {
  if _kernel_has_opts /dev/shm nodev nosuid noexec; then
    result_ok "/dev/shm: nodev,nosuid,noexec"
  else
    result_warn "/dev/shm ohne nodev,nosuid,noexec ($(_kernel_mount_opts /dev/shm))"
  fi
  local path
  local -a want
  read -ra want <<<"$(_kernel_wanted_tmp_opts)"
  for path in /tmp /var/tmp; do
    if [[ -z $(_kernel_mount_fstype "$path") ]]; then
      result_warn "$path ist kein eigener Mount (ohne $(IFS=,; echo "${want[*]}")) – 'srvctl configure kernel' hängt es per Bind-Mount ein"
    elif _kernel_has_opts "$path" "${want[@]}"; then
      result_ok "$path: $(IFS=,; echo "${want[*]}")"
    else
      result_warn "$path ohne $(IFS=,; echo "${want[*]}") ($(_kernel_mount_opts "$path"))"
    fi
  done
}

_kernel_check_coredumps() {
  local ok=1
  [[ -f $_KERNEL_LIMITS ]] || ok=0
  [[ $(sysctl -n fs.suid_dumpable 2>/dev/null) == 0 ]] || ok=0
  if [[ -d /etc/systemd/coredump.conf.d || -x /usr/lib/systemd/systemd-coredump ]] && [[ ! -f $_KERNEL_COREDUMP ]]; then
    ok=0
  fi
  if ((ok)); then
    result_ok "Core-Dumps abgeschaltet"
  else
    result_warn "Core-Dumps sind nicht vollständig abgeschaltet"
  fi
}

# --- Apply ---------------------------------------------------------------------

_kernel_apply_sysctl() {
  local content key value
  content="# ${_KERNEL_HEADER}"$'\n'"# Siehe docs/PLAN.md, Abschnitt 6"$'\n'
  while read -r key value; do
    content+="${key} = ${value}"$'\n'
  done < <(_kernel_sysctls_supported)
  write_file "$_KERNEL_SYSCTL" 0644 <<<"${content%$'\n'}"
  if ((FILE_CHANGED)); then
    run_cmd sysctl -q -p "$_KERNEL_SYSCTL"
    result_ok "sysctl-Härtung angewendet"
  fi
}

_kernel_apply_modules() {
  local mod content="# ${_KERNEL_HEADER}"$'\n'"# Ungenutzte Treiber und Protokolle (Angriffsfläche) – nicht ladbar"$'\n'
  for mod in $(_kernel_blacklist); do
    content+="install ${mod} /bin/false"$'\n'"blacklist ${mod}"$'\n'
  done
  write_file "$_KERNEL_MODPROBE" 0644 <<<"${content%$'\n'}"
  if ((FILE_CHANGED)); then
    result_ok "Kernelmodule gesperrt (bereits geladene erst nach Neustart)"
  fi
}

_kernel_apply_mounts() {
  # /dev/shm via fstab (systemd mounts it early; remount applies the options)
  local line="tmpfs /dev/shm tmpfs defaults,nodev,nosuid,noexec 0 0"
  if grep -qE '^[^#[:space:]]+[[:space:]]+/dev/shm[[:space:]]' /etc/fstab; then
    file_sed /etc/fstab "s|^[^#[:space:]]+[[:space:]]+/dev/shm[[:space:]].*\$|${line}|"
  else
    ensure_line /etc/fstab "$line"
  fi
  if ((FILE_CHANGED)) || ! _kernel_has_opts /dev/shm nodev nosuid noexec; then
    run_cmd mount -o remount,nodev,nosuid,noexec /dev/shm
    result_ok "/dev/shm mit nodev,nosuid,noexec eingehängt"
  fi

  local opts
  opts=$(_kernel_wanted_tmp_opts | tr ' ' ',')

  # /tmp: Debian 13 mounts a tmpfs via tmp.mount (nodev,nosuid by default)
  if _kernel_tmp_noexec; then
    if [[ $(_kernel_mount_fstype /tmp) == tmpfs ]]; then
      write_file "$_KERNEL_TMP_DROPIN" 0644 <<<"# ${_KERNEL_HEADER}
[Mount]
Options=mode=1777,strictatime,size=50%%,nr_inodes=1m,${opts}"
      if ((FILE_CHANGED)); then
        run_cmd systemctl daemon-reload
        run_cmd mount -o "remount,${opts}" /tmp
      fi
    else
      result_warn "/tmp ist kein tmpfs – noexec wird nicht gesetzt"
    fi
  elif [[ -f $_KERNEL_TMP_DROPIN ]]; then
    backup_file "$_KERNEL_TMP_DROPIN"
    run_cmd rm -f -- "$_KERNEL_TMP_DROPIN"
    run_cmd systemctl daemon-reload
    run_cmd mount -o remount,exec /tmp
  fi

  # /var/tmp: bind mount onto itself with restrictive options
  write_file "$_KERNEL_VARTMP_UNIT" 0644 <<<"# ${_KERNEL_HEADER}
[Unit]
Description=/var/tmp mit ${opts} (srvctl)
DefaultDependencies=no
Conflicts=umount.target
Before=local-fs.target umount.target
After=local-fs-pre.target

[Mount]
What=/var/tmp
Where=/var/tmp
Type=none
Options=bind,${opts}

[Install]
WantedBy=local-fs.target"
  if ((FILE_CHANGED)); then
    run_cmd systemctl daemon-reload
    run_cmd systemctl enable var-tmp.mount
    if findmnt -n --mountpoint /var/tmp >/dev/null; then
      run_cmd mount -o "remount,bind,${opts}" /var/tmp
    else
      run_cmd systemctl start var-tmp.mount
    fi
    result_ok "/var/tmp mit ${opts} eingehängt"
  fi
}

_kernel_apply_coredumps() {
  write_file "$_KERNEL_LIMITS" 0644 <<<"# ${_KERNEL_HEADER}
# Core-Dumps können Passwörter und Schlüssel aus dem Speicher enthalten
* hard core 0"
  write_file "$_KERNEL_SYSTEMD_LIMITS" 0644 <<<"# ${_KERNEL_HEADER}
# Gilt für systemd-Dienste ab dem nächsten Neustart
[Manager]
DefaultLimitCORE=0"
  if [[ -d /etc/systemd/coredump.conf.d || -x /usr/lib/systemd/systemd-coredump ]]; then
    write_file "$_KERNEL_COREDUMP" 0644 <<<"# ${_KERNEL_HEADER}
[Coredump]
Storage=none
ProcessSizeMax=0"
  fi
}

# --- Actions -------------------------------------------------------------------

kernel::check() {
  _kernel_validate || return 0
  _kernel_check_sysctl
  _kernel_check_modules
  _kernel_check_mounts
  _kernel_check_coredumps
}

kernel::setup() {
  kernel::configure
}

kernel::configure() {
  _kernel_validate || return 1
  _kernel_apply_sysctl
  _kernel_apply_modules
  _kernel_apply_mounts
  _kernel_apply_coredumps
}

# Restores the files; re-applies Debian's sysctl defaults and remounts.
# kexec_load_disabled and unprivileged_bpf_disabled stay until reboot.
kernel::rollback() {
  backup_restore_module kernel
  run_cmd systemctl daemon-reload
  if [[ ! -f $_KERNEL_VARTMP_UNIT ]] && findmnt -n --mountpoint /var/tmp >/dev/null; then
    run_cmd umount /var/tmp
  fi
  if ! grep -qE '^[^#[:space:]]+[[:space:]]+/dev/shm[[:space:]].*noexec' /etc/fstab; then
    run_cmd mount -o remount,exec /dev/shm
  fi
  run_cmd sysctl -q --system
  log_info "Hinweis: kexec_load_disabled und unprivileged_bpf_disabled bleiben bis zum Neustart aktiv"
}
