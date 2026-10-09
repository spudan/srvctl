# shellcheck shell=bash
# base - foundation of the hardening: automatic security updates, time sync
# via chrony + NTS, timezone, locale, apt sources and package baseline.
# Decisions: docs/PLAN.md, section "1. base".

MODULE_NAME="base"
MODULE_DESC="Grundsystem: Sicherheitsupdates, Zeit (NTS), Locale, Paketquellen, Pakete"
MODULE_DEPENDS=()
MODULE_LISTEN=(chronyd)

readonly _BASE_UU_CONF=/etc/apt/apt.conf.d/52srvctl-unattended-upgrades
readonly _BASE_AUTO_CONF=/etc/apt/apt.conf.d/20auto-upgrades
readonly _BASE_NR_CONF=/etc/needrestart/conf.d/srvctl.conf
readonly _BASE_CHRONY_CONF=/etc/chrony/chrony.conf
readonly _BASE_CHRONY_SOURCES=/etc/chrony/sources.d/srvctl-nts.sources
readonly _BASE_CHRONY_LOCAL=/etc/chrony/conf.d/srvctl.conf
readonly _BASE_SECURITY_SOURCES=/etc/apt/sources.list.d/srvctl-security.sources
readonly _BASE_HEADER="Verwaltet von srvctl (Modul: base) – manuelle Änderungen werden überschrieben"

# --- Configuration -----------------------------------------------------------

_base_nts_servers() {
  cfg_get BASE_NTS_SERVERS "ptbtime1.ptb.de ptbtime2.ptb.de ptbtime3.ptb.de nts.netnod.se time.cloudflare.com"
}

_base_time_require_nts() { [[ $(cfg_get BASE_TIME_REQUIRE_NTS 1) == 1 ]]; }

_base_packages_install() {
  local pkgs
  pkgs=$(cfg_get BASE_PACKAGES_INSTALL "needrestart debsecan apt-listchanges ca-certificates debsums apt-show-versions")
  os_is debian || pkgs=${pkgs//debsecan/} # debsecan uses Debian's security tracker
  echo $pkgs # word splitting collapses the gap left by the removal
}

_base_packages_remove() {
  cfg_get BASE_PACKAGES_REMOVE "telnet inetutils-telnet rsh-client nis talk ftp tnftp inetutils-ftp avahi-daemon cups xinetd rpcbind"
}

_base_locales() { # BASE_LOCALE first, then extras
  echo "$(cfg_get BASE_LOCALE en_US.UTF-8) $(cfg_get BASE_LOCALES_EXTRA de_DE.UTF-8)"
}

# Returns 1 (with FAIL) on invalid configuration values.
_base_validate() {
  local ok=0 tz reboot mode locale server
  tz=$(cfg_get BASE_TIMEZONE Europe/Berlin)
  [[ -f /usr/share/zoneinfo/$tz && $tz != */../* ]] || {
    result_fail "BASE_TIMEZONE: unbekannte Zeitzone '$tz'"
    ok=1
  }
  reboot=$(cfg_get BASE_AUTO_REBOOT "")
  [[ -z $reboot || $reboot =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || {
    result_fail "BASE_AUTO_REBOOT: '$reboot' ist keine Uhrzeit (HH:MM) – leer lassen für 'kein automatischer Neustart'"
    ok=1
  }
  mode=$(cfg_get BASE_NEEDRESTART auto)
  [[ $mode == auto || $mode == list ]] || {
    result_fail "BASE_NEEDRESTART: '$mode' ist ungültig (auto oder list)"
    ok=1
  }
  for locale in $(_base_locales); do
    [[ $locale =~ ^([a-z]{2,3}_[A-Z]{2}|C)\.UTF-8$ ]] || {
      result_fail "Locale '$locale' wird nicht unterstützt (Format: xx_YY.UTF-8)"
      ok=1
    }
  done
  for server in $(_base_nts_servers) $(cfg_get BASE_TIME_SERVERS ""); do
    [[ $server =~ ^[A-Za-z0-9.:-]+$ ]] || {
      result_fail "BASE_NTS_SERVERS/BASE_TIME_SERVERS: ungültiger Servername '$server'"
      ok=1
    }
  done
  return "$ok"
}

# --- Apt sources ---------------------------------------------------------------

_base_source_files() {
  local f
  for f in /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources; do
    [[ -f $f ]] && echo "$f"
  done
  return 0
}

# Prints "URL<TAB>SIGNED_BY(0/1)<TAB>TRUSTED(0/1)<TAB>FILE" for every enabled
# "deb" entry, from one-line (.list) and deb822 (.sources) files.
_base_source_entries() {
  local -a files
  mapfile -t files < <(_base_source_files)
  ((${#files[@]})) || return 0
  awk '
    function flush(   n, i, u) {
      if (uris != "" && types ~ /(^|[ \t])deb([ \t]|$)/ && enabled != "no")
        for (i = split(uris, u, /[ \t]+/); i >= 1; i--) if (u[i] != "") print u[i] "\t" signed "\t" trusted "\t" fname
      uris = ""; types = ""; signed = 0; trusted = 0; enabled = ""
    }
    FNR == 1 { flush(); fname = FILENAME; is822 = (FILENAME ~ /\.sources$/) }
    is822 {
      if ($0 ~ /^[ \t]*$/) { flush(); next }
      if ($0 ~ /^[ \t#]/) next
      key = tolower($0); sub(/:.*/, "", key)
      val = $0; sub(/^[^:]*:[ \t]*/, "", val)
      if (key == "types") types = val
      else if (key == "uris") uris = val
      else if (key == "signed-by") signed = 1
      else if (key == "trusted") trusted = (tolower(val) == "yes")
      else if (key == "enabled") enabled = tolower(val)
      next
    }
    {
      sub(/#.*/, "")
      if ($1 != "deb") next
      opts = ""; url = $2
      if ($2 ~ /^\[/) {
        i = 2; opts = $2
        while ($i !~ /\]$/ && i < NF) { i++; opts = opts " " $i }
        url = $(i + 1)
      }
      print url "\t" (opts ~ /signed-by=/) "\t" (opts ~ /trusted=yes/) "\t" FILENAME
    }
    END { flush() }' "${files[@]}" | sed -E 's#/+\t#\t#'
}

# Prints "URL<TAB>ORIGIN" from the downloaded package lists.
_base_source_origins() {
  LC_ALL=C apt-cache policy 2>/dev/null | awk '
    /^ *-?[0-9]+ [a-z+]+:/ { url = $2; sub(/\/+$/, "", url); next } # priority may be -1 (pinning)
    /^ +release / {
      if (url == "") next
      rel = $0; sub(/^ +release /, "", rel); o = ""
      n = split(rel, kv, ",")
      for (i = 1; i <= n; i++) if (kv[i] ~ /^o=/) o = substr(kv[i], 3)
      if (!seen[url]++) print url "\t" o
      url = ""
    }'
}

_base_has_security_source() {
  local -a files
  mapfile -t files < <(_base_source_files)
  ((${#files[@]})) && grep -hsqE "^[^#]*[[:space:]]${OS_CODENAME}-security([[:space:]]|$)" "${files[@]}"
}

# _base_source_allowed URL - matches BASE_APT_ALLOWED_SOURCES (globs on the URL
# without scheme, e.g. "rspamd.com/*")
_base_source_allowed() {
  local url=${1#*://} pattern
  local -a patterns
  # read -a: no pathname expansion of the patterns (srvctl runs with nullglob)
  read -ra patterns <<<"$(cfg_get BASE_APT_ALLOWED_SOURCES "")"
  for pattern in "${patterns[@]}"; do
    # shellcheck disable=SC2053
    [[ $url == $pattern ]] && return 0
  done
  return 1
}

_base_check_sources() {
  if _base_has_security_source; then
    result_ok "Security-Paketquelle (${OS_CODENAME}-security) ist eingebunden"
  else
    result_fail "Security-Paketquelle (${OS_CODENAME}-security) fehlt – 'srvctl setup base'"
  fi

  if LC_ALL=C apt-config dump 2>/dev/null |
    grep -qEi '^Acquire::(AllowInsecureRepositories|AllowDowngradeToInsecureRepositories|AllowWeakRepositories) "(1|true|yes)"'; then
    result_fail "APT erlaubt unsignierte oder schwach signierte Quellen (Acquire::Allow…Repositories)"
  fi
  if [[ -s /etc/apt/trusted.gpg ]]; then
    result_warn "Globaler Schlüsselbund /etc/apt/trusted.gpg vorhanden – Schlüssel gelten für alle Quellen (signed-by verwenden)"
  fi

  local -A origin=()
  local url org signed trusted file foreign=0
  while IFS=$'\t' read -r url org; do
    origin[$url]=$org
  done < <(_base_source_origins)

  while IFS=$'\t' read -r url signed trusted file; do
    org=${origin[$url]:-}
    if ((trusted)); then
      result_fail "Quelle ohne Signaturprüfung (trusted=yes): $url ($file)"
    fi
    case $org in
      Debian* | Ubuntu*) continue ;;
    esac
    foreign=1
    if _base_source_allowed "$url"; then
      result_ok "Erlaubte Fremdquelle: $url${org:+ (Herkunft: $org)}"
    elif [[ -z $org ]]; then
      result_warn "Quelle mit unbekannter Herkunft: $url ($file) – Paketlisten veraltet? Sonst in BASE_APT_ALLOWED_SOURCES erlauben"
    else
      result_warn "Fremdquelle: $url (Herkunft: $org, $file) – in BASE_APT_ALLOWED_SOURCES erlauben oder entfernen"
    fi
    if ((!signed)); then
      result_warn "Fremdquelle ohne signed-by: $url – ihr Schlüssel gilt für alle Quellen"
    fi
  done < <(_base_source_entries)
  ((foreign)) || result_ok "Keine Fremdquellen eingebunden"
}

_base_apply_sources() {
  if _base_has_security_source; then
    return 0
  fi
  local content
  case $OS_ID in
    debian)
      content="Types: deb
URIs: http://security.debian.org/debian-security
Suites: ${OS_CODENAME}-security
Components: main
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg"
      ;;
    ubuntu)
      content="Types: deb
URIs: http://security.ubuntu.com/ubuntu
Suites: ${OS_CODENAME}-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg"
      ;;
    *)
      result_warn "Security-Paketquelle fehlt und kann für $OS_NAME nicht automatisch ergänzt werden"
      return 0
      ;;
  esac
  write_file "$_BASE_SECURITY_SOURCES" 0644 <<<"# ${_BASE_HEADER}"$'\n'"${content}"
  result_ok "Security-Paketquelle ergänzt: $_BASE_SECURITY_SOURCES"
}

# --- Packages ------------------------------------------------------------------

_base_check_packages() {
  local pkg
  local -a missing=() unwanted=()
  for pkg in $(_base_packages_install) unattended-upgrades chrony locales; do
    if ! pkg_installed "$pkg"; then missing+=("$pkg"); fi
  done
  for pkg in $(_base_packages_remove); do
    if pkg_installed "$pkg"; then unwanted+=("$pkg"); fi
  done
  if ((${#missing[@]})); then
    result_warn "Fehlende Basispakete: ${missing[*]}"
  else
    result_ok "Alle Basispakete sind installiert"
  fi
  if ((${#unwanted[@]})); then
    result_warn "Unerwünschte Pakete installiert: ${unwanted[*]}"
  else
    result_ok "Keine unerwünschten Pakete installiert"
  fi
  local residual
  residual=$(pkg_residual | paste -sd ' ')
  if [[ -n $residual ]]; then
    result_warn "Reste entfernter Pakete (Konfiguration, Cron-Jobs): $residual – 'srvctl setup base'"
  fi
}

_base_install_packages() {
  local -a pkgs
  read -ra pkgs <<<"$(_base_packages_install) unattended-upgrades chrony locales"
  if os_is debian && ! pkg_installed debsecan && [[ " ${pkgs[*]} " == *" debsecan "* ]]; then
    # No daily report mail (needs a mail server); suite is passed in check.
    run_cmd debconf-set-selections <<<"debsecan debsecan/report boolean false"
  fi
  pkg_install "${pkgs[@]}"
}

_base_remove_packages() {
  local pkg
  local -a present=()
  for pkg in $(_base_packages_remove); do
    if pkg_installed "$pkg"; then present+=("$pkg"); fi
  done
  ((${#present[@]})) || return 0
  log_info "Unerwünschte Pakete: ${present[*]}"
  if ! confirm "Diese Pakete entfernen?"; then
    result_warn "Entfernen übersprungen: ${present[*]}"
    return 0
  fi
  pkg_purge "${present[@]}"
  result_ok "Entfernt: ${present[*]}"
}

# Purges configuration left behind by removed packages
_base_purge_residual() {
  local -a residual
  mapfile -t residual < <(pkg_residual)
  ((${#residual[@]})) || return 0
  log_info "Reste entfernter Pakete: ${residual[*]}"
  if ! confirm "Konfigurationsreste dieser Pakete löschen?"; then
    result_warn "Bereinigung übersprungen: ${residual[*]}"
    return 0
  fi
  pkg_purge "${residual[@]}"
  result_ok "Reste bereinigt: ${residual[*]}"
}

# --- Automatic updates ---------------------------------------------------------

_base_check_updates() {
  if ! pkg_installed unattended-upgrades; then
    result_fail "unattended-upgrades ist nicht installiert – 'srvctl setup base'"
  elif [[ $(apt-config dump APT::Periodic::Unattended-Upgrade 2>/dev/null) == *'"1"'* ]]; then
    result_ok "Automatische Updates sind aktiv"
  else
    result_fail "Automatische Updates sind nicht aktiviert ($_BASE_AUTO_CONF)"
  fi

  if os_is debian && pkg_installed unattended-upgrades; then
    local origins other
    origins=$(apt-config dump Unattended-Upgrade::Origins-Pattern 2>/dev/null |
      sed -n 's/^Unattended-Upgrade::Origins-Pattern:: "\(.*\)";$/\1/p')
    # Only Debian's own non-security origins count; other modules (e.g. crowdsec)
    # add their repositories on purpose.
    other=$(grep -i 'origin=Debian' <<<"$origins" | grep -viE 'security' | paste -sd ' ')
    if [[ -n $other ]]; then
      result_warn "Automatische Updates umfassen auch Nicht-Sicherheitsupdates: $other"
    elif [[ -n $origins ]]; then
      result_ok "Automatisch werden nur Sicherheitsupdates eingespielt"
    fi
  fi

  local reboot want="false"
  [[ -n $(cfg_get BASE_AUTO_REBOOT "") ]] && want="true"
  reboot=$(apt-config dump Unattended-Upgrade::Automatic-Reboot 2>/dev/null | sed -n 's/.*"\(.*\)";$/\1/p')
  if [[ ${reboot:-false} != "$want" ]]; then
    result_warn "Automatischer Neustart ist '${reboot:-false}', erwartet '$want' (BASE_AUTO_REBOOT)"
  fi

  local timer
  for timer in apt-daily.timer apt-daily-upgrade.timer; do
    svc_is_enabled "$timer" || result_fail "$timer ist nicht aktiviert"
  done

  local newest age
  newest=$(find /var/lib/apt/lists -maxdepth 1 -name '*Release' -printf '%T@\n' 2>/dev/null | sort -n | tail -n 1)
  if [[ -n $newest ]]; then
    age=$((($(date +%s) - ${newest%.*}) / 86400))
    if ((age >= 2)); then
      result_warn "Paketlisten sind $age Tage alt – läuft apt-daily.timer?"
    fi
  fi

  local sim total security
  sim=$(LC_ALL=C apt-get -s -o Debug::NoLocking=1 dist-upgrade 2>/dev/null | grep '^Inst ')
  total=$(grep -c . <<<"$sim")
  security=$(grep -ci 'security' <<<"$sim")
  if ((security > 0)); then
    result_warn "$security Sicherheitsupdate(s) ausstehend (werden automatisch eingespielt)"
  elif ((total > 0)); then
    result_ok "Keine Sicherheitsupdates ausstehend ($total reguläre Updates verfügbar – manuell einspielen)"
  else
    result_ok "System ist aktuell"
  fi

  if os_is debian && cmd_exists debsecan; then
    local vulnerable
    vulnerable=$(timeout 90 debsecan --suite "$OS_CODENAME" --only-fixed --no-obsolete --format packages 2>/dev/null | paste -sd ' ')
    if [[ -n $vulnerable ]]; then
      result_warn "Pakete mit bekannten, behobenen Sicherheitslücken: $vulnerable"
    fi
  fi
}

_base_check_restart() {
  local mode
  mode=$(cfg_get BASE_NEEDRESTART auto)
  if [[ -f $_BASE_NR_CONF ]] && grep -q "restart} = '${mode:0:1}'" "$_BASE_NR_CONF"; then
    result_ok "needrestart: Dienste werden nach Updates $([[ $mode == auto ]] && echo "automatisch neu gestartet" || echo "nur aufgelistet")"
  elif pkg_installed needrestart; then
    result_warn "needrestart ist nicht wie konfiguriert eingestellt (BASE_NEEDRESTART=$mode)"
  fi

  local kernel_warned=0
  if cmd_exists needrestart; then
    local out ksta kcur kexp services
    out=$(needrestart -b 2>/dev/null)
    ksta=$(sed -n 's/^NEEDRESTART-KSTA: //p' <<<"$out")
    kcur=$(sed -n 's/^NEEDRESTART-KCUR: //p' <<<"$out")
    kexp=$(sed -n 's/^NEEDRESTART-KEXP: //p' <<<"$out")
    case $ksta in
      2 | 3)
        result_warn "Neustart erforderlich: Kernel ${kexp:-neu} installiert, $kcur läuft"
        kernel_warned=1
        ;;
      1) result_ok "Laufender Kernel ist aktuell ($kcur)" ;;
    esac
    services=$(sed -n 's/^NEEDRESTART-SVC: //p' <<<"$out" | paste -sd ' ')
    if [[ -n $services ]]; then
      result_warn "Dienste nutzen veraltete Bibliotheken (Neustart nötig): $services"
    fi
  else
    local newest
    newest=$(find /boot -maxdepth 1 -name 'vmlinuz-*' -printf '%f\n' 2>/dev/null | sort -V | tail -n 1)
    if [[ -n $newest && $newest != "vmlinuz-$(uname -r)" ]]; then
      result_warn "Neustart erforderlich: ${newest#vmlinuz-} installiert, $(uname -r) läuft"
      kernel_warned=1
    fi
  fi
  if [[ -e /run/reboot-required ]] && ((!kernel_warned)); then
    result_warn "Neustart erforderlich (/run/reboot-required)"
  fi
}

# Origins-Pattern entries configured outside srvctl that are not Debian's own
# (e.g. Docker or a vendor repository); kept when srvctl clears the list.
_base_foreign_origins() {
  local tmp file
  tmp=$(mktemp -d "${RUN_DIR}/aptconf.XXXXXX")
  for file in /etc/apt/apt.conf.d/*; do
    [[ -f $file ]] || continue
    case ${file##*/} in 5[0-9]srvctl-*) continue ;; esac
    cp -- "$file" "$tmp/"
  done
  apt-config -o Dir::Etc::Parts="$tmp" dump Unattended-Upgrade::Origins-Pattern 2>/dev/null |
    sed -n 's/^Unattended-Upgrade::Origins-Pattern:: "\(.*\)";$/\1/p' | grep -v 'origin=Debian' || true
  rm -rf -- "$tmp"
}

_base_apply_updates() {
  local reboot reboot_flag="false" reboot_time="03:30" content
  reboot=$(cfg_get BASE_AUTO_REBOOT "")
  if [[ -n $reboot ]]; then
    reboot_flag="true"
    reboot_time=$reboot
  fi

  write_file "$_BASE_AUTO_CONF" 0644 <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF

  content="// ${_BASE_HEADER}"$'\n'
  if os_is debian; then
    # Debian's default also installs regular stable updates (label=Debian).
    # Origins of other repositories configured elsewhere are kept.
    local origin
    content+='// Nur Sicherheitsupdates automatisch einspielen (Debian); andere Quellen bleiben erhalten.
#clear Unattended-Upgrade::Origins-Pattern;
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
'
    while IFS= read -r origin; do
      content+="        \"${origin}\";"$'\n'
    done < <(_base_foreign_origins)
    content+='};
'
  fi
  content+="Unattended-Upgrade::Automatic-Reboot \"${reboot_flag}\";
Unattended-Upgrade::Automatic-Reboot-Time \"${reboot_time}\";
Unattended-Upgrade::Remove-Unused-Kernel-Packages \"true\";
Unattended-Upgrade::Remove-New-Unused-Dependencies \"true\";
Unattended-Upgrade::SyslogEnable \"true\";"
  write_file "$_BASE_UU_CONF" 0644 <<<"$content"

  local mode
  mode=$(cfg_get BASE_NEEDRESTART auto)
  write_file "$_BASE_NR_CONF" 0644 <<<"# ${_BASE_HEADER}
# Dienste nach Updates: (a)utomatisch neu starten oder nur (l)isten
\$nrconf{restart} = '${mode:0:1}';"

  svc_enable apt-daily.timer
  svc_enable apt-daily-upgrade.timer
  result_ok "Automatische Sicherheitsupdates eingerichtet (Neustart: ${reboot:-nur melden}, needrestart: $mode)"
}

# --- Time ----------------------------------------------------------------------

_base_check_time() {
  if ! pkg_installed chrony; then
    result_fail "chrony ist nicht installiert – 'srvctl setup base'"
    return 0
  fi
  check_service chrony
  if svc_is_active systemd-timesyncd; then
    result_warn "systemd-timesyncd läuft zusätzlich zu chrony"
  fi

  if ! _base_time_require_nts; then
    result_ok "chrony darf auch Zeitquellen ohne NTS nutzen (BASE_TIME_REQUIRE_NTS=0)"
  elif [[ -f $_BASE_CHRONY_LOCAL ]] && grep -q '^authselectmode require' "$_BASE_CHRONY_LOCAL"; then
    result_ok "chrony nutzt nur authentifizierte Zeitquellen"
  else
    result_warn "chrony akzeptiert auch nicht authentifizierte Zeitquellen (authselectmode fehlt)"
  fi
  if _base_time_require_nts && grep -qE '^[[:space:]]*pool[[:space:]]' "$_BASE_CHRONY_CONF" 2>/dev/null; then
    result_warn "Unauthentifizierter NTP-Pool in $_BASE_CHRONY_CONF aktiv"
  fi

  local auth total ok
  auth=$(chronyc -c -N authdata 2>/dev/null)
  total=$(awk -F, '$2 == "NTS"' <<<"$auth" | grep -c .)
  ok=$(awk -F, '$2 == "NTS" && $9 > 0' <<<"$auth" | grep -c .)
  if ((total == 0)); then
    result_fail "Keine NTS-Zeitquellen konfiguriert"
  elif ((ok == 0)); then
    result_fail "Keine NTS-Quelle authentifiziert (0 von $total) – ausgehend TCP 4460 und UDP 123 erlaubt?"
  else
    result_ok "NTS: $ok von $total Zeitquellen authentifiziert"
  fi

  local leap
  leap=$(chronyc -c tracking 2>/dev/null | cut -d, -f14)
  if [[ $leap == Normal ]]; then
    result_ok "Systemzeit ist synchronisiert"
  else
    result_fail "Systemzeit ist nicht synchronisiert (chronyc tracking: ${leap:-keine Antwort})"
  fi
}

_base_apply_time() {
  if [[ ! -f $_BASE_CHRONY_CONF ]]; then
    if ((DRY_RUN)); then
      log_dry "chrony wird nach der Installation für NTS konfiguriert"
      return 0
    fi
    result_fail "chrony ist nicht installiert – zuerst 'srvctl setup base'"
    return 1
  fi

  local server sources="" changed=0
  for server in $(_base_nts_servers); do
    sources+="server ${server} iburst nts"$'\n'
  done
  for server in $(cfg_get BASE_TIME_SERVERS ""); do
    sources+="server ${server} iburst"$'\n'
  done
  write_file "$_BASE_CHRONY_SOURCES" 0644 <<<"# ${_BASE_HEADER}"$'\n'"${sources%$'\n'}"
  if ((FILE_CHANGED)); then changed=1; fi

  if _base_time_require_nts; then
    write_file "$_BASE_CHRONY_LOCAL" 0644 <<<"# ${_BASE_HEADER}
# Nur authentifizierte Quellen (NTS) zur Synchronisation verwenden
authselectmode require"
    if ((FILE_CHANGED)); then changed=1; fi
    file_sed "$_BASE_CHRONY_CONF" 's/^([[:space:]]*pool[[:space:]].*)$/# srvctl (nur NTS): \1/'
    if ((FILE_CHANGED)); then changed=1; fi
  else
    # Non-NTS sources allowed (BASE_TIME_REQUIRE_NTS=0): undo the restriction
    if [[ -f $_BASE_CHRONY_LOCAL ]]; then
      backup_file "$_BASE_CHRONY_LOCAL"
      run_cmd rm -f -- "$_BASE_CHRONY_LOCAL"
      changed=1
    fi
    file_sed "$_BASE_CHRONY_CONF" 's/^# srvctl \(nur NTS\): //'
    if ((FILE_CHANGED)); then changed=1; fi
  fi

  if svc_is_active systemd-timesyncd || svc_is_enabled systemd-timesyncd; then
    svc_disable systemd-timesyncd
  fi
  svc_enable chrony
  if ((changed)); then
    svc_restart chrony
    result_ok "chrony mit NTS konfiguriert ($(_base_nts_servers))"
  else
    result_ok "chrony-Konfiguration ist aktuell"
  fi
}

# --- Timezone and locale -------------------------------------------------------

_base_check_locale() {
  local tz current
  tz=$(cfg_get BASE_TIMEZONE Europe/Berlin)
  current=$(timedatectl show -p Timezone --value 2>/dev/null)
  if [[ $current == "$tz" ]]; then
    result_ok "Zeitzone: $tz"
  else
    result_warn "Zeitzone ist '${current:-unbekannt}', erwartet '$tz'"
  fi

  local wanted lang available locale
  wanted=$(cfg_get BASE_LOCALE en_US.UTF-8)
  lang=$(conf_get /etc/default/locale LANG "=" 2>/dev/null | tr -d '"')
  if [[ $lang == "$wanted" ]]; then
    result_ok "Systemsprache: $lang"
  else
    result_warn "Systemsprache ist '${lang:-nicht gesetzt}', erwartet '$wanted'"
  fi
  available=$(locale -a 2>/dev/null)
  for locale in $(_base_locales); do
    # locale -a prints e.g. "en_US.utf8"
    if ! grep -qixF "${locale%.UTF-8}.utf8" <<<"$available"; then
      result_warn "Locale $locale ist nicht erzeugt"
    fi
  done
}

_base_apply_locale() {
  local tz
  tz=$(cfg_get BASE_TIMEZONE Europe/Berlin)
  if [[ $(timedatectl show -p Timezone --value 2>/dev/null) != "$tz" ]]; then
    backup_file /etc/localtime
    backup_file /etc/timezone
    run_cmd timedatectl set-timezone "$tz"
    result_ok "Zeitzone auf $tz gesetzt"
  fi

  if [[ ! -f /etc/locale.gen ]]; then
    if ((DRY_RUN)); then
      log_dry "Locales werden nach der Installation von 'locales' erzeugt"
      return 0
    fi
    result_fail "/etc/locale.gen fehlt (Paket locales) – zuerst 'srvctl setup base'"
    return 1
  fi

  local locale escaped changed=0
  for locale in $(_base_locales); do
    [[ $locale == C.UTF-8 ]] && continue
    escaped=${locale//./\\.}
    if grep -qE "^${escaped} UTF-8$" /etc/locale.gen; then
      continue
    elif grep -qE "^#[[:space:]]*${escaped} UTF-8$" /etc/locale.gen; then
      file_sed /etc/locale.gen "s/^#[[:space:]]*(${escaped} UTF-8)$/\\1/"
    else
      ensure_line /etc/locale.gen "${locale} UTF-8"
    fi
    if ((FILE_CHANGED)); then changed=1; fi
  done
  if ((changed)); then
    run_cmd locale-gen
  fi

  local wanted current
  wanted=$(cfg_get BASE_LOCALE en_US.UTF-8)
  current=$(conf_get /etc/default/locale LANG "=" 2>/dev/null | tr -d '"') || current=""
  FILE_CHANGED=0
  if [[ $current != "$wanted" ]]; then
    conf_set /etc/default/locale LANG "$wanted" "="
  fi
  if ((changed || FILE_CHANGED)); then
    result_ok "Locales eingerichtet (Systemsprache $wanted, gilt ab der nächsten Anmeldung)"
  fi
}

# --- Pre-check against the existing system ----------------------------------------

# Time servers configured outside srvctl (chrony, ntp/ntpsec, timesyncd),
# without Debian's default pools and the configured servers
_base_custom_time_servers() {
  local known
  known=" $(_base_nts_servers) $(cfg_get BASE_TIME_SERVERS "") "
  {
    awk '$1 ~ /^(server|pool|peer)$/ { print $2 }' "$_BASE_CHRONY_CONF" /etc/ntp.conf /etc/ntpsec/ntp.conf 2>/dev/null
    find /etc/chrony/sources.d -maxdepth 1 -name '*.sources' ! -name "${_BASE_CHRONY_SOURCES##*/}" \
      -exec awk '$1 ~ /^(server|pool|peer)$/ { print $2 }' {} + 2>/dev/null
    sed -n 's/^[[:space:]]*NTP=//p' /etc/systemd/timesyncd.conf /etc/systemd/timesyncd.conf.d/*.conf 2>/dev/null | tr ' ' '\n'
  } | grep -vE '^$|\.debian\.pool\.ntp\.org$' | sort -u | while read -r server; do
    [[ $known == *" $server "* ]] || echo "$server"
  done
}

base::precheck() {
  local pkg others=() servers current tz origins
  for pkg in ntp ntpsec openntpd; do
    if pkg_installed "$pkg"; then others+=("$pkg"); fi
  done
  if ((${#others[@]})); then
    precheck_warn "Zeitdienst ${others[*]} wird entfernt und durch chrony (NTS) ersetzt"
  fi
  servers=$(_base_custom_time_servers | paste -sd ' ')
  if [[ -n $servers ]]; then
    if _base_time_require_nts; then
      precheck_warn "Bisherige Zeitserver ohne NTS ($servers) werden nicht mehr genutzt, nur noch NTS-Quellen. Behalten: BASE_TIME_REQUIRE_NTS=0 und BASE_TIME_SERVERS=\"$servers\""
    else
      precheck_warn "Bisherige Zeitserver ($servers) werden nicht übernommen – bei Bedarf in BASE_TIME_SERVERS eintragen"
    fi
  fi
  current=$(timedatectl show -p Timezone --value 2>/dev/null)
  tz=$(cfg_get BASE_TIMEZONE Europe/Berlin)
  if [[ -n $current && $current != "$tz" ]]; then
    precheck_warn "Zeitzone wechselt von $current auf $tz – Cron-Zeiten und Zeitstempel in Logs verschieben sich"
  fi
  if os_is debian; then
    origins=$(_base_foreign_origins | paste -sd ' ')
    if [[ -n $origins ]]; then
      precheck_info "Eigene Quellen für automatische Updates bleiben erhalten: $origins"
    fi
  fi
}

# --- Actions -------------------------------------------------------------------

base::check() {
  _base_validate || return 0
  _base_check_sources
  _base_check_packages
  _base_check_updates
  _base_check_restart
  _base_check_time
  _base_check_locale
}

base::setup() {
  _base_validate || return 1
  _base_apply_sources
  pkg_update_once
  _base_install_packages
  _base_remove_packages
  _base_purge_residual
  base::configure
}

base::configure() {
  _base_validate || return 1
  if ((!DRY_RUN)); then
    local pkg
    for pkg in unattended-upgrades chrony locales; do
      if ! pkg_installed "$pkg"; then
        result_fail "Paket $pkg fehlt – zuerst 'srvctl setup base'"
        return 1
      fi
    done
  fi
  _base_apply_updates
  _base_apply_time
  _base_apply_locale
}

# No base::rollback: the default restores all files changed by the last run.
# Installed or removed packages are not reverted.
