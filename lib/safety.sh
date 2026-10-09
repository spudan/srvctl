# shellcheck shell=bash
# Safety: backups, restore, dry-run aware command execution, confirmations
# and idempotent file writes.
#
# Backups live in BACKUP_DIR/<RUN_ID>/<original path>. Each run directory has a
# MANIFEST with lines "KIND<TAB>module<TAB>path<TAB>action":
#   SAVED       file was saved before the change
#   ABSENT      file did not exist before, so a restore removes it
#   ROLLEDBACK  the module's changes of this run were rolled back (path = "-")
# Rollbacks work like an undo stack: each rollback undoes the newest run of the
# module that is neither a rollback run nor already rolled back.

BACKUP_DIR=""
BACKUP_RUN_DIR=""
FILE_CHANGED=0

backup_init() {
  BACKUP_DIR=${SRVCTL_BACKUP_DIR:-/var/backups/srvctl}
  BACKUP_RUN_DIR="${BACKUP_DIR}/${RUN_ID}"
}

# _manifest_kind RUN_DIR PATH - prints SAVED/ABSENT of the entry for PATH
_manifest_kind() {
  [[ -f $1/MANIFEST ]] || return 1
  _P=$2 awk -F'\t' '($1 == "SAVED" || $1 == "ABSENT") && $3 == ENVIRON["_P"] { k = $1 } END { if (k == "") exit 1; print k }' "$1/MANIFEST"
}

# backup_file PATH - saves PATH once per run before it gets modified
backup_file() {
  local src
  src=$(realpath -m -- "$1")
  _manifest_kind "$BACKUP_RUN_DIR" "$src" >/dev/null && return 0

  if ((DRY_RUN)); then
    log_dry "Backup: $src"
    return 0
  fi

  [[ -d $src && ! -L $src ]] && {
    log_error "backup_file unterstützt nur Dateien: $src"
    return 1
  }
  (umask 077 && mkdir -p -- "$BACKUP_RUN_DIR") || return 1

  local kind=ABSENT
  if [[ -e $src || -L $src ]]; then
    (umask 077 && mkdir -p -- "$(dirname -- "${BACKUP_RUN_DIR}${src}")") &&
      cp -a -- "$src" "${BACKUP_RUN_DIR}${src}" || {
      log_error "Backup von $src fehlgeschlagen"
      return 1
    }
    kind=SAVED
  fi
  printf '%s\t%s\t%s\t%s\n' "$kind" "${CURRENT_MODULE:-srvctl}" "$src" "${CURRENT_ACTION:-}" \
    >>"${BACKUP_RUN_DIR}/MANIFEST"
  log_debug "Backup ($kind): $src"
}

# Prints run IDs of all backups, newest first, excluding the current run.
_backup_runs() {
  local -a runs=("$BACKUP_DIR"/*/)
  local i run
  for ((i = ${#runs[@]} - 1; i >= 0; i--)); do
    run=$(basename -- "${runs[i]}")
    [[ $run == "$RUN_ID" ]] || echo "$run"
  done
}

# backup_restore PATH [RUN_ID] - restores PATH from the newest (or given) backup
backup_restore() {
  local path run=${2:-} kind
  path=$(realpath -m -- "$1")
  if [[ -z $run ]]; then
    while read -r run; do
      _manifest_kind "${BACKUP_DIR}/${run}" "$path" >/dev/null && break
      run=""
    done < <(_backup_runs)
  fi
  kind=$(_manifest_kind "${BACKUP_DIR}/${run}" "$path") || {
    log_error "Kein Backup gefunden für $path"
    return 1
  }

  case $kind in
    SAVED)
      if ((DRY_RUN)); then
        log_dry "Wiederherstellen: $path (Backup $run)"
        return 0
      fi
      backup_file "$path" || return 1
      cp -a -- "${BACKUP_DIR}/${run}${path}" "${path}.srvctl-restore" &&
        mv -f -- "${path}.srvctl-restore" "$path" || return 1
      log_info "Wiederhergestellt: $path (Backup $run)"
      ;;
    ABSENT)
      [[ -e $path || -L $path ]] || return 0
      if ((DRY_RUN)); then
        log_dry "Entfernen: $path (existierte vor $run nicht)"
        return 0
      fi
      backup_file "$path" || return 1
      rm -f -- "$path"
      log_info "Entfernt: $path (existierte vor $run nicht)"
      ;;
  esac
}

# backup_restore_module MODULE - undoes the newest run of MODULE that is not a
# rollback itself and was not rolled back yet. Used as default rollback.
backup_restore_module() {
  local mod=$1 run="" path
  while read -r run; do
    [[ -f ${BACKUP_DIR}/${run}/MANIFEST ]] &&
      awk -F'\t' -v m="$mod" '$2 != m { next }
        $1 == "ROLLEDBACK" { done = 1 }
        ($1 == "SAVED" || $1 == "ABSENT") && $4 != "rollback" { f = 1 }
        END { exit !(f && !done) }' "${BACKUP_DIR}/${run}/MANIFEST" && break
    run=""
  done < <(_backup_runs)

  if [[ -z $run ]]; then
    result_skip "Keine Änderungen zum Zurücksetzen vorhanden"
    return 0
  fi

  log_info "Setze Änderungen aus Lauf $run zurück"
  local rc=0
  while IFS= read -r path; do
    backup_restore "$path" "$run" || rc=1
  done < <(awk -F'\t' -v m="$mod" '$2 == m && ($1 == "SAVED" || $1 == "ABSENT") && !seen[$3]++ { print $3 }' \
    "${BACKUP_DIR}/${run}/MANIFEST")

  if ((rc == 0)) && ((!DRY_RUN)); then
    printf 'ROLLEDBACK\t%s\t-\t%s\n' "$mod" "$RUN_ID" >>"${BACKUP_DIR}/${run}/MANIFEST"
  fi
  if ((rc == 0)); then
    result_ok "Änderungen aus Lauf $run zurückgesetzt (Dienste ggf. neu starten)"
  else
    result_fail "Zurücksetzen aus Lauf $run unvollständig"
  fi
  return "$rc"
}

backup_list() {
  local -a runs
  mapfile -t runs < <(_backup_runs)
  if ((${#runs[@]} == 0)); then
    log_info "Keine Backups in $BACKUP_DIR"
    return 0
  fi
  printf '%s%-24s %-7s %s%s\n' "$C_BOLD" "Lauf" "Dateien" "Module (Aktion)" "$C_RESET"
  local run m
  for run in "${runs[@]}"; do
    m="${BACKUP_DIR}/${run}/MANIFEST"
    [[ -f $m ]] || continue
    awk -F'\t' -v run="$run" '
      $1 == "ROLLEDBACK" { rb[$2] = 1; next }
      { files++; if (!seen[$2]++) mods[++n] = $2; act[$2] = $4 }
      END {
        for (i = 1; i <= n; i++)
          out = out (i > 1 ? ", " : "") mods[i] " (" (act[mods[i]] == "" ? "?" : act[mods[i]]) \
            (rb[mods[i]] ? ", zurückgesetzt" : "") ")"
        printf "%-24s %-7d %s\n", run, files, out
      }' "$m"
  done
  printf '\nVerzeichnis: %s\n' "$BACKUP_DIR"
}

# Removes old backup runs, keeping SRVCTL_BACKUP_KEEP (default 30).
backup_prune() {
  local keep=${SRVCTL_BACKUP_KEEP:-30} run
  local -a runs
  mapfile -t runs < <(_backup_runs)
  for run in "${runs[@]:$keep}"; do
    rm -rf -- "${BACKUP_DIR:?}/${run:?}"
    log_debug "Altes Backup entfernt: $run"
  done
}

# run_cmd CMD [ARGS...] - executes a command, or only shows it in dry-run mode
run_cmd() {
  local cmd rc=0
  printf -v cmd '%q ' "$@"
  cmd=${cmd% }
  if ((DRY_RUN)); then
    log_dry "$cmd"
    return 0
  fi
  _log_file CMD "$cmd"
  ((VERBOSE)) && printf '    %s$ %s%s\n' "$C_DIM" "$cmd" "$C_RESET"
  "$@" || rc=$?
  ((rc == 0)) || _log_file ERROR "Exit-Code $rc: $cmd"
  return "$rc"
}

# confirm QUESTION - yes/no prompt; true with --yes or --dry-run
confirm() {
  ((ASSUME_YES)) && return 0
  if ((DRY_RUN)); then
    log_dry "Rückfrage: $1 -> ja (Probelauf)"
    return 0
  fi
  if ! (: </dev/tty) 2>/dev/null; then
    log_warn "Keine Rückfrage möglich (kein Terminal) – mit --yes bestätigen: $1"
    return 1
  fi
  local answer
  read -r -p "${C_BOLD}?${C_RESET} $1 [j/N] " answer </dev/tty || return 1
  _log_file CONFIRM "$1 -> ${answer:-N}"
  [[ ${answer,,} =~ ^(j|ja|y|yes)$ ]]
}

# write_file PATH [MODE] [OWNER] <CONTENT - writes stdin to PATH if it differs.
# Creates a backup first, writes atomically and keeps mode/owner of an
# existing file unless MODE/OWNER are given. Sets FILE_CHANGED=0/1.
# Feed it with "<<<" or "< <(...)", not a pipe, so FILE_CHANGED stays visible.
write_file() {
  local dest=$1 mode=${2:-} owner=${3:-} tmp
  [[ -L $dest ]] && dest=$(readlink -f -- "$dest")
  tmp=$(mktemp "${RUN_DIR}/write.XXXXXX") || return 1
  cat >"$tmp"
  FILE_CHANGED=0

  if [[ -f $dest ]] && cmp -s -- "$tmp" "$dest"; then
    log_debug "Unverändert: $dest"
    rm -f -- "$tmp"
    return 0
  fi
  FILE_CHANGED=1

  if ((DRY_RUN)); then
    log_dry "Datei ändern: $dest"
    local old=$dest
    [[ -f $dest ]] || old=/dev/null
    diff -u --label "$dest (aktuell)" --label "$dest (neu)" -- "$old" "$tmp" | sed 's/^/          /' || true
    rm -f -- "$tmp"
    return 0
  fi

  backup_file "$dest" || return 1
  mkdir -p -- "$(dirname -- "$dest")" || return 1
  local new="${dest}.srvctl-new"
  cp -- "$tmp" "$new" || return 1
  if [[ -f $dest ]]; then
    chmod --reference="$dest" -- "$new" && chown --reference="$dest" -- "$new"
  else
    chmod "${mode:-0644}" -- "$new"
  fi
  [[ -n $mode ]] && chmod "$mode" -- "$new"
  [[ -n $owner ]] && chown "$owner" -- "$new"
  mv -f -- "$new" "$dest" || return 1
  rm -f -- "$tmp"
  log_info "Geschrieben: $dest"
}
