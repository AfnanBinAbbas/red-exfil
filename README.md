# red-exfil

Phase 5 — objective completion:

- `idor_enum.py` — sequential id walk → record files, email/phone aggregation, optional photo pull
- `log_pii_extract.sh` — fetch exposed app logs → PII emails/fields/secrets
- `mysql_dump.sh` — mysqldump chain with PII-table prioritization (creds via CLI args — NEVER hardcoded)

```bash
./phases/05-exfil.sh --target host
python3 checks/idor_enum.py --base https://host --path '/item/{id}' --start 1 --end 200 --out loot/idor
./checks/mysql_dump.sh --target x -- <db-host> 3306 <db-user> '<db-pass>' "db1,db2"
```

DB creds arrive as arguments/env only; nothing sensitive is committed.
Authorized targets only.
