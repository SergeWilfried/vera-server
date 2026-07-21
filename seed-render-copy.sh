#!/usr/bin/env bash
# Seed a DEPLOYED Verawall database by copying a pristine local demo dataset
# (tenant wallet-acme) into it. No MASTER_KEY / HMAC key needed — this is a
# direct table copy, not an ingest run. Idempotent: it clears the target's
# wallet-acme demo rows first, so it is safe to re-run.
#
# Prereqs: a locally-seeded source DB (default `vera_seed`). To build one:
#   createdb vera_seed
#   DATABASE_URL=postgres://localhost/vera_seed PORT=8091 ./fraud-ingest-server-go/vera-go &
#   for i in 1 2 3; do node fraud-ingest-server/simulate-sdk.js seed http://localhost:8091; done
#
# Usage:  ./seed-render-copy.sh "postgresql://…external-db-url…/vera_vault"
set -euo pipefail

DEST="${1:-}"
LOCAL="${LOCAL_DB:-vera_seed}"
if [ -z "$DEST" ]; then echo "usage: ./seed-render-copy.sh <target-database-url>"; exit 1; fi

echo "→ clearing existing wallet-acme demo rows on the target …"
psql "$DEST" -v ON_ERROR_STOP=1 <<'SQL'
DELETE FROM case_events  WHERE case_id IN (SELECT id FROM cases WHERE tenant_id='wallet-acme');
DELETE FROM actions      WHERE tenant_id='wallet-acme';
DELETE FROM cases        WHERE tenant_id='wallet-acme';
DELETE FROM alerts       WHERE tenant_id='wallet-acme';
DELETE FROM decisions    WHERE tenant_id='wallet-acme';
DELETE FROM bank_txns    WHERE tenant_id='wallet-acme';
DELETE FROM events       WHERE tenant_id='wallet-acme';
DELETE FROM user_devices WHERE tenant_id='wallet-acme';
DELETE FROM devices      WHERE tenant_id='wallet-acme';
DELETE FROM app_users    WHERE tenant_id='wallet-acme';
DELETE FROM sessions     WHERE tenant_id='wallet-acme';
SQL

copy () {  # copy(table, where)
  echo "  copying $1 …"
  psql "$LOCAL" -c "\copy (SELECT * FROM $1 WHERE $2) TO STDOUT" \
    | psql "$DEST" -v ON_ERROR_STOP=1 -c "\copy $1 FROM STDIN"
}

# parents before children (case_events → cases, actions → alerts; the rest
# reference only tenants, which already exists on the target)
copy sessions     "tenant_id='wallet-acme'"
copy app_users    "tenant_id='wallet-acme'"
copy devices      "tenant_id='wallet-acme'"
copy user_devices "tenant_id='wallet-acme'"
copy events    "tenant_id='wallet-acme'"
copy bank_txns "tenant_id='wallet-acme'"
copy decisions "tenant_id='wallet-acme' AND signals IS NOT NULL"
copy alerts    "tenant_id='wallet-acme'"
copy cases     "tenant_id='wallet-acme'"
copy actions   "tenant_id='wallet-acme'"
echo "  copying case_events …"
psql "$LOCAL" -c "\copy (SELECT ce.* FROM case_events ce JOIN cases c ON c.id=ce.case_id WHERE c.tenant_id='wallet-acme') TO STDOUT" \
  | psql "$DEST" -v ON_ERROR_STOP=1 -c "\copy case_events FROM STDIN"

echo "→ advancing sequences so new inserts don't collide …"
psql "$DEST" -v ON_ERROR_STOP=1 <<'SQL'
SELECT setval('alert_seq',          greatest((SELECT coalesce(max(substring(id from 5)::int),1) FROM alerts), 1));
SELECT setval('case_seq',           greatest((SELECT coalesce(max(substring(id from 3)::int),1) FROM cases), 1));
SELECT setval('action_seq',         greatest((SELECT coalesce(max(substring(id from 5)::int),1) FROM actions), 1));
SELECT setval('events_id_seq',      greatest((SELECT coalesce(max(id),1) FROM events), 1));
SELECT setval('decisions_id_seq',   greatest((SELECT coalesce(max(id),1) FROM decisions), 1));
SELECT setval('bank_txns_id_seq',   greatest((SELECT coalesce(max(id),1) FROM bank_txns), 1));
SELECT setval('case_events_id_seq', greatest((SELECT coalesce(max(id),1) FROM case_events), 1));
SQL

echo "✓ done —"
psql "$DEST" -tc "SELECT threat_type||': '||count(*) FROM alerts WHERE tenant_id='wallet-acme' GROUP BY threat_type ORDER BY count(*) DESC;"
psql "$DEST" -tAc "SELECT count(*) FROM cases WHERE tenant_id='wallet-acme'" | sed 's/^/  cases: /'
