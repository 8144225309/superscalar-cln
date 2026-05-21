#!/usr/bin/env python3
"""Migration script: split soupwallet.db into libsuperscalar.db + superscalar-cln.db.

Per ARCHITECTURE_TWO_DB_ONE_PLUGIN.md.

Run with the node STOPPED. Per-node invocation:

    migrate_soupwallet_to_two_dbs.py \\
        --soupwallet /var/lib/pirq-t4-a/soupwallet.db \\
        --lib-out    /var/lib/pirq-t4-a/testnet4/libsuperscalar.db \\
        --plugin-out /var/lib/pirq-t4-a/testnet4/superscalar-cln.db

Idempotent: re-running after a successful migration is a no-op.

The script:
  1. Reads wallet_settings rows from soupwallet.db whose key matches
     factory_blob:<iid>:<column> and decodes them into structured BLOB
     columns of libsuperscalar.db's factory_state table.
  2. Copies all other tables (factories, client_signing_prefs, etc.)
     verbatim from soupwallet.db -> superscalar-cln.db.
  3. Renames soupwallet.db -> soupwallet.db.pre-refactor for rollback.

If lib-out or plugin-out already exist (created by the C plugin's
ss_db_init), the script adds/updates rows in place — does not drop
the existing schema.
"""

import argparse
import json
import os
import re
import sqlite3
import sys

# Embedded schemas — match ss_db.c. Used to create dest DBs if absent
# (for dry-run testing; in production ss_db_init creates them).
LIB_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS factory_state (
    factory_instance_id   BLOB PRIMARY KEY,
    meta_blob             BLOB NOT NULL,
    signed_txs_blob       BLOB,
    dist_tx_blob          BLOB,
    channels_blob         BLOB,
    updated_at_block      INTEGER NOT NULL
) WITHOUT ROWID;
INSERT OR IGNORE INTO schema_version (version, applied_at)
    VALUES (1, strftime('%s','now'));
"""

PLUGIN_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS factories (factory_instance_id BLOB PRIMARY KEY, my_role INTEGER NOT NULL, display_label TEXT, created_at_block INTEGER NOT NULL, joined_at_block INTEGER, state INTEGER NOT NULL, last_seen_at INTEGER NOT NULL, archived INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS lsp_join_queue (factory_instance_id BLOB NOT NULL, client_pubkey BLOB NOT NULL, request_id INTEGER NOT NULL, contribution_sats INTEGER NOT NULL, received_at_block INTEGER NOT NULL, accepted_at_block INTEGER, decided_at_block INTEGER, last_seen_block INTEGER, status INTEGER NOT NULL, reason TEXT, PRIMARY KEY (factory_instance_id, client_pubkey));
CREATE TABLE IF NOT EXISTS outgoing_joins (factory_instance_id BLOB NOT NULL, lsp_pubkey BLOB NOT NULL, request_id INTEGER NOT NULL, contribution_sats INTEGER NOT NULL, sent_at_block INTEGER NOT NULL, expected_signing_block INTEGER, updated_at_block INTEGER NOT NULL, status INTEGER NOT NULL, reason TEXT, PRIMARY KEY (factory_instance_id, lsp_pubkey));
CREATE TABLE IF NOT EXISTS iid_counter (id INTEGER PRIMARY KEY CHECK (id = 0), counter INTEGER NOT NULL, updated_at INTEGER NOT NULL);
INSERT OR IGNORE INTO iid_counter (id, counter, updated_at) VALUES (0, 0, strftime('%s','now'));
CREATE TABLE IF NOT EXISTS factory_policy_snapshots (factory_instance_id BLOB PRIMARY KEY, policy_schema_version INTEGER NOT NULL, policy_tlv BLOB NOT NULL, captured_at_block INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS lsp_operator_prefs (factory_instance_id BLOB, pref_key TEXT NOT NULL, pref_value TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (factory_instance_id, pref_key));
CREATE TABLE IF NOT EXISTS client_signing_prefs (factory_instance_id BLOB NOT NULL, pref_key TEXT NOT NULL, pref_value TEXT NOT NULL, updated_at INTEGER NOT NULL, PRIMARY KEY (factory_instance_id, pref_key));
CREATE TABLE IF NOT EXISTS peer_notes (peer_pubkey BLOB PRIMARY KEY, label TEXT, body TEXT, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS peer_reputation (peer_pubkey BLOB PRIMARY KEY, score INTEGER NOT NULL, n_observations INTEGER NOT NULL, last_observed_at INTEGER NOT NULL, source TEXT);
CREATE TABLE IF NOT EXISTS custom_join_rules (rule_id INTEGER PRIMARY KEY AUTOINCREMENT, role INTEGER NOT NULL, rule_type TEXT NOT NULL, rule_value TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS discovery_history (lsp_pubkey BLOB NOT NULL, factory_count INTEGER NOT NULL, browsed_at_block INTEGER NOT NULL, snapshot_tlv BLOB, PRIMARY KEY (lsp_pubkey, browsed_at_block));
CREATE TABLE IF NOT EXISTS fiat_rate_cache (currency TEXT PRIMARY KEY, rate_sat_per_unit INTEGER NOT NULL, fetched_at INTEGER NOT NULL, source TEXT);
CREATE TABLE IF NOT EXISTS wallet_settings (setting_key TEXT PRIMARY KEY, setting_value TEXT NOT NULL, updated_at INTEGER NOT NULL);
INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (1, strftime('%s','now'));
"""

FACTORY_BLOB_RE = re.compile(r'^factory_blob:([0-9a-f]{64}):(meta|signed-txs|dist-tx|channels)$')

COLUMN_MAP = {
    'meta':         'meta_blob',
    'signed-txs':   'signed_txs_blob',
    'dist-tx':      'dist_tx_blob',
    'channels':     'channels_blob',
}

# Tables that move verbatim to superscalar-cln.db.
# wallet_settings is special: only the non-factory_blob:* rows go over.
PLUGIN_TABLES = [
    'schema_version',
    'factories',
    'lsp_join_queue',
    'outgoing_joins',
    'iid_counter',
    'factory_policy_snapshots',
    'lsp_operator_prefs',
    'client_signing_prefs',
    'peer_notes',
    'peer_reputation',
    'custom_join_rules',
    'discovery_history',
    'fiat_rate_cache',
]


def hex_to_bytes(h: str) -> bytes:
    return bytes.fromhex(h)


def decode_stored_setting(value: str) -> str:
    """The sidecar stores wallet_settings values as JSON-encoded (JSON.stringify).
    For factory_blob:* rows the original value was a hex string, so JSON-stringify
    wraps it as '"<hex>"'. Strip the quotes back to get the hex string."""
    if value is None:
        return ''
    if isinstance(value, bytes):
        value = value.decode('utf-8', errors='replace')
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, ValueError):
        return value  # not JSON; assume raw hex
    if isinstance(decoded, str):
        return decoded
    return str(decoded)


def get_columns(conn: sqlite3.Connection, table: str) -> list:
    return [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]


def copy_table(src: sqlite3.Connection, dst: sqlite3.Connection, table: str):
    """Copy all rows from src.<table> to dst.<table>. INSERT OR REPLACE
    so re-running is idempotent."""
    src_cols = get_columns(src, table)
    dst_cols = get_columns(dst, table)
    if not src_cols:
        print(f"  [skip] {table}: not present in source")
        return
    if not dst_cols:
        print(f"  [skip] {table}: not present in destination; skipping")
        return
    common = [c for c in src_cols if c in dst_cols]
    if not common:
        print(f"  [skip] {table}: no common columns")
        return
    placeholders = ','.join('?' for _ in common)
    col_list = ','.join(common)
    rows = src.execute(f"SELECT {col_list} FROM {table}").fetchall()
    if not rows:
        print(f"  [empty] {table}")
        return
    dst.executemany(f"INSERT OR REPLACE INTO {table} ({col_list}) VALUES ({placeholders})", rows)
    print(f"  [copied] {table}: {len(rows)} rows")


def migrate_factory_blobs(src: sqlite3.Connection, lib: sqlite3.Connection,
                          current_block: int = 0):
    """Decode factory_blob:<iid>:<column> k/v rows from src.wallet_settings
    into lib.factory_state structured columns."""
    # Group rows by IID first
    blobs = {}  # iid_hex -> {column_name: bytes}
    rows = src.execute(
        "SELECT setting_key, setting_value FROM wallet_settings "
        "WHERE setting_key LIKE 'factory_blob:%'"
    ).fetchall()
    for key, value in rows:
        m = FACTORY_BLOB_RE.match(key)
        if not m:
            print(f"  [skip] unrecognised key: {key}")
            continue
        iid_hex, col_name = m.group(1), m.group(2)
        target_col = COLUMN_MAP.get(col_name)
        if not target_col:
            continue
        if iid_hex not in blobs:
            blobs[iid_hex] = {}
        hex_value = decode_stored_setting(value)
        try:
            blobs[iid_hex][target_col] = hex_to_bytes(hex_value)
        except ValueError as e:
            print(f"  [skip] {key}: hex decode failed ({e}); first 32 chars: {hex_value[:32]!r}")
            continue

    # Write each as one factory_state row (meta_blob is NOT NULL).
    n_written = 0
    n_skipped = 0
    for iid_hex, cols in blobs.items():
        if 'meta_blob' not in cols:
            print(f"  [warn] {iid_hex[:8]}: no meta_blob; skipping factory_state row")
            n_skipped += 1
            continue
        iid_bytes = hex_to_bytes(iid_hex)
        lib.execute(
            "INSERT OR REPLACE INTO factory_state "
            "(factory_instance_id, meta_blob, signed_txs_blob, dist_tx_blob, "
            " channels_blob, updated_at_block) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                iid_bytes,
                cols['meta_blob'],
                cols.get('signed_txs_blob'),
                cols.get('dist_tx_blob'),
                cols.get('channels_blob'),
                current_block,
            )
        )
        n_written += 1
    print(f"  [migrated] {n_written} factory_state rows ({n_skipped} skipped)")
    return n_written


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--soupwallet', required=True,
                   help='Path to existing soupwallet.db (input)')
    p.add_argument('--lib-out', required=True,
                   help='Path to libsuperscalar.db (output; may already exist from ss_db_init)')
    p.add_argument('--plugin-out', required=True,
                   help='Path to superscalar-cln.db (output; may already exist from ss_db_init)')
    p.add_argument('--current-block', type=int, default=0,
                   help='Block height to stamp on migrated factory_state rows')
    p.add_argument('--keep-source', action='store_true',
                   help="Don't rename soupwallet.db to .pre-refactor after success")
    args = p.parse_args()

    if not os.path.exists(args.soupwallet):
        print(f"FATAL: soupwallet.db not found at {args.soupwallet}", file=sys.stderr)
        sys.exit(1)

    print(f"== Migration starting ==")
    print(f"  source: {args.soupwallet}")
    print(f"  lib:    {args.lib_out}")
    print(f"  plugin: {args.plugin_out}")

    src = sqlite3.connect(args.soupwallet)
    lib = sqlite3.connect(args.lib_out)
    plugin = sqlite3.connect(args.plugin_out)
    try:
        lib.execute('PRAGMA journal_mode = WAL')
        lib.execute('PRAGMA synchronous = FULL')
        plugin.execute('PRAGMA journal_mode = WAL')
        plugin.execute('PRAGMA synchronous = FULL')

        # Apply schemas if missing (for dry-run; idempotent in production).
        lib.executescript(LIB_SCHEMA)
        plugin.executescript(PLUGIN_SCHEMA)
        lib.commit()
        plugin.commit()

        print("== Step 1: migrate factory_blob:* rows to lib.factory_state ==")
        migrate_factory_blobs(src, lib, args.current_block)
        lib.commit()

        print("== Step 2: copy non-blob tables to superscalar-cln.db ==")
        for t in PLUGIN_TABLES:
            copy_table(src, plugin, t)

        print("== Step 3: copy non-factory_blob wallet_settings rows ==")
        ws_cols = get_columns(plugin, 'wallet_settings')
        if ws_cols:
            rows = src.execute(
                "SELECT setting_key, setting_value, updated_at FROM wallet_settings "
                "WHERE setting_key NOT LIKE 'factory_blob:%'"
            ).fetchall()
            if rows:
                plugin.executemany(
                    "INSERT OR REPLACE INTO wallet_settings "
                    "(setting_key, setting_value, updated_at) VALUES (?, ?, ?)",
                    rows
                )
                print(f"  [copied] wallet_settings: {len(rows)} non-blob rows")
            else:
                print("  [empty] wallet_settings: no non-blob rows")
        plugin.commit()

    finally:
        src.close()
        lib.close()
        plugin.close()

    if not args.keep_source:
        backup = args.soupwallet + '.pre-refactor'
        os.rename(args.soupwallet, backup)
        print(f"== Source renamed to: {backup} (rollback path) ==")

    print("== Migration complete ==")


if __name__ == '__main__':
    main()
