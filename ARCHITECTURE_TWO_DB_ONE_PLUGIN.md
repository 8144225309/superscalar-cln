# Architecture: one plugin, two databases

Status: **DRAFT**, awaiting review by lib team and operator before implementation.
Author: plugin/wallet AI
Date: 2026-05-21
Tracks: task #139 (refactor), companion to LIB_TEAM_NOTE_MUSIG_PERSISTENCE.md
        and LIB_TEAM_REPLY_MUSIG_PERSISTENCE.md.

## Goal

Replace the current two-CLN-plugin deployment (C plugin `superscalar` +
Node.js plugin `soupwallet-cln-plugin`) with a single CLN plugin
(`superscalar`) that owns two SQLite databases directly. End the
RPC-based dual-write coordination between plugins. Preserve all
existing wire and JSON-RPC behaviour. Set up a clean handoff point for
the lib team to take ownership of `libsuperscalar.db`'s schema later.

## Current state (before)

```
lightningd
├── superscalar      (C, 22k+ lines)         ← bLIP-56 protocol
│   ├── opens soupwallet.db READ-ONLY at startup (to enumerate factories)
│   └── dual-writes coordination state via RPC to ──┐
│                                                    │
└── soupwallet-cln-plugin  (Node.js, 1.3kLOC) ◄─────┘
    ├── owns soupwallet.db READ-WRITE
    └── exposes 19 wallet-* RPCs over the CLN RPC bus
```

Storage today is a single SQLite file (`soupwallet.db`) holding both:

1. Coordination state in structured tables (factories, client_signing_prefs,
   lsp_operator_prefs, peer_notes, peer_reputation, custom_join_rules,
   discovery_history, fiat_rate_cache, iid_counter, factory_policy_snapshots,
   lsp_join_queue, outgoing_joins, schema_version).
2. Lib-owned binary state stuffed into a generic key/value table
   `wallet_settings` with keys like `factory_blob:<iid>:meta`,
   `factory_blob:<iid>:signed-txs`, `factory_blob:<iid>:dist-tx`,
   `factory_blob:<iid>:channels`.

Plus three plugin-managed JSON flat files for historical reasons:
`superscalar_policy_cache.json`, `superscalar_lsp_sig_queue.json`,
`superscalar_signing_prefs.json`.

## Problems with the current setup

1. **Two processes, one DB file**. The sidecar process exists only to
   own SQLite writes via RPC. Wallet UI doesn't talk to it directly
   (no HTTP server). The split adds operational complexity without a
   matching architectural benefit.

2. **Silent dual-write failures**. If the sidecar isn't loaded or its
   RPC fails, the C plugin logs a warning and continues. Audit item #1
   was exactly this symptom: `wallet-upsert-*` calls failing for
   every state change.

3. **Two config option pairs** that must stay in sync (`soupwallet-db-path=`
   on the sidecar, `superscalar-wallet-db=` on the C plugin). Silently
   diverge if only one is set. Foot-gun bit us during audit #1; the
   path log line in commit `7ab09e2` warns about it.

4. **Mixed-concern schema**. `wallet_settings` is a generic k/v bag
   holding both lib-owned binary state (factory_blob:*) and other
   junk drawer entries. The k/v shape exists because the sidecar was
   built before the lib-vs-wallet ownership split was clear.

5. **No clean handoff to lib team**. The lib has no API for persisting
   its own state — the plugin hand-serializes `factory_instance_t` to
   bytes and dumps them into the sidecar's k/v store. When the lib
   team ships `factory_open_db()` / `factory_save_state()` (task #80
   territory), there's no clean migration target.

## Target state (after)

```
lightningd
└── superscalar  (C)        ← bLIP-56 protocol + SQLite writes
    ├── libsuperscalar.db  (NEW file)         ← lib-owned binary state,
    │                                           BLOB columns in structured tables
    │                                           schema eventually owned by lib team
    └── superscalar-cln.db (renamed from soupwallet.db)
                                              ← plugin-owned policy/coordination state,
                                                schema owned by plugin team
```

Single plugin. Two SQLite files. Both opened and written by the C plugin
directly. Sidecar deleted.

## File layout

Both DB files live in the lightning datadir per network:

```
/var/lib/<node-name>/<network>/libsuperscalar.db
/var/lib/<node-name>/<network>/superscalar-cln.db
```

Default location follows CLN convention; operator can override with
plugin options (see Config below).

## Schemas

### `libsuperscalar.db`

Holds the lib's serialized binary state. Schema is intentionally minimal —
columns are opaque BLOBs because the plugin does not own the format. The
lib's serialize/deserialize functions remain the authority. The schema is
documented here as a stable contract that the plugin and any future lib
DB API can both adhere to.

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;

CREATE TABLE schema_version (
    version INTEGER PRIMARY KEY,
    applied_at_block INTEGER NOT NULL
);

CREATE TABLE factory_state (
    factory_instance_id  BLOB PRIMARY KEY,    -- 32 bytes
    meta_blob            BLOB NOT NULL,       -- lib-serialized factory_instance_t
    signed_txs_blob      BLOB,                -- lib-serialized signed DW TXs
    dist_tx_blob         BLOB,                -- lib-serialized distribution TX
    channels_blob        BLOB,                -- lib-serialized channel map
    updated_at_block     INTEGER NOT NULL
) WITHOUT ROWID;
```

Why BLOBs and not normalized columns: the contents are serialized by the
lib via `ss_persist_serialize_meta` / `ss_persist_serialize_signed_txs`
/ etc. The plugin must NOT decode the bytes — the format is the lib's
to evolve. The structured table replaces the previous k/v shape of
`factory_blob:<iid>:meta` keys; same opaque content, less stringly-typed.

### `superscalar-cln.db`

Holds plugin-owned policy/coordination state. Same set of tables that
exist today in `soupwallet.db`, minus the `wallet_settings` k/v table:

```sql
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;

-- (carried forward from existing soupwallet.db, schema unchanged)
CREATE TABLE factories ( ... );             -- coordination metadata
CREATE TABLE client_signing_prefs ( ... );  -- user thresholds, auto_sign toggle
CREATE TABLE lsp_operator_prefs ( ... );    -- LSP-side rules
CREATE TABLE peer_notes ( ... );
CREATE TABLE peer_reputation ( ... );
CREATE TABLE custom_join_rules ( ... );     -- wallet-creator-extensible
CREATE TABLE discovery_history ( ... );
CREATE TABLE fiat_rate_cache ( ... );
CREATE TABLE iid_counter ( ... );
CREATE TABLE factory_policy_snapshots ( ... ); -- LSP-advertised policy archives
CREATE TABLE lsp_join_queue ( ... );
CREATE TABLE outgoing_joins ( ... );
CREATE TABLE schema_version ( ... );
```

The exact column lists are carried verbatim from the current
soupwallet.db so that the migration is a simple copy. See
`migrate-soupwallet-to-two-dbs.py` (Phase 4 deliverable).

## Write discipline

### `synchronous=FULL` on both DBs

Matches CLN's `lightningd.sqlite3` setting and the `better-sqlite3`
default that the sidecar uses today. Each COMMIT fsyncs before
returning. This is the standard for fund-critical SQLite usage.
Trade-off (~1-10ms per commit on SSD) is acceptable at LN write rates.

### Write order: lib DB COMMIT → plugin DB COMMIT

When a logical operation needs to update both DBs (most ceremony state
transitions do), the lib DB write completes first.

```c
sqlite3_exec(lib_db, "BEGIN IMMEDIATE TRANSACTION", ...);
// ... lib state updates ...
if (sqlite3_exec(lib_db, "COMMIT", ...) != SQLITE_OK)
    return error_to_caller(...);
// lib DB durable on disk now

sqlite3_exec(plugin_db, "BEGIN IMMEDIATE TRANSACTION", ...);
// ... plugin state updates ...
if (sqlite3_exec(plugin_db, "COMMIT", ...) != SQLITE_OK)
    return error_to_caller(...);
// both writes durable
```

If we crash between the two COMMITs, lib DB has the new state and
plugin DB is missing the matching row. On startup, the plugin reconciles:
any factory_state row in lib DB without a corresponding factories row
in plugin DB gets a default plugin-DB row filled in (default label,
default prefs). Self-healing.

The reverse order (plugin DB first) would leave orphan plugin rows
pointing at factories that don't exist crypto-wise — confusing and not
self-healing.

### Hard errors on COMMIT failure

Departure from current behavior. Today, dual-write RPC failures are
best-effort: log a warning and continue. Tomorrow, a failed SQLite
COMMIT bubbles up as an error to the calling RPC / wire handler. The
operation fails visibly rather than completing with inconsistent state.

Affected call sites (TBD enumeration in Phase 3):
- ss_save_factory (~12 call sites)
- ss_save_outgoing_joins
- ss_save_incoming_joins
- factory-approve-proposal / factory-refuse-proposal
- client-signing-prefs-set
- Everywhere wallet-set-setting was previously called

## JSON-RPC compatibility

The 19 wallet-* RPCs the sidecar exposes today are reimplemented in C
inside the superscalar plugin with **byte-identical** request/response
shapes:

- wallet-upsert-factory
- wallet-get-factory
- wallet-list-factories-by-role
- wallet-get-factory-policy-snapshot
- wallet-save-factory-policy-snapshot
- wallet-get-signing-pref / wallet-set-signing-pref
- wallet-get-operator-pref / wallet-set-operator-pref
- wallet-get-setting / wallet-set-setting
- wallet-get-iid-counter / wallet-set-iid-counter / wallet-increment-iid-counter
- wallet-list-join-queue-by-status / wallet-upsert-join-queue-entry
- wallet-count-join-queue-by-status
- wallet-list-outgoing-joins-by-status / wallet-upsert-outgoing-join
- wallet-status

The wallet UI continues to call these by name; the dispatcher now
resolves them to the C plugin instead of the Node.js plugin. No UI
changes required.

Note: `wallet-set-setting` and `wallet-get-setting` will be retained in
the API (some callers might still use them as a generic k/v) but the
`factory_blob:<iid>:*` keys are deprecated. After migration these keys
won't be served — readers should use structured factory-state RPCs
instead.

## Config options

### Removed

- `soupwallet-db-path=` (sidecar option, no longer relevant)
- `superscalar-wallet-db=` (sidecar-side read-only mirror, no longer
  needed since the plugin owns the file directly)

### Added

- `libsuperscalar-db-path=` (string, optional) — path to libsuperscalar.db.
  Default: `<lightning-dir>/<network>/libsuperscalar.db`.
- `superscalar-cln-db-path=` (string, optional) — path to superscalar-cln.db.
  Default: `<lightning-dir>/<network>/superscalar-cln.db`.

Both default to the lightning datadir, so most operators won't need to
set either.

The existing `--enable-session-restore` flag stays.

## Migration

Per-node one-shot Python script (`migrate-soupwallet-to-two-dbs.py`):

1. Stop the node.
2. Copy current `soupwallet.db` → `soupwallet.db.pre-refactor` for rollback.
3. Create new `libsuperscalar.db` with target schema.
4. Walk `wallet_settings` rows; for each `factory_blob:<iid>:<column>`
   key, decode the hex value and write to `factory_state` BLOB column.
5. Copy all other tables (factories, client_signing_prefs, ...) from
   `soupwallet.db` to `superscalar-cln.db` (rename + remove wallet_settings).
6. Update node config: remove old options/plugin, add new options.
7. Restart node, verify factories load and operations work.

Rollback path: stop node, restore `soupwallet.db.pre-refactor`, revert
config, restart with sidecar plugin.

## Out of scope (deferred to follow-up PRs)

- **Retention/purge columns and policies.** Revisit when we see actual
  growth patterns.
- **Backup tooling.** Mirror CLN's `chanbackup` peer-storage pattern.
  HSM-derived encryption keys per DB. Restore RPC. Periodic restore
  drills. Estimated ~1-2 weeks; not blocking the refactor.
- **Encryption at rest.** Bundles with backup work; same HSM-derived
  key infrastructure.
- **Hook-based extensibility** for signing decisions. Current validator
  + signing prefs + held-proposals review is sufficient until a real
  third-party consumer asks for hooks.
- **Lib team adoption of `libsuperscalar.db` schema.** When the lib
  team ships `factory_open_db()` / `factory_save_state()` /
  `factory_restore_sessions()`, the plugin swaps the direct SQLite
  ops for lib API calls without changing the file format. The
  `--enable-session-restore` flag (commit `e574a51`) is the integration
  point already in place.

## Compatibility and rollback

- **Wire protocol**: unchanged. Existing peers and ceremonies continue
  to work.
- **Wallet UI**: unchanged. Same wallet-* RPC names, params, and
  response shapes.
- **Rollback**: one-shot per node. Restore `soupwallet.db.pre-refactor`,
  revert config, restart with the old sidecar deployment. Until Phase 7
  archives the sidecar, rollback remains trivial.

## Open questions

1. **DB file naming.** Should we rename `libsuperscalar.db` and/or
   `superscalar-cln.db` to something else before we ship? See discussion
   tracked in task #140.
2. **Schema versioning.** Both DBs include a `schema_version` table.
   Initial version = 1. When the lib team adopts the lib DB schema,
   they bump and ship a migration; the plugin runs it on startup.
3. **Async migration RPC.** Should `migrate-soupwallet-to-two-dbs.py`
   be a standalone script, or should the plugin auto-detect a
   pre-refactor `soupwallet.db` at startup and migrate in-process?
   Auto-migrate is convenient but adds one-time-only code to the
   plugin source.

## Lib team review request

Lib team — companion read to LIB_TEAM_REPLY_MUSIG_PERSISTENCE.md.
Specifically asking for sign-off on:

- The `factory_state` table in `libsuperscalar.db` (column names,
  BLOB-only contract, indexed by factory_instance_id).
- Confirming you're comfortable taking over this schema when
  `factory_open_db()` ships, OR confirming you'd prefer to design a
  different schema and migrate later (the BLOBs are easy to copy into
  whatever shape you want).
- Anything else you'd want the plugin to commit to in the lib's
  ownership area while we're here.

## References

- Task #72 (completed): "Pivot plugin off CLN datastore: split between
  libsuperscalar SQLite (crypto/ceremony) and wallet SQLite (coordination)"
- Task #77 (completed): "Wallet daemon skeleton: SQLite + RPCs from
  schema doc"
- Task #84 (completed): "Drop CLN datastore — read+write to two-SQL
  model only"
- Audit item #1 (completed in this session, commit `1384ae0` and
  config changes): sidecar deployed and per-node DB binding fixed.
- LIB_TEAM_NOTE_MUSIG_PERSISTENCE.md (this session): plugin team
  handoff to lib team on session-restore.
- LIB_TEAM_REPLY_MUSIG_PERSISTENCE.md (this session): lib team reply
  with the preferred message-replay approach.
- Commit `e574a51` (this session): `--enable-session-restore` plugin
  option as integration point for lib's future API.
