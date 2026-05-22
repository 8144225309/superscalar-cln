#ifndef SUPERSCALAR_SS_DB_H
#define SUPERSCALAR_SS_DB_H

/* ============================================================================
 * ss_db: SQLite layer for the two databases owned by the consolidated plugin.
 *
 * Replaces the Node.js soupwallet-cln-plugin's role. See
 * ARCHITECTURE_TWO_DB_ONE_PLUGIN.md for the design rationale.
 *
 * Two databases:
 *   - ss_lib_db        — lib-owned binary state (factory_state BLOBs)
 *   - ss_plugin_db     — plugin-owned policy / coordination state
 *
 * Open / close pair called from plugin init() / shutdown.
 * Both opened with synchronous=FULL and WAL journal mode.
 * ============================================================================ */

#include <sqlite3.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Singleton handles. NULL before init / after close. */
extern sqlite3 *ss_lib_db;
extern sqlite3 *ss_plugin_db;

/* Config option storage (set via plugin_option, read at init). */
extern char *ss_lib_db_path_override;
extern char *ss_plugin_db_path_override;

/* Open both DBs read-write. Creates files + schemas if absent.
 *
 * Returns true on success, false on failure (with a plugin_log entry
 * describing the failure). Plugin should refuse to start on false.
 *
 * Idempotent: calling on an already-open handle returns true immediately. */
bool ss_db_init(void);

/* Close both DBs. Safe to call even if not initialized. */
void ss_db_close(void);

/* Resolve the path used for a given DB, honoring (in order):
 *   1. The plugin_option override (ss_lib_db_path_override etc.)
 *   2. The environment variable (SUPERSCALAR_LIB_DB_PATH etc.)
 *   3. Default: <CWD>/<filename>  (CLN runs plugins with cwd = network datadir)
 *
 * Returned buffer is tal-allocated against the passed ctx. */
char *ss_db_resolve_lib_path(const void *ctx);
char *ss_db_resolve_plugin_path(const void *ctx);

/* Current schema version for each DB. -1 if not initialized. */
int ss_db_lib_schema_version(void);
int ss_db_plugin_schema_version(void);

/* ============================================================================
 * Transaction helpers.
 *
 * Standard write pattern for cross-DB updates:
 *
 *     if (!ss_db_begin_lib())              return error;
 *     // ... writes to ss_lib_db ...
 *     if (!ss_db_commit_lib())             return error;   // lib durable
 *     if (!ss_db_begin_plugin())           return error;
 *     // ... writes to ss_plugin_db ...
 *     if (!ss_db_commit_plugin())          return error;   // plugin durable
 *
 * Order matters: lib DB commits first (it's the protocol's ground truth).
 * Both commits are required-success. A failed commit MUST bubble up to the
 * caller as a hard error — no silent fall-through. See the design doc.
 * ============================================================================ */
bool ss_db_begin_lib(void);
bool ss_db_commit_lib(void);
bool ss_db_rollback_lib(void);

bool ss_db_begin_plugin(void);
bool ss_db_commit_plugin(void);
bool ss_db_rollback_plugin(void);


/* ============================================================================
 * Plugin-side helpers for the legacy ss_save_factory call sites. These
 * replace the jsonrpc_request_start("wallet-set-setting", ...) and
 * jsonrpc_request_start("wallet-upsert-factory", ...) RPC dual-writes
 * with direct SQLite writes to ss_plugin_db.
 *
 * Wallet UI continues to call the same wallet-* RPCs (now served by
 * ss_wallet_rpc.c in the C plugin), so the wire shape is preserved.
 * ============================================================================ */

/* INSERT OR REPLACE on ss_plugin_db.wallet_settings.
 * Value is JSON-stringified hex of the blob (matching the sidecar format
 * so old and new readers see the same shape).
 * Returns true on success. */
bool ss_db_set_setting_blob(const char *key, const uint8_t *data, size_t len);

/* INSERT OR REPLACE on ss_plugin_db.factories.
 * archived defaults to 0; pass non-zero to mark a factory as hidden.
 * Returns true on success. */
bool ss_db_upsert_factory_row(const uint8_t iid[32], uint32_t my_role,
                              uint32_t created_at_block, uint32_t state,
                              uint32_t archived);




/* Session 5a (real-time push + offline catchup): append a row to
 * event_log. Used by C-side handlers to make events visible to
 * connected wallets (live push) AND queued for offline wallets to
 * fetch on reconnect via wallet-list-events-since. payload_json must
 * already be valid JSON (the caller formats it); iid may be NULL for
 * non-factory events. Returns true on success. */
bool ss_db_emit_event(const char *type, const uint8_t iid_or_null[32],
                      const char *payload_json);


#endif /* SUPERSCALAR_SS_DB_H */
