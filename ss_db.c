/* ============================================================================
 * ss_db: SQLite layer for the two databases owned by the consolidated plugin.
 *
 * See ss_db.h and ARCHITECTURE_TWO_DB_ONE_PLUGIN.md.
 * ============================================================================ */

#include "ss_db.h"
#include <plugins/libplugin.h>
#include <ccan/tal/tal.h>
#include <ccan/tal/str/str.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <pwd.h>
#include <unistd.h>

extern struct plugin *plugin_handle;

sqlite3 *ss_lib_db = NULL;
sqlite3 *ss_plugin_db = NULL;
char *ss_lib_db_path_override = NULL;
char *ss_plugin_db_path_override = NULL;

#define SS_LIB_DB_DEFAULT_NAME     "libsuperscalar.db"
#define SS_PLUGIN_DB_DEFAULT_NAME  "superscalar-cln.db"

/* Target schema versions. Bumping these triggers migration logic. */
#define SS_LIB_DB_SCHEMA_VERSION       1
#define SS_PLUGIN_DB_SCHEMA_VERSION    1

static int ss_lib_db_version_cached = -1;
static int ss_plugin_db_version_cached = -1;

/* ============================================================================
 * Schemas
 * ============================================================================ */

static const char *ss_lib_db_schema_v1[] = {
	"CREATE TABLE IF NOT EXISTS schema_version ("
	"   version    INTEGER PRIMARY KEY,"
	"   applied_at INTEGER NOT NULL"
	");",

	/* factory_state: opaque lib-serialized blobs, one row per factory.
	 *
	 * The plugin DOES NOT decode these columns — the format is owned by
	 * libsuperscalar (ss_persist_serialize_meta / signed_txs / etc.).
	 * This table replaces the previous wallet_settings k/v shape where
	 * the same data lived under composite keys like
	 *   factory_blob:<iid>:meta, factory_blob:<iid>:signed-txs, ...
	 *
	 * BLOB columns instead of separate rows: foreign keys + DELETE
	 * cascades work cleanly, atomic update of all four blobs in one
	 * row, can query "factories with signed_txs_blob NOT NULL", etc. */
	"CREATE TABLE IF NOT EXISTS factory_state ("
	"   factory_instance_id   BLOB PRIMARY KEY,"
	"   meta_blob             BLOB NOT NULL,"
	"   signed_txs_blob       BLOB,"
	"   dist_tx_blob          BLOB,"
	"   channels_blob         BLOB,"
	"   updated_at_block      INTEGER NOT NULL"
	") WITHOUT ROWID;",

"INSERT OR IGNORE INTO schema_version (version, applied_at) "
	"VALUES (1, strftime('%s','now'));",

	NULL
};

static const char *ss_plugin_db_schema_v1[] = {
	"CREATE TABLE IF NOT EXISTS schema_version ("
	"   version    INTEGER PRIMARY KEY,"
	"   applied_at INTEGER NOT NULL"
	");",

	/* Carry-forward of the existing soupwallet.db schema. The
	 * wallet_settings k/v table stays as a general key/value store
	 * for wallet UI use; only the factory_blob:<iid>:* rows migrate
	 * out to ss_lib_db.factory_state as structured BLOB columns. */

	"CREATE TABLE IF NOT EXISTS factories ("
	"   factory_instance_id   BLOB PRIMARY KEY,"
	"   my_role               INTEGER NOT NULL,"
	"   display_label         TEXT,"
	"   created_at_block      INTEGER NOT NULL,"
	"   joined_at_block       INTEGER,"
	"   state                 INTEGER NOT NULL,"
	"   last_seen_at          INTEGER NOT NULL,"
	"   archived              INTEGER NOT NULL DEFAULT 0"
	");",
	"CREATE INDEX IF NOT EXISTS idx_factories_role_state "
	"   ON factories(my_role, state);",

	"CREATE TABLE IF NOT EXISTS lsp_join_queue ("
	"   factory_instance_id   BLOB NOT NULL,"
	"   client_pubkey         BLOB NOT NULL,"
	"   request_id            INTEGER NOT NULL,"
	"   contribution_sats     INTEGER NOT NULL,"
	"   received_at_block     INTEGER NOT NULL,"
	"   accepted_at_block     INTEGER,"
	"   decided_at_block      INTEGER,"
	"   last_seen_block       INTEGER,"
	"   status                INTEGER NOT NULL,"
	"   reason                TEXT,"
	"   PRIMARY KEY (factory_instance_id, client_pubkey)"
	");",
	"CREATE INDEX IF NOT EXISTS idx_lsp_join_queue_status "
	"   ON lsp_join_queue(factory_instance_id, status);",

	"CREATE TABLE IF NOT EXISTS outgoing_joins ("
	"   factory_instance_id    BLOB NOT NULL,"
	"   lsp_pubkey             BLOB NOT NULL,"
	"   request_id             INTEGER NOT NULL,"
	"   contribution_sats      INTEGER NOT NULL,"
	"   sent_at_block          INTEGER NOT NULL,"
	"   expected_signing_block INTEGER,"
	"   updated_at_block       INTEGER NOT NULL,"
	"   status                 INTEGER NOT NULL,"
	"   reason                 TEXT,"
	"   PRIMARY KEY (factory_instance_id, lsp_pubkey)"
	");",
	"CREATE INDEX IF NOT EXISTS idx_outgoing_joins_status "
	"   ON outgoing_joins(status, updated_at_block);",

	"CREATE TABLE IF NOT EXISTS iid_counter ("
	"   id           INTEGER PRIMARY KEY CHECK (id = 0),"
	"   counter      INTEGER NOT NULL,"
	"   updated_at   INTEGER NOT NULL"
	");",
	"INSERT OR IGNORE INTO iid_counter (id, counter, updated_at) "
	"VALUES (0, 0, strftime('%s','now'));",

	"CREATE TABLE IF NOT EXISTS factory_policy_snapshots ("
	"   factory_instance_id   BLOB PRIMARY KEY,"
	"   policy_schema_version INTEGER NOT NULL,"
	"   policy_tlv            BLOB NOT NULL,"
	"   captured_at_block     INTEGER NOT NULL"
	");",

	"CREATE TABLE IF NOT EXISTS lsp_operator_prefs ("
	"   factory_instance_id   BLOB,"
	"   pref_key              TEXT NOT NULL,"
	"   pref_value            TEXT NOT NULL,"
	"   updated_at            INTEGER NOT NULL,"
	"   PRIMARY KEY (factory_instance_id, pref_key)"
	");",

	"CREATE TABLE IF NOT EXISTS client_signing_prefs ("
	"   factory_instance_id   BLOB NOT NULL,"
	"   pref_key              TEXT NOT NULL,"
	"   pref_value            TEXT NOT NULL,"
	"   updated_at            INTEGER NOT NULL,"
	"   PRIMARY KEY (factory_instance_id, pref_key)"
	");",

	"CREATE TABLE IF NOT EXISTS peer_notes ("
	"   peer_pubkey   BLOB PRIMARY KEY,"
	"   label         TEXT,"
	"   body          TEXT,"
	"   created_at    INTEGER NOT NULL,"
	"   updated_at    INTEGER NOT NULL"
	");",

	"CREATE TABLE IF NOT EXISTS peer_reputation ("
	"   peer_pubkey      BLOB PRIMARY KEY,"
	"   score            INTEGER NOT NULL,"
	"   n_observations   INTEGER NOT NULL,"
	"   last_observed_at INTEGER NOT NULL,"
	"   source           TEXT"
	");",
	"CREATE INDEX IF NOT EXISTS idx_peer_reputation_score "
	"   ON peer_reputation(score DESC);",

	"CREATE TABLE IF NOT EXISTS custom_join_rules ("
	"   rule_id     INTEGER PRIMARY KEY AUTOINCREMENT,"
	"   role        INTEGER NOT NULL,"
	"   rule_type   TEXT NOT NULL,"
	"   rule_value  TEXT NOT NULL,"
	"   enabled     INTEGER NOT NULL DEFAULT 1,"
	"   created_at  INTEGER NOT NULL"
	");",

	"CREATE TABLE IF NOT EXISTS discovery_history ("
	"   lsp_pubkey       BLOB NOT NULL,"
	"   factory_count    INTEGER NOT NULL,"
	"   browsed_at_block INTEGER NOT NULL,"
	"   snapshot_tlv     BLOB,"
	"   PRIMARY KEY (lsp_pubkey, browsed_at_block)"
	");",

	"CREATE TABLE IF NOT EXISTS fiat_rate_cache ("
	"   currency          TEXT PRIMARY KEY,"
	"   rate_sat_per_unit INTEGER NOT NULL,"
	"   fetched_at        INTEGER NOT NULL,"
	"   source            TEXT"
	");",

	"CREATE TABLE IF NOT EXISTS wallet_settings ("
	"   setting_key      TEXT PRIMARY KEY,"
	"   setting_value    TEXT NOT NULL,"
	"   updated_at       INTEGER NOT NULL"
	");",

	"CREATE TABLE IF NOT EXISTS event_log ("
	"event_id     INTEGER PRIMARY KEY AUTOINCREMENT, "
	"type         TEXT NOT NULL, "
	"factory_iid  BLOB, "
	"payload_json TEXT NOT NULL, "
	"created_at   INTEGER NOT NULL);"
"CREATE INDEX IF NOT EXISTS idx_event_log_factory ON event_log(factory_iid);"
"CREATE INDEX IF NOT EXISTS idx_event_log_type ON event_log(type);"
	"INSERT OR IGNORE INTO schema_version (version, applied_at) "
	"VALUES (1, strftime('%s','now'));",

	NULL
};

/* ============================================================================
 * Path resolution
 * ============================================================================ */

static char *ss_db_resolve_path(const void *ctx,
				const char *override,
				const char *env_var,
				const char *default_name)
{
	if (override && override[0])
		return tal_strdup(ctx, override);

	const char *env = getenv(env_var);
	if (env && env[0])
		return tal_strdup(ctx, env);

	/* CLN runs plugins with cwd set to the network datadir
	 * (e.g. /var/lib/.../testnet4). Default DB path is alongside
	 * CLN's own lightningd.sqlite3 there. */
	return tal_fmt(ctx, "%s", default_name);
}

char *ss_db_resolve_lib_path(const void *ctx)
{
	return ss_db_resolve_path(ctx, ss_lib_db_path_override,
				  "SUPERSCALAR_LIB_DB_PATH",
				  SS_LIB_DB_DEFAULT_NAME);
}

char *ss_db_resolve_plugin_path(const void *ctx)
{
	return ss_db_resolve_path(ctx, ss_plugin_db_path_override,
				  "SUPERSCALAR_CLN_DB_PATH",
				  SS_PLUGIN_DB_DEFAULT_NAME);
}

/* ============================================================================
 * Schema management
 * ============================================================================ */

static int ss_db_read_schema_version(sqlite3 *db)
{
	sqlite3_stmt *st = NULL;
	int version = 0;
	if (sqlite3_prepare_v2(db,
		"SELECT MAX(version) FROM schema_version",
		-1, &st, NULL) != SQLITE_OK)
		return -1;
	if (sqlite3_step(st) == SQLITE_ROW)
		version = sqlite3_column_int(st, 0);
	sqlite3_finalize(st);
	return version;
}

static bool ss_db_apply_statements(sqlite3 *db, const char **stmts,
				   const char *db_label)
{
	for (int i = 0; stmts[i] != NULL; i++) {
		char *err = NULL;
		int rc = sqlite3_exec(db, stmts[i], NULL, NULL, &err);
		if (rc != SQLITE_OK) {
			plugin_log(plugin_handle, LOG_BROKEN,
				   "ss_db: %s schema step %d failed: %s",
				   db_label, i, err ? err : "(no msg)");
			if (err) sqlite3_free(err);
			return false;
		}
	}
	return true;
}

static bool ss_db_apply_pragmas(sqlite3 *db, const char *db_label)
{
	const char *pragmas[] = {
		"PRAGMA journal_mode = WAL;",
		"PRAGMA synchronous = FULL;",  /* fund-critical durability */
		"PRAGMA foreign_keys = ON;",
		"PRAGMA busy_timeout = 5000;",  /* 5s before SQLITE_BUSY */
		NULL
	};
	return ss_db_apply_statements(db, pragmas, db_label);
}

/* ============================================================================
 * Open / close
 * ============================================================================ */

static bool ss_db_open_one(const char *path, const char *db_label,
			   sqlite3 **out, const char **schema_stmts,
			   int target_version, int *version_cache)
{
	sqlite3 *db = NULL;
	int rc = sqlite3_open_v2(path, &db,
		SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE |
		SQLITE_OPEN_NOMUTEX,
		NULL);
	if (rc != SQLITE_OK) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "ss_db: failed to open %s at %s: %s",
			   db_label, path, sqlite3_errstr(rc));
		if (db) sqlite3_close(db);
		return false;
	}
	if (!ss_db_apply_pragmas(db, db_label)) {
		sqlite3_close(db);
		return false;
	}
	if (!ss_db_apply_statements(db, schema_stmts, db_label)) {
		sqlite3_close(db);
		return false;
	}
	int current = ss_db_read_schema_version(db);
	if (current < 0) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "ss_db: failed to read schema_version for %s",
			   db_label);
		sqlite3_close(db);
		return false;
	}
	if (current != target_version) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "ss_db: %s schema version is %d, expected %d "
			   "(migration scaffolding goes here in future)",
			   db_label, current, target_version);
		/* For now: just log. When we ship v2, migration logic
		 * will branch on the current version and apply diffs. */
	}
	*out = db;
	*version_cache = current;
	plugin_log(plugin_handle, LOG_INFORM,
		   "ss_db: opened %s at %s (schema v%d, synchronous=FULL)",
		   db_label, path, current);
	return true;
}

/* Resolve relative DB paths to absolute via getcwd() at init time, so
 * subsequent ss_open_wallet_db_ro calls (which may run from a different
 * cwd under e.g. pyln-testing) hit the same file ss_db_init created.
 * Idempotent: if the path is already absolute, leave it alone. */
static void ss_db_pin_path_absolute(char **path_override_out,
                                    const char *default_name)
{
	if (*path_override_out && (*path_override_out)[0] == "/"[0])
		return;
	char cwd[4096];
	if (getcwd(cwd, sizeof(cwd)) == NULL)
		return;
	char *abs = malloc(strlen(cwd) + 1 + strlen(default_name) + 1);
	if (!abs) return;
	sprintf(abs, "%s/%s", cwd, default_name);
	if (*path_override_out)
		free(*path_override_out);
	*path_override_out = abs;
}

bool ss_db_init(void)
{
	/* Pin DB paths to absolute BEFORE opening so post-init reopens (e.g.
	 * ss_open_wallet_db_ro from a different cwd) hit the same files. */
	ss_db_pin_path_absolute(&ss_lib_db_path_override, SS_LIB_DB_DEFAULT_NAME);
	ss_db_pin_path_absolute(&ss_plugin_db_path_override, SS_PLUGIN_DB_DEFAULT_NAME);

	if (ss_lib_db && ss_plugin_db)
		return true;  /* idempotent */

	const tal_t *tmp = tal(NULL, char);
	char *lib_path = ss_db_resolve_lib_path(tmp);
	char *plugin_path = ss_db_resolve_plugin_path(tmp);

	bool ok = true;
	if (!ss_lib_db) {
		ok = ss_db_open_one(lib_path, "libsuperscalar.db",
				    &ss_lib_db, ss_lib_db_schema_v1,
				    SS_LIB_DB_SCHEMA_VERSION,
				    &ss_lib_db_version_cached);
	}
	if (ok && !ss_plugin_db) {
		ok = ss_db_open_one(plugin_path, "superscalar-cln.db",
				    &ss_plugin_db, ss_plugin_db_schema_v1,
				    SS_PLUGIN_DB_SCHEMA_VERSION,
				    &ss_plugin_db_version_cached);
	}
	tal_free(tmp);

	if (!ok) {
		ss_db_close();
		return false;
	}
	return true;
}

void ss_db_close(void)
{
	if (ss_lib_db) {
		sqlite3_close(ss_lib_db);
		ss_lib_db = NULL;
	}
	if (ss_plugin_db) {
		sqlite3_close(ss_plugin_db);
		ss_plugin_db = NULL;
	}
	ss_lib_db_version_cached = -1;
	ss_plugin_db_version_cached = -1;
}

int ss_db_lib_schema_version(void) { return ss_lib_db_version_cached; }
int ss_db_plugin_schema_version(void) { return ss_plugin_db_version_cached; }

/* ============================================================================
 * Transaction helpers.
 *
 * Per the design doc: lib DB commits before plugin DB. Both commits
 * are required-success — failed commit is a hard error that bubbles
 * up to the caller. No silent best-effort fall-through.
 * ============================================================================ */

static bool ss_db_exec_noresult(sqlite3 *db, const char *sql,
				const char *db_label, const char *op_label)
{
	char *err = NULL;
	int rc = sqlite3_exec(db, sql, NULL, NULL, &err);
	if (rc != SQLITE_OK) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "ss_db: %s on %s failed: %s",
			   op_label, db_label, err ? err : "(no msg)");
		if (err) sqlite3_free(err);
		return false;
	}
	return true;
}

bool ss_db_begin_lib(void)
{
	if (!ss_lib_db) return false;
	return ss_db_exec_noresult(ss_lib_db,
		"BEGIN IMMEDIATE TRANSACTION",
		"libsuperscalar.db", "BEGIN");
}

bool ss_db_commit_lib(void)
{
	if (!ss_lib_db) return false;
	return ss_db_exec_noresult(ss_lib_db, "COMMIT",
		"libsuperscalar.db", "COMMIT");
}

bool ss_db_rollback_lib(void)
{
	if (!ss_lib_db) return false;
	return ss_db_exec_noresult(ss_lib_db, "ROLLBACK",
		"libsuperscalar.db", "ROLLBACK");
}

bool ss_db_begin_plugin(void)
{
	if (!ss_plugin_db) return false;
	return ss_db_exec_noresult(ss_plugin_db,
		"BEGIN IMMEDIATE TRANSACTION",
		"superscalar-cln.db", "BEGIN");
}

bool ss_db_commit_plugin(void)
{
	if (!ss_plugin_db) return false;
	return ss_db_exec_noresult(ss_plugin_db, "COMMIT",
		"superscalar-cln.db", "COMMIT");
}

bool ss_db_rollback_plugin(void)
{
	if (!ss_plugin_db) return false;
	return ss_db_exec_noresult(ss_plugin_db, "ROLLBACK",
		"superscalar-cln.db", "ROLLBACK");
}


/* ============================================================================
 * Helpers used by superscalar.c\x27s legacy ss_save_factory path to replace
 * the RPC-based dual-write with direct SQLite ops on ss_plugin_db.
 * ============================================================================ */

bool ss_db_set_setting_blob(const char *key, const uint8_t *data, size_t len)
{
	if (!ss_plugin_db) return false;

	/* Hex-encode the blob, then JSON-string-wrap it (with quotes) so the
	 * stored value matches what the sidecar wrote. Existing
	 * ss_wallet_db_load_blob_tal in superscalar.c strips the wrapping
	 * quotes before hex-decoding. */
	char *value = malloc(len * 2 + 3);
	if (!value) return false;
	value[0] = '"';
	for (size_t i = 0; i < len; i++)
		sprintf(value + 1 + i*2, "%02x", data[i]);
	value[1 + len*2] = '"';
	value[1 + len*2 + 1] = '\0';

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"INSERT INTO wallet_settings (setting_key, setting_value, updated_at) "
		"VALUES (?, ?, strftime(\'%s\',\'now\')) "
		"ON CONFLICT(setting_key) DO UPDATE SET "
		"  setting_value = excluded.setting_value,"
		"  updated_at = excluded.updated_at",
		-1, &st, NULL) != SQLITE_OK) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "ss_db_set_setting_blob prepare failed: %s",
			   sqlite3_errmsg(ss_plugin_db));
		free(value);
		return false;
	}
	sqlite3_bind_text(st, 1, key, -1, SQLITE_TRANSIENT);
	sqlite3_bind_text(st, 2, value, -1, SQLITE_TRANSIENT);
	int rc = sqlite3_step(st);
	sqlite3_finalize(st);
	free(value);
	if (rc != SQLITE_DONE) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "ss_db_set_setting_blob step failed: %s",
			   sqlite3_errstr(rc));
		return false;
	}
	return true;
}

bool ss_db_upsert_factory_row(const uint8_t iid[32], uint32_t my_role,
			      uint32_t created_at_block, uint32_t state,
			      uint32_t archived)
{
	if (!ss_plugin_db) return false;

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"INSERT INTO factories "
		"  (factory_instance_id, my_role, display_label, created_at_block,"
		"   joined_at_block, state, last_seen_at, archived) "
		"VALUES (?, ?, NULL, ?, NULL, ?, strftime(\'%s\',\'now\'), ?) "
		"ON CONFLICT(factory_instance_id) DO UPDATE SET "
		"  my_role = excluded.my_role,"
		"  created_at_block = excluded.created_at_block,"
		"  state = excluded.state,"
		"  last_seen_at = excluded.last_seen_at,"
		"  archived = excluded.archived",
		-1, &st, NULL) != SQLITE_OK) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "ss_db_upsert_factory_row prepare failed: %s",
			   sqlite3_errmsg(ss_plugin_db));
		return false;
	}
	sqlite3_bind_blob(st, 1, iid, 32, SQLITE_TRANSIENT);
	sqlite3_bind_int(st, 2, (int)my_role);
	sqlite3_bind_int(st, 3, (int)created_at_block);
	sqlite3_bind_int(st, 4, (int)state);
	sqlite3_bind_int(st, 5, (int)archived);
	int rc = sqlite3_step(st);
	sqlite3_finalize(st);
	if (rc != SQLITE_DONE) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "ss_db_upsert_factory_row step failed: %s",
			   sqlite3_errstr(rc));
		return false;
	}
	return true;
}

/* ============================================================================
 * Session 5a: event_log helper.
 *
 * Append a single row representing a notable factory-or-LSP event so
 * wallets that aren\'t currently connected can fetch it later via
 * wallet-list-events-since. The connected-wallet push path (sessions
 * 5b/c) reads the same table; this keeps live and offline consistent.
 * ============================================================================ */

bool ss_db_emit_event(const char *type, const uint8_t iid_or_null[32],
                      const char *payload_json)
{
	if (!ss_plugin_db || !type || !payload_json) return false;

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"INSERT INTO event_log (type, factory_iid, payload_json, created_at) "
		"VALUES (?, ?, ?, strftime(\'%s\',\'now\'))",
		-1, &st, NULL) != SQLITE_OK) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "ss_db_emit_event prepare failed: %s",
			   sqlite3_errmsg(ss_plugin_db));
		return false;
	}
	sqlite3_bind_text(st, 1, type, -1, SQLITE_TRANSIENT);
	if (iid_or_null)
		sqlite3_bind_blob(st, 2, iid_or_null, 32, SQLITE_TRANSIENT);
	else
		sqlite3_bind_null(st, 2);
	sqlite3_bind_text(st, 3, payload_json, -1, SQLITE_TRANSIENT);

	int rc = sqlite3_step(st);
	sqlite3_finalize(st);
	if (rc != SQLITE_DONE) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "ss_db_emit_event step failed: %s",
			   sqlite3_errstr(rc));
		return false;
	}

	/* Rolling cap: trim oldest if we go above 10000 rows. Best-effort. */
	sqlite3_exec(ss_plugin_db,
		"DELETE FROM event_log WHERE event_id < "
		"(SELECT MAX(event_id) FROM event_log) - 10000",
		NULL, NULL, NULL);

	return true;
}

/* See ss_db.h. */
uint64_t ss_db_get_operator_pref_u64(const uint8_t iid_or_null[32],
                                     const char *pref_key,
                                     uint64_t fallback)
{
	if (!ss_plugin_db || !pref_key) return fallback;

	/* First try per-factory. */
	if (iid_or_null) {
		sqlite3_stmt *st = NULL;
		if (sqlite3_prepare_v2(ss_plugin_db,
			"SELECT pref_value FROM lsp_operator_prefs "
			"WHERE factory_instance_id = ? AND pref_key = ? "
			"ORDER BY rowid DESC LIMIT 1",
			-1, &st, NULL) == SQLITE_OK) {
			sqlite3_bind_blob(st, 1, iid_or_null, 32, SQLITE_STATIC);
			sqlite3_bind_text(st, 2, pref_key, -1, SQLITE_STATIC);
			if (sqlite3_step(st) == SQLITE_ROW &&
			    sqlite3_column_type(st, 0) != SQLITE_NULL) {
				const char *v = (const char *)sqlite3_column_text(st, 0);
				if (v && v[0]) {
					/* Strip JSON-wrap quotes if present. */
					const char *p = v;
					if (*p == '\"') p++;
					char *end = NULL;
					errno = 0;
					unsigned long long val = strtoull(p, &end, 10);
					if (!errno && end != p) {
						sqlite3_finalize(st);
						return (uint64_t)val;
					}
				}
			}
			sqlite3_finalize(st);
		}
	}

	/* Fall back to global default. */
	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"SELECT pref_value FROM lsp_operator_prefs "
		"WHERE factory_instance_id IS NULL AND pref_key = ? "
		"ORDER BY rowid DESC LIMIT 1",
		-1, &st, NULL) != SQLITE_OK)
		return fallback;
	sqlite3_bind_text(st, 1, pref_key, -1, SQLITE_STATIC);
	uint64_t result = fallback;
	if (sqlite3_step(st) == SQLITE_ROW &&
	    sqlite3_column_type(st, 0) != SQLITE_NULL) {
		const char *v = (const char *)sqlite3_column_text(st, 0);
		if (v && v[0]) {
			const char *p = v;
			if (*p == '\"') p++;
			char *end = NULL;
			errno = 0;
			unsigned long long val = strtoull(p, &end, 10);
			if (!errno && end != p) result = (uint64_t)val;
		}
	}
	sqlite3_finalize(st);
	return result;
}

