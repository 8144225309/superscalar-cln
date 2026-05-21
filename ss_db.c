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

bool ss_db_init(void)
{
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
