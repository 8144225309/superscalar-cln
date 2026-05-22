/* ============================================================================
 * ss_wallet_rpc: C implementations of the 20 wallet-* RPCs.
 *
 * Replaces the Node.js soupwallet-cln-plugin's RPC handlers with C versions
 * that talk directly to the SQLite databases (libsuperscalar.db and
 * superscalar-cln.db) via the ss_db layer.
 *
 * Response shapes are byte-compatible with the sidecar so the wallet UI
 * doesn't need changes.
 *
 * Conventions:
 *   - u64 fields (request_id, contribution_sats) wire-encoded as STRING
 *     (JSON Number can't represent past 2^53). Parse via strtoull, emit
 *     via snprintf "%" PRIu64.
 *   - BLOB fields (factory_instance_id, client_pubkey, etc.) wire-encoded
 *     as hex string. Parse via tal_hexdata + length check, emit via
 *     json_add_hex.
 *   - JSON-typed prefs values stored as TEXT (JSON-stringified) in DB.
 *     On read, emit raw bytes back via json_add_jsonstr.
 *   - "Not found" responses: return {"value": null} or {"factory": null}
 *     rather than top-level null. Sidecar returned bare null at top level;
 *     wallet UI handler treats both shapes equivalently.
 * ============================================================================ */

#include "ss_wallet_rpc.h"
#include "factory_state.h"
#include "ss_db.h"
#include <common/json_param.h>
#include <common/json_stream.h>
#include <common/jsonrpc_errors.h>
#include <ccan/tal/str/str.h>
#include <ccan/json_escape/json_escape.h>
#include <sqlite3.h>
#include <errno.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern struct plugin *plugin_handle;
extern superscalar_state_t ss_state;

/* ============================================================================
 * Shared helpers
 * ============================================================================ */

/* Decode a hex string param to bytes (tal-allocated against cmd). Returns
 * command_param_failed-style result on bad input, or NULL on success with
 * *out / *out_len populated. */
static struct command_result *param_hex_blob(struct command *cmd, const char *name,
					     const char *hex, size_t expected_len,
					     uint8_t **out, size_t *out_len)
{
	if (!hex) {
		*out = NULL; *out_len = 0;
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s required", name);
	}
	size_t hex_len = strlen(hex);
	if (hex_len % 2 != 0) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s must be even-length hex", name);
	}
	size_t bytes = hex_len / 2;
	if (expected_len > 0 && bytes != expected_len) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s must be %zu-byte hex (%zu chars)",
				    name, expected_len, expected_len * 2);
	}
	uint8_t *buf = tal_arr(cmd, uint8_t, bytes);
	for (size_t i = 0; i < bytes; i++) {
		unsigned int b;
		if (sscanf(hex + i*2, "%2x", &b) != 1) {
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "%s contains non-hex chars at offset %zu",
					    name, i*2);
		}
		buf[i] = (uint8_t)b;
	}
	*out = buf;
	*out_len = bytes;
	return NULL;
}

/* Stringly parse a u64 from a JSON value (string or number). */
static struct command_result *parse_u64_param(struct command *cmd,
					      const char *name, const char *buf,
					      const jsmntok_t *tok, uint64_t *out)
{
	if (!tok) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s required", name);
	}
	char *s = tal_strndup(cmd, buf + tok->start, tok->end - tok->start);
	/* Strip surrounding quotes if present (string-encoded u64) */
	if (tok->type == JSMN_STRING) {
		/* tal_strndup got just the content between quotes already */
	}
	char *end = NULL;
	errno = 0;
	unsigned long long v = strtoull(s, &end, 10);
	if (errno != 0 || end == s || *end != '\0') {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "%s must be a u64 numeric string", name);
	}
	*out = (uint64_t)v;
	return NULL;
}

/* Emit a u64 as a JSON STRING (wire-compatible with sidecar's BigInt.toString). */
static void json_add_u64_string(struct json_stream *js, const char *key, uint64_t val)
{
	char buf[32];
	snprintf(buf, sizeof(buf), "%" PRIu64, val);
	json_add_string(js, key, buf);
}

/* SQLite step + finalize for write-only statements. Returns true on
 * SQLITE_DONE, false otherwise (with plugin_log + finalize). */
static bool db_step_done(sqlite3_stmt *st, const char *op)
{
	int rc = sqlite3_step(st);
	if (rc != SQLITE_DONE) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "ss_wallet_rpc: %s step failed: %s",
			   op, sqlite3_errstr(rc));
		sqlite3_finalize(st);
		return false;
	}
	sqlite3_finalize(st);
	return true;
}

/* Convenience: return a 1-field JSON success {"key": null} */
static struct command_result *reply_null_value(struct command *cmd, const char *key)
{
	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_primitive(js, key, "null");
	return command_finished(cmd, js);
}

/* Convenience: return {"ok": true} */
static struct command_result *reply_ok(struct command *cmd)
{
	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_bool(js, "ok", true);
	return command_finished(cmd, js);
}

/* Convenience: return a SQL failure */
static struct command_result *reply_sql_fail(struct command *cmd, const char *op)
{
	return command_fail(cmd, LIGHTNINGD,
			    "ss_wallet_rpc: %s SQL failed: %s",
			    op, sqlite3_errmsg(ss_plugin_db));
}

/* ============================================================================
 * IID counter
 * ============================================================================ */

struct command_result *json_wallet_get_iid_counter(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"SELECT counter FROM iid_counter WHERE id = 0",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "get_iid_counter");

	int64_t counter = 0;
	if (sqlite3_step(st) == SQLITE_ROW)
		counter = sqlite3_column_int64(st, 0);
	sqlite3_finalize(st);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_u64(js, "counter", (uint64_t)counter);
	return command_finished(cmd, js);
}

struct command_result *json_wallet_increment_iid_counter(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	if (!ss_db_begin_plugin())
		return reply_sql_fail(cmd, "increment BEGIN");

	sqlite3_stmt *st = NULL;
	int64_t current = 0;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"SELECT counter FROM iid_counter WHERE id = 0",
		-1, &st, NULL) == SQLITE_OK) {
		if (sqlite3_step(st) == SQLITE_ROW)
			current = sqlite3_column_int64(st, 0);
		sqlite3_finalize(st);
	}
	int64_t next = current + 1;

	if (sqlite3_prepare_v2(ss_plugin_db,
		"UPDATE iid_counter SET counter = ?, updated_at = strftime('%s','now') WHERE id = 0",
		-1, &st, NULL) != SQLITE_OK) {
		ss_db_rollback_plugin();
		return reply_sql_fail(cmd, "increment UPDATE prepare");
	}
	sqlite3_bind_int64(st, 1, next);
	if (!db_step_done(st, "increment UPDATE")) {
		ss_db_rollback_plugin();
		return command_fail(cmd, LIGHTNINGD, "increment UPDATE failed");
	}
	if (!ss_db_commit_plugin())
		return reply_sql_fail(cmd, "increment COMMIT");

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_u64(js, "counter", (uint64_t)next);
	return command_finished(cmd, js);
}

struct command_result *json_wallet_set_iid_counter(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	uint32_t *counter;
	if (!param(cmd, buf, params,
		   p_req("counter", param_u32, &counter),
		   NULL))
		return command_param_failed();

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"UPDATE iid_counter SET counter = ?, updated_at = strftime('%s','now') WHERE id = 0",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "set_iid_counter prepare");

	sqlite3_bind_int64(st, 1, (int64_t)*counter);
	if (!db_step_done(st, "set_iid_counter"))
		return command_fail(cmd, LIGHTNINGD, "set_iid_counter failed");

	return reply_ok(cmd);
}

/* ============================================================================
 * Factories
 * ============================================================================ */

static void emit_factory_row(struct json_stream *js, sqlite3_stmt *st)
{
	json_object_start(js, NULL);
	const void *iid = sqlite3_column_blob(st, 0);
	int iid_len = sqlite3_column_bytes(st, 0);
	json_add_hex(js, "factory_instance_id_hex", iid, iid_len);
	json_add_u32(js, "my_role", (uint32_t)sqlite3_column_int(st, 1));
	if (sqlite3_column_type(st, 2) == SQLITE_NULL)
		json_add_primitive(js, "display_label", "null");
	else
		json_add_string(js, "display_label", (const char *)sqlite3_column_text(st, 2));
	json_add_u32(js, "created_at_block", (uint32_t)sqlite3_column_int(st, 3));
	if (sqlite3_column_type(st, 4) == SQLITE_NULL)
		json_add_primitive(js, "joined_at_block", "null");
	else
		json_add_u32(js, "joined_at_block", (uint32_t)sqlite3_column_int(st, 4));
	json_add_u32(js, "state", (uint32_t)sqlite3_column_int(st, 5));
	json_add_u32(js, "last_seen_at", (uint32_t)sqlite3_column_int(st, 6));
	json_add_u32(js, "archived", (uint32_t)sqlite3_column_int(st, 7));
	json_object_end(js);
}

struct command_result *json_wallet_upsert_factory(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *iid_hex = NULL;
	uint32_t *my_role;
	const char *display_label = NULL;
	uint32_t *created_at_block;
	uint32_t *joined_at_block_opt = NULL;
	uint32_t *state;
	uint32_t *archived_opt = NULL;

	if (!param(cmd, buf, params,
		   p_req("factory_instance_id_hex", param_string, &iid_hex),
		   p_req("my_role", param_u32, &my_role),
		   p_req("created_at_block", param_u32, &created_at_block),
		   p_req("state", param_u32, &state),
		   p_opt("display_label", param_string, &display_label),
		   p_opt("joined_at_block", param_u32, &joined_at_block_opt),
		   p_opt("archived", param_u32, &archived_opt),
		   NULL))
		return command_param_failed();

	uint8_t *iid; size_t iid_len;
	struct command_result *err = param_hex_blob(cmd, "factory_instance_id_hex",
						    iid_hex, 32, &iid, &iid_len);
	if (err) return err;

	uint32_t archived = archived_opt ? *archived_opt : 0;
	int64_t now = (int64_t)time(NULL);

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"INSERT INTO factories "
		"  (factory_instance_id, my_role, display_label, created_at_block,"
		"   joined_at_block, state, last_seen_at, archived) "
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
		"ON CONFLICT(factory_instance_id) DO UPDATE SET "
		"  my_role = excluded.my_role,"
		"  display_label = excluded.display_label,"
		"  created_at_block = excluded.created_at_block,"
		"  joined_at_block = excluded.joined_at_block,"
		"  state = excluded.state,"
		"  last_seen_at = excluded.last_seen_at,"
		"  archived = excluded.archived",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "upsert_factory prepare");

	sqlite3_bind_blob(st, 1, iid, (int)iid_len, SQLITE_STATIC);
	sqlite3_bind_int(st, 2, (int)*my_role);
	if (display_label)
		sqlite3_bind_text(st, 3, display_label, -1, SQLITE_STATIC);
	else
		sqlite3_bind_null(st, 3);
	sqlite3_bind_int(st, 4, (int)*created_at_block);
	if (joined_at_block_opt)
		sqlite3_bind_int(st, 5, (int)*joined_at_block_opt);
	else
		sqlite3_bind_null(st, 5);
	sqlite3_bind_int(st, 6, (int)*state);
	sqlite3_bind_int64(st, 7, now);
	sqlite3_bind_int(st, 8, (int)archived);

	if (!db_step_done(st, "upsert_factory"))
		return command_fail(cmd, LIGHTNINGD, "upsert_factory failed");

	return reply_ok(cmd);
}

struct command_result *json_wallet_get_factory(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *iid_hex = NULL;
	if (!param(cmd, buf, params,
		   p_req("factory_instance_id_hex", param_string, &iid_hex),
		   NULL))
		return command_param_failed();

	uint8_t *iid; size_t iid_len;
	struct command_result *err = param_hex_blob(cmd, "factory_instance_id_hex",
						    iid_hex, 32, &iid, &iid_len);
	if (err) return err;

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"SELECT factory_instance_id, my_role, display_label, created_at_block,"
		"       joined_at_block, state, last_seen_at, archived "
		"FROM factories WHERE factory_instance_id = ?",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "get_factory prepare");

	sqlite3_bind_blob(st, 1, iid, (int)iid_len, SQLITE_STATIC);

	int rc = sqlite3_step(st);
	if (rc == SQLITE_ROW) {
		struct json_stream *js = jsonrpc_stream_success(cmd);
		/* Emit a wrapper object with the factory fields directly */
		const void *iid_b = sqlite3_column_blob(st, 0);
		int iid_b_len = sqlite3_column_bytes(st, 0);
		json_add_hex(js, "factory_instance_id_hex", iid_b, iid_b_len);
		json_add_u32(js, "my_role", (uint32_t)sqlite3_column_int(st, 1));
		if (sqlite3_column_type(st, 2) == SQLITE_NULL)
			json_add_primitive(js, "display_label", "null");
		else
			json_add_string(js, "display_label", (const char *)sqlite3_column_text(st, 2));
		json_add_u32(js, "created_at_block", (uint32_t)sqlite3_column_int(st, 3));
		if (sqlite3_column_type(st, 4) == SQLITE_NULL)
			json_add_primitive(js, "joined_at_block", "null");
		else
			json_add_u32(js, "joined_at_block", (uint32_t)sqlite3_column_int(st, 4));
		json_add_u32(js, "state", (uint32_t)sqlite3_column_int(st, 5));
		json_add_u32(js, "last_seen_at", (uint32_t)sqlite3_column_int(st, 6));
		json_add_u32(js, "archived", (uint32_t)sqlite3_column_int(st, 7));
		sqlite3_finalize(st);
		return command_finished(cmd, js);
	}
	sqlite3_finalize(st);
	/* Not found: return {"factory_instance_id_hex": null} as sentinel */
	return reply_null_value(cmd, "factory_instance_id_hex");
}

struct command_result *json_wallet_list_factories_by_role(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	uint32_t *role;
	bool *include_archived_opt = NULL;
	if (!param(cmd, buf, params,
		   p_req("role", param_u32, &role),
		   p_opt("include_archived", param_bool, &include_archived_opt),
		   NULL))
		return command_param_failed();

	bool include_archived = include_archived_opt ? *include_archived_opt : false;

	sqlite3_stmt *st = NULL;
	const char *sql = include_archived
		? "SELECT factory_instance_id, my_role, display_label, created_at_block,"
		  "       joined_at_block, state, last_seen_at, archived "
		  "FROM factories WHERE my_role = ? ORDER BY created_at_block DESC"
		: "SELECT factory_instance_id, my_role, display_label, created_at_block,"
		  "       joined_at_block, state, last_seen_at, archived "
		  "FROM factories WHERE my_role = ? AND archived = 0 ORDER BY created_at_block DESC";

	if (sqlite3_prepare_v2(ss_plugin_db, sql, -1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "list_factories prepare");
	sqlite3_bind_int(st, 1, (int)*role);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_array_start(js, "factories");
	while (sqlite3_step(st) == SQLITE_ROW)
		emit_factory_row(js, st);
	json_array_end(js);
	sqlite3_finalize(st);
	return command_finished(cmd, js);
}

/* ============================================================================
 * LSP join queue
 * ============================================================================ */

static void emit_join_queue_row(struct json_stream *js, sqlite3_stmt *st)
{
	json_object_start(js, NULL);
	const void *iid = sqlite3_column_blob(st, 0);
	int iid_len = sqlite3_column_bytes(st, 0);
	json_add_hex(js, "factory_instance_id_hex", iid, iid_len);
	const void *cli = sqlite3_column_blob(st, 1);
	int cli_len = sqlite3_column_bytes(st, 1);
	json_add_hex(js, "client_pubkey_hex", cli, cli_len);
	json_add_u64_string(js, "request_id", (uint64_t)sqlite3_column_int64(st, 2));
	json_add_u64_string(js, "contribution_sats", (uint64_t)sqlite3_column_int64(st, 3));
	json_add_u32(js, "received_at_block", (uint32_t)sqlite3_column_int(st, 4));
	if (sqlite3_column_type(st, 5) == SQLITE_NULL) json_add_primitive(js, "accepted_at_block", "null");
	else json_add_u32(js, "accepted_at_block", (uint32_t)sqlite3_column_int(st, 5));
	if (sqlite3_column_type(st, 6) == SQLITE_NULL) json_add_primitive(js, "decided_at_block", "null");
	else json_add_u32(js, "decided_at_block", (uint32_t)sqlite3_column_int(st, 6));
	if (sqlite3_column_type(st, 7) == SQLITE_NULL) json_add_primitive(js, "last_seen_block", "null");
	else json_add_u32(js, "last_seen_block", (uint32_t)sqlite3_column_int(st, 7));
	json_add_u32(js, "status", (uint32_t)sqlite3_column_int(st, 8));
	if (sqlite3_column_type(st, 9) == SQLITE_NULL) json_add_primitive(js, "reason", "null");
	else json_add_string(js, "reason", (const char *)sqlite3_column_text(st, 9));
	json_object_end(js);
}

struct command_result *json_wallet_upsert_join_queue_entry(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *iid_hex, *cli_hex;
	const char *request_id_s, *contribution_sats_s;
	uint32_t *received_at_block;
	uint32_t *accepted_at_block_opt = NULL, *decided_at_block_opt = NULL;
	uint32_t *last_seen_block_opt = NULL;
	uint32_t *status;
	const char *reason = NULL;

	if (!param(cmd, buf, params,
		   p_req("factory_instance_id_hex", param_string, &iid_hex),
		   p_req("client_pubkey_hex", param_string, &cli_hex),
		   p_req("request_id", param_string, &request_id_s),
		   p_req("contribution_sats", param_string, &contribution_sats_s),
		   p_req("received_at_block", param_u32, &received_at_block),
		   p_req("status", param_u32, &status),
		   p_opt("accepted_at_block", param_u32, &accepted_at_block_opt),
		   p_opt("decided_at_block", param_u32, &decided_at_block_opt),
		   p_opt("last_seen_block", param_u32, &last_seen_block_opt),
		   p_opt("reason", param_string, &reason),
		   NULL))
		return command_param_failed();

	uint8_t *iid, *cli; size_t iid_len, cli_len;
	struct command_result *err;
	err = param_hex_blob(cmd, "factory_instance_id_hex", iid_hex, 32, &iid, &iid_len);
	if (err) return err;
	err = param_hex_blob(cmd, "client_pubkey_hex", cli_hex, 33, &cli, &cli_len);
	if (err) return err;

	errno = 0;
	uint64_t request_id = strtoull(request_id_s, NULL, 10);
	if (errno) return command_fail(cmd, JSONRPC2_INVALID_PARAMS, "request_id parse");
	errno = 0;
	uint64_t contribution_sats = strtoull(contribution_sats_s, NULL, 10);
	if (errno) return command_fail(cmd, JSONRPC2_INVALID_PARAMS, "contribution_sats parse");

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"INSERT INTO lsp_join_queue "
		"  (factory_instance_id, client_pubkey, request_id, contribution_sats,"
		"   received_at_block, accepted_at_block, decided_at_block,"
		"   last_seen_block, status, reason) "
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
		"ON CONFLICT(factory_instance_id, client_pubkey) DO UPDATE SET "
		"  request_id = excluded.request_id,"
		"  contribution_sats = excluded.contribution_sats,"
		"  received_at_block = excluded.received_at_block,"
		"  accepted_at_block = excluded.accepted_at_block,"
		"  decided_at_block = excluded.decided_at_block,"
		"  last_seen_block = excluded.last_seen_block,"
		"  status = excluded.status,"
		"  reason = excluded.reason",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "upsert_join_queue prepare");

	sqlite3_bind_blob(st, 1, iid, (int)iid_len, SQLITE_STATIC);
	sqlite3_bind_blob(st, 2, cli, (int)cli_len, SQLITE_STATIC);
	sqlite3_bind_int64(st, 3, (int64_t)request_id);
	sqlite3_bind_int64(st, 4, (int64_t)contribution_sats);
	sqlite3_bind_int(st, 5, (int)*received_at_block);
	if (accepted_at_block_opt) sqlite3_bind_int(st, 6, (int)*accepted_at_block_opt);
	else sqlite3_bind_null(st, 6);
	if (decided_at_block_opt) sqlite3_bind_int(st, 7, (int)*decided_at_block_opt);
	else sqlite3_bind_null(st, 7);
	if (last_seen_block_opt) sqlite3_bind_int(st, 8, (int)*last_seen_block_opt);
	else sqlite3_bind_null(st, 8);
	sqlite3_bind_int(st, 9, (int)*status);
	if (reason) sqlite3_bind_text(st, 10, reason, -1, SQLITE_STATIC);
	else sqlite3_bind_null(st, 10);

	if (!db_step_done(st, "upsert_join_queue"))
		return command_fail(cmd, LIGHTNINGD, "upsert_join_queue failed");
	return reply_ok(cmd);
}

struct command_result *json_wallet_list_join_queue_by_status(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *iid_hex;
	uint32_t *status;
	if (!param(cmd, buf, params,
		   p_req("factory_instance_id_hex", param_string, &iid_hex),
		   p_req("status", param_u32, &status),
		   NULL))
		return command_param_failed();

	uint8_t *iid; size_t iid_len;
	struct command_result *err = param_hex_blob(cmd, "factory_instance_id_hex",
						    iid_hex, 32, &iid, &iid_len);
	if (err) return err;

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"SELECT factory_instance_id, client_pubkey, request_id, contribution_sats,"
		"       received_at_block, accepted_at_block, decided_at_block,"
		"       last_seen_block, status, reason "
		"FROM lsp_join_queue "
		"WHERE factory_instance_id = ? AND status = ? "
		"ORDER BY received_at_block ASC",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "list_join_queue prepare");

	sqlite3_bind_blob(st, 1, iid, (int)iid_len, SQLITE_STATIC);
	sqlite3_bind_int(st, 2, (int)*status);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_array_start(js, "entries");
	while (sqlite3_step(st) == SQLITE_ROW)
		emit_join_queue_row(js, st);
	json_array_end(js);
	sqlite3_finalize(st);
	return command_finished(cmd, js);
}

struct command_result *json_wallet_count_join_queue_by_status(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *iid_hex;
	uint32_t *status;
	if (!param(cmd, buf, params,
		   p_req("factory_instance_id_hex", param_string, &iid_hex),
		   p_req("status", param_u32, &status),
		   NULL))
		return command_param_failed();

	uint8_t *iid; size_t iid_len;
	struct command_result *err = param_hex_blob(cmd, "factory_instance_id_hex",
						    iid_hex, 32, &iid, &iid_len);
	if (err) return err;

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"SELECT COUNT(*) FROM lsp_join_queue "
		"WHERE factory_instance_id = ? AND status = ?",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "count_join_queue prepare");
	sqlite3_bind_blob(st, 1, iid, (int)iid_len, SQLITE_STATIC);
	sqlite3_bind_int(st, 2, (int)*status);

	int64_t count = 0;
	if (sqlite3_step(st) == SQLITE_ROW)
		count = sqlite3_column_int64(st, 0);
	sqlite3_finalize(st);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_u64(js, "count", (uint64_t)count);
	return command_finished(cmd, js);
}

/* ============================================================================
 * Outgoing joins
 * ============================================================================ */

static void emit_outgoing_join_row(struct json_stream *js, sqlite3_stmt *st)
{
	json_object_start(js, NULL);
	const void *iid = sqlite3_column_blob(st, 0);
	int iid_len = sqlite3_column_bytes(st, 0);
	json_add_hex(js, "factory_instance_id_hex", iid, iid_len);
	const void *lsp = sqlite3_column_blob(st, 1);
	int lsp_len = sqlite3_column_bytes(st, 1);
	json_add_hex(js, "lsp_pubkey_hex", lsp, lsp_len);
	json_add_u64_string(js, "request_id", (uint64_t)sqlite3_column_int64(st, 2));
	json_add_u64_string(js, "contribution_sats", (uint64_t)sqlite3_column_int64(st, 3));
	json_add_u32(js, "sent_at_block", (uint32_t)sqlite3_column_int(st, 4));
	if (sqlite3_column_type(st, 5) == SQLITE_NULL)
		json_add_primitive(js, "expected_signing_block", "null");
	else
		json_add_u32(js, "expected_signing_block", (uint32_t)sqlite3_column_int(st, 5));
	json_add_u32(js, "updated_at_block", (uint32_t)sqlite3_column_int(st, 6));
	json_add_u32(js, "status", (uint32_t)sqlite3_column_int(st, 7));
	if (sqlite3_column_type(st, 8) == SQLITE_NULL)
		json_add_primitive(js, "reason", "null");
	else
		json_add_string(js, "reason", (const char *)sqlite3_column_text(st, 8));
	json_object_end(js);
}

struct command_result *json_wallet_upsert_outgoing_join(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *iid_hex, *lsp_hex, *request_id_s, *contribution_sats_s;
	uint32_t *sent_at_block;
	uint32_t *expected_signing_block_opt = NULL;
	uint32_t *updated_at_block;
	uint32_t *status;
	const char *reason = NULL;

	if (!param(cmd, buf, params,
		   p_req("factory_instance_id_hex", param_string, &iid_hex),
		   p_req("lsp_pubkey_hex", param_string, &lsp_hex),
		   p_req("request_id", param_string, &request_id_s),
		   p_req("contribution_sats", param_string, &contribution_sats_s),
		   p_req("sent_at_block", param_u32, &sent_at_block),
		   p_req("updated_at_block", param_u32, &updated_at_block),
		   p_req("status", param_u32, &status),
		   p_opt("expected_signing_block", param_u32, &expected_signing_block_opt),
		   p_opt("reason", param_string, &reason),
		   NULL))
		return command_param_failed();

	uint8_t *iid, *lsp; size_t iid_len, lsp_len;
	struct command_result *err;
	err = param_hex_blob(cmd, "factory_instance_id_hex", iid_hex, 32, &iid, &iid_len);
	if (err) return err;
	err = param_hex_blob(cmd, "lsp_pubkey_hex", lsp_hex, 33, &lsp, &lsp_len);
	if (err) return err;

	errno = 0;
	uint64_t request_id = strtoull(request_id_s, NULL, 10);
	if (errno) return command_fail(cmd, JSONRPC2_INVALID_PARAMS, "request_id parse");
	errno = 0;
	uint64_t contribution_sats = strtoull(contribution_sats_s, NULL, 10);
	if (errno) return command_fail(cmd, JSONRPC2_INVALID_PARAMS, "contribution_sats parse");

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"INSERT INTO outgoing_joins "
		"  (factory_instance_id, lsp_pubkey, request_id, contribution_sats,"
		"   sent_at_block, expected_signing_block, updated_at_block,"
		"   status, reason) "
		"VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
		"ON CONFLICT(factory_instance_id, lsp_pubkey) DO UPDATE SET "
		"  request_id = excluded.request_id,"
		"  contribution_sats = excluded.contribution_sats,"
		"  sent_at_block = excluded.sent_at_block,"
		"  expected_signing_block = excluded.expected_signing_block,"
		"  updated_at_block = excluded.updated_at_block,"
		"  status = excluded.status,"
		"  reason = excluded.reason",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "upsert_outgoing_join prepare");

	sqlite3_bind_blob(st, 1, iid, (int)iid_len, SQLITE_STATIC);
	sqlite3_bind_blob(st, 2, lsp, (int)lsp_len, SQLITE_STATIC);
	sqlite3_bind_int64(st, 3, (int64_t)request_id);
	sqlite3_bind_int64(st, 4, (int64_t)contribution_sats);
	sqlite3_bind_int(st, 5, (int)*sent_at_block);
	if (expected_signing_block_opt)
		sqlite3_bind_int(st, 6, (int)*expected_signing_block_opt);
	else
		sqlite3_bind_null(st, 6);
	sqlite3_bind_int(st, 7, (int)*updated_at_block);
	sqlite3_bind_int(st, 8, (int)*status);
	if (reason) sqlite3_bind_text(st, 9, reason, -1, SQLITE_STATIC);
	else sqlite3_bind_null(st, 9);

	if (!db_step_done(st, "upsert_outgoing_join"))
		return command_fail(cmd, LIGHTNINGD, "upsert_outgoing_join failed");
	return reply_ok(cmd);
}

struct command_result *json_wallet_list_outgoing_joins_by_status(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	uint32_t *status;
	if (!param(cmd, buf, params,
		   p_req("status", param_u32, &status),
		   NULL))
		return command_param_failed();

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"SELECT factory_instance_id, lsp_pubkey, request_id, contribution_sats,"
		"       sent_at_block, expected_signing_block, updated_at_block,"
		"       status, reason "
		"FROM outgoing_joins WHERE status = ? ORDER BY updated_at_block DESC",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "list_outgoing_joins prepare");
	sqlite3_bind_int(st, 1, (int)*status);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_array_start(js, "entries");
	while (sqlite3_step(st) == SQLITE_ROW)
		emit_outgoing_join_row(js, st);
	json_array_end(js);
	sqlite3_finalize(st);
	return command_finished(cmd, js);
}

/* ============================================================================
 * Factory policy snapshots
 * ============================================================================ */

struct command_result *json_wallet_save_factory_policy_snapshot(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *iid_hex, *policy_tlv_hex;
	uint32_t *schema_version;
	uint32_t *captured_at_block;
	if (!param(cmd, buf, params,
		   p_req("factory_instance_id_hex", param_string, &iid_hex),
		   p_req("policy_schema_version", param_u32, &schema_version),
		   p_req("policy_tlv_hex", param_string, &policy_tlv_hex),
		   p_req("captured_at_block", param_u32, &captured_at_block),
		   NULL))
		return command_param_failed();

	uint8_t *iid, *tlv; size_t iid_len, tlv_len;
	struct command_result *err;
	err = param_hex_blob(cmd, "factory_instance_id_hex", iid_hex, 32, &iid, &iid_len);
	if (err) return err;
	err = param_hex_blob(cmd, "policy_tlv_hex", policy_tlv_hex, 0, &tlv, &tlv_len);
	if (err) return err;

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"INSERT INTO factory_policy_snapshots "
		"  (factory_instance_id, policy_schema_version, policy_tlv, captured_at_block) "
		"VALUES (?, ?, ?, ?) "
		"ON CONFLICT(factory_instance_id) DO UPDATE SET "
		"  policy_schema_version = excluded.policy_schema_version,"
		"  policy_tlv = excluded.policy_tlv,"
		"  captured_at_block = excluded.captured_at_block",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "save_policy_snapshot prepare");

	sqlite3_bind_blob(st, 1, iid, (int)iid_len, SQLITE_STATIC);
	sqlite3_bind_int(st, 2, (int)*schema_version);
	sqlite3_bind_blob(st, 3, tlv, (int)tlv_len, SQLITE_STATIC);
	sqlite3_bind_int(st, 4, (int)*captured_at_block);

	if (!db_step_done(st, "save_policy_snapshot"))
		return command_fail(cmd, LIGHTNINGD, "save_policy_snapshot failed");
	return reply_ok(cmd);
}

struct command_result *json_wallet_get_factory_policy_snapshot(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *iid_hex;
	if (!param(cmd, buf, params,
		   p_req("factory_instance_id_hex", param_string, &iid_hex),
		   NULL))
		return command_param_failed();

	uint8_t *iid; size_t iid_len;
	struct command_result *err = param_hex_blob(cmd, "factory_instance_id_hex",
						    iid_hex, 32, &iid, &iid_len);
	if (err) return err;

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"SELECT policy_schema_version, policy_tlv, captured_at_block "
		"FROM factory_policy_snapshots WHERE factory_instance_id = ?",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "get_policy_snapshot prepare");
	sqlite3_bind_blob(st, 1, iid, (int)iid_len, SQLITE_STATIC);

	int rc = sqlite3_step(st);
	if (rc == SQLITE_ROW) {
		struct json_stream *js = jsonrpc_stream_success(cmd);
		json_add_hex(js, "factory_instance_id_hex", iid, iid_len);
		json_add_u32(js, "policy_schema_version", (uint32_t)sqlite3_column_int(st, 0));
		const void *tlv = sqlite3_column_blob(st, 1);
		int tlv_len = sqlite3_column_bytes(st, 1);
		json_add_hex(js, "policy_tlv_hex", tlv, tlv_len);
		json_add_u32(js, "captured_at_block", (uint32_t)sqlite3_column_int(st, 2));
		sqlite3_finalize(st);
		return command_finished(cmd, js);
	}
	sqlite3_finalize(st);
	return reply_null_value(cmd, "policy_tlv_hex");
}

/* ============================================================================
 * Operator prefs (LSP-side)
 *
 * Per-factory falling back to global (factory_instance_id IS NULL).
 * Values are JSON-encoded TEXT.
 * ============================================================================ */

struct command_result *json_wallet_set_operator_pref(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *iid_hex_or_null = NULL;
	const char *pref_key;
	const char *pref_value_json;

	if (!param(cmd, buf, params,
		   p_req("pref_key", param_string, &pref_key),
		   p_req("pref_value", param_string, &pref_value_json),
		   p_opt("factory_instance_id_hex", param_string, &iid_hex_or_null),
		   NULL))
		return command_param_failed();

	uint8_t *iid = NULL; size_t iid_len = 0;
	if (iid_hex_or_null) {
		struct command_result *err = param_hex_blob(cmd, "factory_instance_id_hex",
						    iid_hex_or_null, 32, &iid, &iid_len);
		if (err) return err;
	}

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"INSERT INTO lsp_operator_prefs "
		"  (factory_instance_id, pref_key, pref_value, updated_at) "
		"VALUES (?, ?, ?, strftime('%s','now')) "
		"ON CONFLICT(factory_instance_id, pref_key) DO UPDATE SET "
		"  pref_value = excluded.pref_value,"
		"  updated_at = excluded.updated_at",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "set_operator_pref prepare");

	if (iid) sqlite3_bind_blob(st, 1, iid, (int)iid_len, SQLITE_STATIC);
	else sqlite3_bind_null(st, 1);
	sqlite3_bind_text(st, 2, pref_key, -1, SQLITE_STATIC);
	sqlite3_bind_text(st, 3, pref_value_json, -1, SQLITE_STATIC);

	if (!db_step_done(st, "set_operator_pref"))
		return command_fail(cmd, LIGHTNINGD, "set_operator_pref failed");
	return reply_ok(cmd);
}

struct command_result *json_wallet_get_operator_pref(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *iid_hex_or_null = NULL;
	const char *pref_key;
	if (!param(cmd, buf, params,
		   p_req("pref_key", param_string, &pref_key),
		   p_opt("factory_instance_id_hex", param_string, &iid_hex_or_null),
		   NULL))
		return command_param_failed();

	uint8_t *iid = NULL; size_t iid_len = 0;
	if (iid_hex_or_null) {
		struct command_result *err = param_hex_blob(cmd, "factory_instance_id_hex",
						    iid_hex_or_null, 32, &iid, &iid_len);
		if (err) return err;
	}

	sqlite3_stmt *st = NULL;
	const char *found_json = NULL;
	char *found_dup = NULL;

	/* Per-factory first */
	if (iid) {
		if (sqlite3_prepare_v2(ss_plugin_db,
			"SELECT pref_value FROM lsp_operator_prefs "
			"WHERE factory_instance_id = ? AND pref_key = ?",
			-1, &st, NULL) == SQLITE_OK) {
			sqlite3_bind_blob(st, 1, iid, (int)iid_len, SQLITE_STATIC);
			sqlite3_bind_text(st, 2, pref_key, -1, SQLITE_STATIC);
			if (sqlite3_step(st) == SQLITE_ROW)
				found_json = (const char *)sqlite3_column_text(st, 0);
			if (found_json) found_dup = tal_strdup(cmd, found_json);
			sqlite3_finalize(st);
			st = NULL;
		}
	}

	/* Fall back to global */
	if (!found_dup) {
		if (sqlite3_prepare_v2(ss_plugin_db,
			"SELECT pref_value FROM lsp_operator_prefs "
			"WHERE factory_instance_id IS NULL AND pref_key = ?",
			-1, &st, NULL) == SQLITE_OK) {
			sqlite3_bind_text(st, 1, pref_key, -1, SQLITE_STATIC);
			if (sqlite3_step(st) == SQLITE_ROW)
				found_json = (const char *)sqlite3_column_text(st, 0);
			if (found_json) found_dup = tal_strdup(cmd, found_json);
			sqlite3_finalize(st);
		}
	}

	struct json_stream *js = jsonrpc_stream_success(cmd);
	if (found_dup)
		json_add_jsonstr(js, "value", found_dup, strlen(found_dup));
	else
		json_add_primitive(js, "value", "null");
	return command_finished(cmd, js);
}

/* ============================================================================
 * Client signing prefs
 * ============================================================================ */

struct command_result *json_wallet_set_signing_pref(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *iid_hex, *pref_key, *pref_value_json;
	if (!param(cmd, buf, params,
		   p_req("factory_instance_id_hex", param_string, &iid_hex),
		   p_req("pref_key", param_string, &pref_key),
		   p_req("pref_value", param_string, &pref_value_json),
		   NULL))
		return command_param_failed();

	uint8_t *iid; size_t iid_len;
	struct command_result *err = param_hex_blob(cmd, "factory_instance_id_hex",
						    iid_hex, 32, &iid, &iid_len);
	if (err) return err;

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"INSERT INTO client_signing_prefs "
		"  (factory_instance_id, pref_key, pref_value, updated_at) "
		"VALUES (?, ?, ?, strftime('%s','now')) "
		"ON CONFLICT(factory_instance_id, pref_key) DO UPDATE SET "
		"  pref_value = excluded.pref_value,"
		"  updated_at = excluded.updated_at",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "set_signing_pref prepare");

	sqlite3_bind_blob(st, 1, iid, (int)iid_len, SQLITE_STATIC);
	sqlite3_bind_text(st, 2, pref_key, -1, SQLITE_STATIC);
	sqlite3_bind_text(st, 3, pref_value_json, -1, SQLITE_STATIC);

	if (!db_step_done(st, "set_signing_pref"))
		return command_fail(cmd, LIGHTNINGD, "set_signing_pref failed");
	return reply_ok(cmd);
}

struct command_result *json_wallet_get_signing_pref(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *iid_hex, *pref_key;
	if (!param(cmd, buf, params,
		   p_req("factory_instance_id_hex", param_string, &iid_hex),
		   p_req("pref_key", param_string, &pref_key),
		   NULL))
		return command_param_failed();

	uint8_t *iid; size_t iid_len;
	struct command_result *err = param_hex_blob(cmd, "factory_instance_id_hex",
						    iid_hex, 32, &iid, &iid_len);
	if (err) return err;

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"SELECT pref_value FROM client_signing_prefs "
		"WHERE factory_instance_id = ? AND pref_key = ?",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "get_signing_pref prepare");
	sqlite3_bind_blob(st, 1, iid, (int)iid_len, SQLITE_STATIC);
	sqlite3_bind_text(st, 2, pref_key, -1, SQLITE_STATIC);

	char *found_dup = NULL;
	if (sqlite3_step(st) == SQLITE_ROW) {
		const char *t = (const char *)sqlite3_column_text(st, 0);
		if (t) found_dup = tal_strdup(cmd, t);
	}
	sqlite3_finalize(st);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	if (found_dup)
		json_add_jsonstr(js, "value", found_dup, strlen(found_dup));
	else
		json_add_primitive(js, "value", "null");
	return command_finished(cmd, js);
}

/* ============================================================================
 * General KV settings
 * ============================================================================ */

struct command_result *json_wallet_set_setting(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *setting_key, *setting_value_json;
	if (!param(cmd, buf, params,
		   p_req("setting_key", param_string, &setting_key),
		   p_req("setting_value", param_string, &setting_value_json),
		   NULL))
		return command_param_failed();

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"INSERT INTO wallet_settings (setting_key, setting_value, updated_at) "
		"VALUES (?, ?, strftime('%s','now')) "
		"ON CONFLICT(setting_key) DO UPDATE SET "
		"  setting_value = excluded.setting_value,"
		"  updated_at = excluded.updated_at",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "set_setting prepare");
	sqlite3_bind_text(st, 1, setting_key, -1, SQLITE_STATIC);
	sqlite3_bind_text(st, 2, setting_value_json, -1, SQLITE_STATIC);
	if (!db_step_done(st, "set_setting"))
		return command_fail(cmd, LIGHTNINGD, "set_setting failed");
	return reply_ok(cmd);
}

struct command_result *json_wallet_get_setting(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *setting_key;
	if (!param(cmd, buf, params,
		   p_req("setting_key", param_string, &setting_key),
		   NULL))
		return command_param_failed();

	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"SELECT setting_value FROM wallet_settings WHERE setting_key = ?",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "get_setting prepare");
	sqlite3_bind_text(st, 1, setting_key, -1, SQLITE_STATIC);

	char *found_dup = NULL;
	if (sqlite3_step(st) == SQLITE_ROW) {
		const char *t = (const char *)sqlite3_column_text(st, 0);
		if (t) found_dup = tal_strdup(cmd, t);
	}
	sqlite3_finalize(st);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	if (found_dup)
		json_add_jsonstr(js, "value", found_dup, strlen(found_dup));
	else
		json_add_primitive(js, "value", "null");
	return command_finished(cmd, js);
}

/* ============================================================================
 * Health
 * ============================================================================ */

struct command_result *json_wallet_status(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_u32(js, "lib_schema_version", (uint32_t)ss_db_lib_schema_version());
	json_add_u32(js, "plugin_schema_version", (uint32_t)ss_db_plugin_schema_version());
	char *lib_path = ss_db_resolve_lib_path(cmd);
	char *plugin_path = ss_db_resolve_plugin_path(cmd);
	json_add_string(js, "lib_db_path", lib_path);
	json_add_string(js, "plugin_db_path", plugin_path);
	json_add_bool(js, "ready", true);
	return command_finished(cmd, js);
}

/* ============================================================================
 * Session 1 (LSP UI gaps): wallet-approve-join-queued / wallet-refuse-join-queued
 *
 * Operator-side admin actions to transition an lsp_join_queue row from
 * QUEUED to either ACCEPTED (status=1) or REJECTED (status=3). The
 * existing client-side handler enqueues all incoming JOIN_REQUEST as
 * QUEUED by default unless auto_accept_threshold matched. These RPCs
 * let an LSP operator advance the lifecycle manually from the UI.
 *
 * Status enum (factory_join_status_t in factory_state.h):
 *   0 QUEUED, 1 ACCEPTED, 2 SIGNED, 3 REJECTED, 4 CANCELLED, 5 ALREADY_MEMBER
 *
 * No wire-level notification is sent on REJECTED here — the client will
 * see the new status next time it polls (or, if the operator decides to
 * proactively notify, that's a follow-up). On ACCEPTED, the existing
 * factory-trigger-ceremony flow consumes the queue per-iid and the
 * client is included in the next rotation.
 * ============================================================================ */

static struct command_result *update_join_queue_status(
	struct command *cmd, const char *iid_hex, const char *cli_hex,
	int new_status, const char *reason)
{
	uint8_t *iid; size_t iid_len;
	struct command_result *err;
	err = param_hex_blob(cmd, "factory_instance_id_hex", iid_hex, 32, &iid, &iid_len);
	if (err) return err;
	uint8_t *cli; size_t cli_len;
	err = param_hex_blob(cmd, "client_pubkey_hex", cli_hex, 33, &cli, &cli_len);
	if (err) return err;

	/* First confirm the row exists + capture its current status so we can
	 * report it back and reject illegal transitions cleanly. */
	sqlite3_stmt *st = NULL;
	if (sqlite3_prepare_v2(ss_plugin_db,
		"SELECT status FROM lsp_join_queue "
		"WHERE factory_instance_id = ? AND client_pubkey = ?",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "update_join_queue_status select prepare");
	sqlite3_bind_blob(st, 1, iid, (int)iid_len, SQLITE_STATIC);
	sqlite3_bind_blob(st, 2, cli, (int)cli_len, SQLITE_STATIC);
	int rc = sqlite3_step(st);
	if (rc != SQLITE_ROW) {
		sqlite3_finalize(st);
		return command_fail(cmd, LIGHTNINGD,
			"no join_queue row for iid+client_pubkey "
			"(client must have sent JOIN_REQUEST first)");
	}
	int current = sqlite3_column_int(st, 0);
	sqlite3_finalize(st);

	/* Legal transitions:
	 *   QUEUED(0)   -> ACCEPTED(1) | REJECTED(3)
	 *   ACCEPTED(1) -> REJECTED(3)   (operator can change mind pre-rotation)
	 *   SIGNED(2)   -> (nothing; client already in)
	 *   REJECTED(3) -> ACCEPTED(1)   (operator can change mind)
	 *   CANCELLED(4) | ALREADY_MEMBER(5) -> (terminal)
	 */
	if (current == 2 || current == 4 || current == 5) {
		return command_fail(cmd, LIGHTNINGD,
			"join_queue row is in terminal status %d "
			"(2=SIGNED, 4=CANCELLED, 5=ALREADY_MEMBER); "
			"no transition possible",
			current);
	}

	if (sqlite3_prepare_v2(ss_plugin_db,
		"UPDATE lsp_join_queue SET status = ?, decided_at_block = ?, "
		"reason = ? WHERE factory_instance_id = ? AND client_pubkey = ?",
		-1, &st, NULL) != SQLITE_OK)
		return reply_sql_fail(cmd, "update_join_queue_status update prepare");
	sqlite3_bind_int(st, 1, new_status);
	sqlite3_bind_int(st, 2, (int)ss_state.current_blockheight);
	if (reason && reason[0]) sqlite3_bind_text(st, 3, reason, -1, SQLITE_STATIC);
	else sqlite3_bind_null(st, 3);
	sqlite3_bind_blob(st, 4, iid, (int)iid_len, SQLITE_STATIC);
	sqlite3_bind_blob(st, 5, cli, (int)cli_len, SQLITE_STATIC);
	if (!db_step_done(st, "update_join_queue_status"))
		return command_fail(cmd, LIGHTNINGD, "update_join_queue_status step failed");

	plugin_log(plugin_handle, LOG_INFORM,
		   "lsp_join_queue: iid=%.8s... client=%.8s... %d -> %d%s%s",
		   iid_hex, cli_hex, current, new_status,
		   reason && reason[0] ? " reason=" : "",
		   reason && reason[0] ? reason : "");

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_bool(js, "ok", true);
	json_add_u32(js, "prior_status", (uint32_t)current);
	json_add_u32(js, "new_status", (uint32_t)new_status);
	return command_finished(cmd, js);
}

struct command_result *json_wallet_approve_join_queued(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *iid_hex, *cli_hex;
	if (!param(cmd, buf, params,
		   p_req("factory_instance_id_hex", param_string, &iid_hex),
		   p_req("client_pubkey_hex", param_string, &cli_hex),
		   NULL))
		return command_param_failed();
	return update_join_queue_status(cmd, iid_hex, cli_hex, 1 /* ACCEPTED */, NULL);
}

struct command_result *json_wallet_refuse_join_queued(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *iid_hex, *cli_hex;
	const char *reason = NULL;
	if (!param(cmd, buf, params,
		   p_req("factory_instance_id_hex", param_string, &iid_hex),
		   p_req("client_pubkey_hex", param_string, &cli_hex),
		   p_opt("reason", param_string, &reason),
		   NULL))
		return command_param_failed();
	return update_join_queue_status(cmd, iid_hex, cli_hex, 3 /* REJECTED */, reason);
}

