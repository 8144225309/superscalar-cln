#ifndef SUPERSCALAR_SS_WALLET_RPC_H
#define SUPERSCALAR_SS_WALLET_RPC_H

/* ============================================================================
 * ss_wallet_rpc: C implementations of the 20 wallet-* RPCs the Node.js
 * soupwallet-cln-plugin used to expose. Same names, same params, same
 * response shapes — wallet UI doesn't need changes.
 *
 * See ARCHITECTURE_TWO_DB_ONE_PLUGIN.md.
 *
 * Phase 3b ships these handlers; they are NOT registered in commands[]
 * yet (Phase 5 cutover does that simultaneously with removing the
 * sidecar from the lightningd config).
 * ============================================================================ */

#include <plugins/libplugin.h>

struct command;
struct command_result;

/* IID counter */
struct command_result *json_wallet_get_iid_counter(struct command *cmd, const char *buf, const jsmntok_t *params);
struct command_result *json_wallet_increment_iid_counter(struct command *cmd, const char *buf, const jsmntok_t *params);
struct command_result *json_wallet_set_iid_counter(struct command *cmd, const char *buf, const jsmntok_t *params);

/* Factories */
struct command_result *json_wallet_upsert_factory(struct command *cmd, const char *buf, const jsmntok_t *params);
struct command_result *json_wallet_get_factory(struct command *cmd, const char *buf, const jsmntok_t *params);
struct command_result *json_wallet_list_factories_by_role(struct command *cmd, const char *buf, const jsmntok_t *params);

/* LSP-side join queue */
struct command_result *json_wallet_upsert_join_queue_entry(struct command *cmd, const char *buf, const jsmntok_t *params);
struct command_result *json_wallet_list_join_queue_by_status(struct command *cmd, const char *buf, const jsmntok_t *params);
struct command_result *json_wallet_count_join_queue_by_status(struct command *cmd, const char *buf, const jsmntok_t *params);

/* Client-side outgoing joins */
struct command_result *json_wallet_upsert_outgoing_join(struct command *cmd, const char *buf, const jsmntok_t *params);
struct command_result *json_wallet_list_outgoing_joins_by_status(struct command *cmd, const char *buf, const jsmntok_t *params);

/* Factory policy snapshots */
struct command_result *json_wallet_save_factory_policy_snapshot(struct command *cmd, const char *buf, const jsmntok_t *params);
struct command_result *json_wallet_get_factory_policy_snapshot(struct command *cmd, const char *buf, const jsmntok_t *params);

/* Operator preferences */
struct command_result *json_wallet_set_operator_pref(struct command *cmd, const char *buf, const jsmntok_t *params);
struct command_result *json_wallet_get_operator_pref(struct command *cmd, const char *buf, const jsmntok_t *params);

/* Client signing preferences */
struct command_result *json_wallet_set_signing_pref(struct command *cmd, const char *buf, const jsmntok_t *params);
struct command_result *json_wallet_get_signing_pref(struct command *cmd, const char *buf, const jsmntok_t *params);

/* General KV settings */
struct command_result *json_wallet_set_setting(struct command *cmd, const char *buf, const jsmntok_t *params);
struct command_result *json_wallet_get_setting(struct command *cmd, const char *buf, const jsmntok_t *params);

/* Health */
struct command_result *json_wallet_status(struct command *cmd, const char *buf, const jsmntok_t *params);


/* Session 1 (LSP UI gaps): admin actions on lsp_join_queue. Operators
 * approve or refuse a QUEUED join via the wallet UI; the row transitions
 * to ACCEPTED (waiting next rotation) or REJECTED. No wire-level
 * notification fires here — the client learns of the new status either
 * (a) when it polls or (b) on the next factory-trigger-ceremony for
 * ACCEPTED rows. */
struct command_result *json_wallet_approve_join_queued(struct command *cmd, const char *buf, const jsmntok_t *params);
struct command_result *json_wallet_refuse_join_queued(struct command *cmd, const char *buf, const jsmntok_t *params);

#endif /* SUPERSCALAR_SS_WALLET_RPC_H */
