/* SuperScalar channel factory plugin for Core Lightning.
 *
 * Links against libsuperscalar.a for DW tree construction,
 * MuSig2 signing, and factory state management.
 */
#include "config.h"
#include "ss_db.h"
#include "ss_wallet_rpc.h"
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <plugins/libplugin.h>
#include <bitcoin/psbt.h>
#include <bitcoin/privkey.h>
#include <common/addr.h>
#include <common/features.h>
#include <common/memleak.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <ccan/crypto/sha256/sha256.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include "ceremony.h"
#include "ceremony_wire.h"
#include "factory_state.h"
#include "nonce_exchange.h"
#include "persist.h"
#include "sweep_builder.h"

/* Direct read access to the wallet plugin's SQLite (Task #84).
 * The wallet plugin (Node.js, apps/cln-plugin) is the canonical writer
 * for the four typed coordination tables + the wallet_settings hex-blob
 * keys. The C plugin opens wallet.db read-only at init to load state
 * after restart; runtime writes still go via the wallet-* RPC dispatch.
 * No more CLN datastore touches anywhere. */
#include <sqlite3.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>

/* SuperScalar library */
#include <superscalar/factory.h>
#include <superscalar/musig.h>
#include <superscalar/dw_state.h>
#include <superscalar/ladder.h>
#include <superscalar/adaptor.h>
#include <superscalar/htlc_fee_bump.h>
#include <superscalar/fee_estimator.h>
#include <superscalar/tx_builder.h>
#include <common/bech32.h>
#include <wire/onion_wiregen.h>

/* Phase 3c3: static sanity — fee_estimator_storage on factory_instance_t
 * must be large enough for a fee_estimator_static_t. Checked at compile
 * time so we catch any upstream size change immediately. */
_Static_assert(sizeof(fee_estimator_static_t) <= 64,
	       "factory_instance_t.fee_estimator_storage too small; "
	       "bump size in factory_state.h");

/* Phase 3c3: default feerate for factory tree TX fee estimator. 1000
 * sat/kvB = 1 sat/vB — Bitcoin Core's minimum mempool acceptance floor.
 * Triggers fee_should_use_anchor=true so tree TXs get P2A anchors,
 * activating Phase 3c2/3c2.5's CPFP pipeline. Can be made dynamic via
 * fee_estimator_rpc_t (queries bitcoind estimatesmartfee) in a follow-up. */
#define SS_DEFAULT_FEE_RATE_SAT_PER_KVB 1000

/* Phase 3c3: initialize the per-factory fee estimator + wire into
 * factory_t. Call right after factory_init_from_pubkeys, before any
 * tree-building that needs anchor decisions. */
static void ss_factory_wire_fee_estimator(factory_instance_t *fi,
					  factory_t *factory)
{
	fee_estimator_static_t *fe =
		(fee_estimator_static_t *)fi->fee_estimator_storage;
	fee_estimator_static_init(fe, SS_DEFAULT_FEE_RATE_SAT_PER_KVB);
	factory->fee = (fee_estimator_t *)fe;
}

/* Phase 3c3: lazy retrofit. Called from handle_block_added for each
 * factory. If factory_t->fee is NULL (never wired at the specific
 * construction site — e.g. persistence reload path), wire it now.
 * Essentially free: one pointer check per factory per block. */
static void ss_ensure_factory_fee_wired(factory_instance_t *fi)
{
	factory_t *f = (factory_t *)fi->lib_factory;
	if (!f || f->fee)
		return;
	ss_factory_wire_fee_estimator(fi, f);
	/* No log here — plugin_handle is forward-declared below us. Silent
	 * retrofit is fine; it's a free no-op in steady state. */
}

struct plugin *plugin_handle;
superscalar_state_t ss_state;
static secp256k1_context *global_secp_ctx;

/* Ladder state: manages multi-factory lifecycle with staggered expiry.
 * NULL until initialized (requires LSP mode + HSM key). */
static ladder_t *ss_ladder;

/* Phase 3b: factory-TX kind tag for ss_broadcast_factory_tx. Values are
 * stored in struct broadcast_reply_ctx.kind and inform classification of
 * bitcoind's reply (only kickoff replies feed back into the signal
 * machine; other kinds are informational). Kept at file scope so it can
 * be referenced from call sites above the helper definitions. */
typedef enum {
	FACTORY_TX_KICKOFF = 0,
	FACTORY_TX_STATE   = 1,
	FACTORY_TX_BURN    = 2,
	FACTORY_TX_DIST    = 3,
} factory_tx_kind_t;

/* Forward decl: helper lives near the Phase 3b signal machine, far
 * below; call sites in the cooperative-close and force-close paths
 * reference it earlier. */
static void ss_broadcast_factory_tx(struct command *cmd,
				    factory_instance_t *fi,
				    const char *tx_hex,
				    int kind);

/* Forward decls: Phase 4d sweep-state name helpers used by
 * factory-list before their definitions lower in the file. */
static const char *sweep_state_name(uint8_t s);
static const char *sweep_type_name(uint8_t t);

/* Phase 3c2: CPFP-state name helpers used by factory-list. */
static const char *cpfp_state_name(uint8_t s);
static const char *cpfp_parent_kind_name(uint8_t k);

/* Phase 3c2.5d: forward decl — scheduler_tick calls this, but the
 * implementation lives below in the Phase 3c2.5c block. */
static void ss_scheduler_launch_cpfp(struct command *cmd,
				     factory_instance_t *fi,
				     size_t pc_idx,
				     uint64_t target_feerate);

/* Phase 4b2: forward decl — state_scan_block_cb auto-invokes the
 * burn rebuild path when a new epoch is identified after RBF. Helper
 * lives in Phase 4b's block. */
static int ss_rebuild_breach_burns(struct command *cmd,
				   factory_instance_t *fi,
				   uint32_t target_epoch);

/* Phase 3c2.5d gap-fix: json_factory_force_close at line ~6630 calls
 * these helpers which are defined later in the Phase 3c2.5d block.
 * Forward-declare to make the static declarations match. */
static int ss_find_p2a_vout(const uint8_t *tx, size_t len);
static void ss_register_pending_cpfp(factory_instance_t *fi,
				     uint8_t parent_kind,
				     const uint8_t *parent_txid,
				     uint32_t anchor_vout,
				     uint64_t value_at_stake,
				     uint32_t deadline_block,
				     uint32_t current_block);

/* Phase 4c: blocks an INIT factory must remain stuck before we log a
 * warning. ~1 day at 10-min blocks. Operator decides whether to abort. */
#define FACTORY_INIT_STUCK_BLOCKS 144


/* bLIP-56 factory message type */
/* ODD type = CLN allows it through connectd without any fork changes.
 * Factory protocol messages are plugin-to-plugin via custommsg;
 * they don't need to go through channeld. */
#define FACTORY_MSG_TYPE	33001

/* bLIP-56 feature bit (may already be in common/features.h) */
#ifndef OPT_PLUGGABLE_CHANNEL_FACTORIES
#define OPT_PLUGGABLE_CHANNEL_FACTORIES 271
#endif

/* bLIP-56 standard submessage IDs */
#define BLIP56_SUBMSG_SUPPORTED_PROTOCOLS	2
#define BLIP56_SUBMSG_FACTORY_PIGGYBACK		4

/* Configurable factory parameters */
#define DEFAULT_FUNDING_SATS		500000	   /* Per-channel funding amount */
#define DEFAULT_FACTORY_FUNDING_SATS	1000000	   /* Total factory funding */
#define DW_STEP_BLOCKS			144	   /* Blocks between DW states (~1 day) */
#define DW_STATES_PER_LAYER		16	   /* States per DW layer */
#define DIST_TX_LOCKTIME_DAYS		90	   /* nLockTime for distribution TX */
#define MAX_DIST_OUTPUTS		65	   /* Max outputs in distribution TX */
#define MAX_WIRE_BUF			32768	   /* Wire message buffer size */

/* Choose factory arity from total participant count (LSP + clients).
 *
 * ARITY_2 (2 clients per leaf) minimises tree depth and DW unwind time
 * for factories with 3+ total participants. For exactly 2 participants
 * (LSP + 1 client) ARITY_1 gives each party their own leaf, enabling
 * independent 2-of-2 unilateral exit without needing the other party.
 * Changing this policy requires updating all factory rebuild paths that
 * must reproduce the same arity for an existing on-chain tree. */
static factory_arity_t ss_choose_arity(size_t n_total)
{
	return n_total <= 2 ? FACTORY_ARITY_1 : FACTORY_ARITY_2;
}

/* Resolve the arity this factory should build with.
 *
 * fi->arity_mode is set either by factory-create's arity_mode param (LSP) or
 * received from FACTORY_PROPOSE / ALL_NONCES (client). Value 0 means "auto";
 * we fall back to ss_choose_arity so legacy behavior is preserved bit-for-bit
 * when the knob isn't touched.
 *
 * Accepts NULL fi to tolerate receive-side paths where the factory instance
 * hasn't been looked up yet — callers in that state pass n_total directly
 * via ss_choose_arity. */
static factory_arity_t ss_effective_arity(const factory_instance_t *fi)
{
	if (!fi)
		return FACTORY_ARITY_2;
	if (fi->arity_mode == 1 || fi->arity_mode == 2 ||
	    fi->arity_mode == 3)
		return (factory_arity_t)fi->arity_mode;
	return ss_choose_arity(fi->n_clients + 1);
}

/* Compute worst-case DW tree unwind time for HTLC safety.
 *
 * n_clients: clients only (not counting LSP); n_total = n_clients + 1.
 * arity:     the arity the factory was (or will be) built with.
 *
 * Formula: n_layers * step_blocks * (states_per_layer - 1)
 *          + n_layers * 6 (confirmation buffer per layer)
 *          + 36 (flat safety margin ~6 hours)
 *
 * Tree structure:
 *   ARITY_2: leaves = ceil(n_total / 2);  2 clients share one leaf
 *   ARITY_1: leaves = n_total;            each participant on own leaf
 *   ARITY_PS: same leaf count as ARITY_1, but the leaf DW layer is
 *             replaced with a chained-TX sequence that has no nSequence,
 *             so one leaf-layer's contribution is subtracted from total
 *             (mirrors upstream factory_early_warning_time).
 *   depth   = ceil(log2(leaves))          binary splits above leaves
 *   n_layers = depth + 1                  one DW counter layer per level */
static uint16_t compute_early_warning_time(size_t n_clients,
					   factory_arity_t arity)
{
	size_t n_total = n_clients + 1;

	/* ARITY_1 and ARITY_PS place one participant per leaf; ARITY_2
	 * pairs two clients per leaf for a shallower tree. */
	size_t leaves = (arity == FACTORY_ARITY_2)
		? (n_total + 1) / 2   /* ceil(n_total / 2) */
		: n_total;            /* one leaf per participant */

	/* Tree depth = ceil(log2(leaves)).
	 * Walk up: each level halves the node count (ceiling). */
	size_t depth = 0;
	size_t lvl = leaves;
	while (lvl > 1) {
		lvl = (lvl + 1) / 2;
		depth++;
	}
	size_t n_layers = depth + 1;

	uint32_t total = (uint32_t)n_layers * DW_STEP_BLOCKS
				       * (DW_STATES_PER_LAYER - 1)
		       + (uint32_t)n_layers * 6 + 36;

	/* Tier 2.6: PS leaves contribute zero nSequence at the leaf layer —
	 * TX chaining orders states without relative timelocks. Subtract the
	 * leaf DW layer's contribution (step_blocks * (states_per_layer - 1)
	 * plus its 6-block confirmation buffer). */
	if (arity == FACTORY_ARITY_PS && n_layers > 0) {
		uint32_t leaf_cost = (uint32_t)DW_STEP_BLOCKS
				   * (DW_STATES_PER_LAYER - 1) + 6;
		total = (total > leaf_cost) ? total - leaf_cost : 0;
	}

	if (total > 65535) total = 65535;
	return (uint16_t)total;
}

/* SuperScalar protocol ID: first 32 bytes of "SuperScalar/v1" zero-padded */
static const uint8_t SUPERSCALAR_PROTOCOL_ID[32] = {
	'S','u','p','e','r','S','c','a','l','a','r','/','v','1',
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

/* --------------------------------------------------------------------- *
 * Browse (third-party factory enumeration) — pending request tracking
 *
 * factory-browse-host sends FACTORY_INFO_REQUEST (0x0140) to a target peer
 * and awaits FACTORY_INFO_RESPONSE (0x0141). The RPC returns
 * command_still_pending; this table maps request_id -> cmd so the dispatch
 * handler can resolve the right RPC when the response arrives.
 * --------------------------------------------------------------------- */
#define SS_BROWSE_MAX_PENDING		16
#define SS_BROWSE_TIMEOUT_SECS		30
/* Runtime-mutable copy set by --superscalar-browse-timeout-secs.
 * Default mirrors the compile-time constant; operators can lower for
 * impatient UIs or raise for high-latency networks. */
static u32 ss_browse_timeout_secs = SS_BROWSE_TIMEOUT_SECS;
struct ss_browse_pending_slot {
	uint64_t request_id;
	struct command *cmd;
	time_t deadline;
	uint8_t peer_id[33];        /* for per-peer cap release */
};
static struct ss_browse_pending_slot ss_browse_pending[SS_BROWSE_MAX_PENDING];

/* B1.5: client-side cache of LSP-advertised policies, populated when a
 * FACTORY_INFO_RESPONSE arrives.  Keyed by (peer_id, instance_id).  The
 * validator looks this up at FACTORY_PROPOSE time to decide whether to
 * refuse signing.  Small static array — typical browse pattern touches
 * single-digit LSPs over a session; 64 slots is generous. */
#define SS_POLICY_CACHE_SIZE 64
struct ss_policy_cache_entry {
	uint8_t  lsp_peer_id[33];        /* LSP node_id from peer_id hex */
	uint8_t  instance_id[32];
	ss_factory_policy_t policy;
	bool     used;
	uint32_t cached_at_block;        /* for staleness checks (future) */
};
static struct ss_policy_cache_entry ss_policy_cache[SS_POLICY_CACHE_SIZE];

/* B1.5: hex peer_id -> 33-byte pubkey.  Returns true on success.  Defined
 * (or used inline) elsewhere in this file too; standalone here so the
 * cache helpers below can use it without forward-decl noise. */
static bool ss_peer_id_hex_to_bytes(const char *hex, uint8_t out[33])
{
	if (!hex || strlen(hex) != 66) return false;
	for (int j = 0; j < 33; j++) {
		unsigned int b;
		if (sscanf(hex + j*2, "%2x", &b) != 1) return false;
		out[j] = (uint8_t)b;
	}
	return true;
}

/* B1.5: insert or update a policy in the cache.  If a slot for this
 * (peer, instance_id) already exists, overwrite it; else find an unused
 * slot; else evict the oldest (simple LRU by cached_at_block). */
static void ss_policy_cache_persist(void);
static void ss_policy_cache_put(const uint8_t lsp_peer_id[33], const uint8_t instance_id[32], const ss_factory_policy_t *policy);

/* ============================================================================
 * Phase C: policy cache persistence (flat JSON file).
 * ============================================================================ */
#define SS_POLICY_CACHE_FILE   "superscalar_policy_cache.json"

static void ss_policy_cache_persist(void)
{
	FILE *f = fopen(SS_POLICY_CACHE_FILE ".tmp", "wb");
	if (!f) return;
	fprintf(f, "{\n  \"version\": 1,\n  \"entries\": [\n");
	bool first = true;
	for (int i = 0; i < SS_POLICY_CACHE_SIZE; i++) {
		struct ss_policy_cache_entry *e = &ss_policy_cache[i];
		if (!e->used) continue;
		if (!first) fprintf(f, ",\n");
		first = false;
		char lsp_hex[67], iid_hex[65];
		for (int j = 0; j < 33; j++) sprintf(lsp_hex + j*2, "%02x", e->lsp_peer_id[j]);
		lsp_hex[66] = 0;
		for (int j = 0; j < 32; j++) sprintf(iid_hex + j*2, "%02x", e->instance_id[j]);
		iid_hex[64] = 0;
		fprintf(f, "    {\"lsp\":\"%s\",\"iid\":\"%s\",\"cached_at_block\":%u,",
			lsp_hex, iid_hex, e->cached_at_block);
		uint8_t buf[1024];
		ss_factory_policy_t defaults;
		ss_factory_policy_init_defaults(&defaults);
		size_t plen = ss_factory_policy_encode_diff(&e->policy, &defaults, buf, sizeof(buf));
		fprintf(f, "\"diff_hex\":\"");
		for (size_t k = 0; k < plen; k++) fprintf(f, "%02x", buf[k]);
		fprintf(f, "\"}");
	}
	fprintf(f, "\n  ]\n}\n");
	fclose(f);
	rename(SS_POLICY_CACHE_FILE ".tmp", SS_POLICY_CACHE_FILE);
}

static void ss_policy_cache_load_from_disk(void)
{
	FILE *f = fopen(SS_POLICY_CACHE_FILE, "rb");
	if (!f) return;
	char *blob = NULL;
	size_t cap = 0, n = 0;
	while (!feof(f)) {
		if (n + 4096 > cap) { cap = cap ? cap * 2 : 8192; blob = realloc(blob, cap); if (!blob) { fclose(f); return; } }
		size_t r = fread(blob + n, 1, cap - n, f);
		if (r == 0) break;
		n += r;
	}
	fclose(f);
	if (!blob) return;
	if (n >= cap) n = cap - 1;
	blob[n] = '\0';

	int loaded = 0;
	const char *p = blob;
	while ((p = strstr(p, "\"lsp\":\""))) {
		p += 7;
		const char *lsp_end = strchr(p, '"');
		if (!lsp_end || lsp_end - p != 66) break;
		uint8_t lsp_pk[33];
		bool ok = true;
		for (int j = 0; j < 33; j++) {
			unsigned int b;
			if (sscanf(p + j*2, "%2x", &b) != 1) { ok = false; break; }
			lsp_pk[j] = (uint8_t)b;
		}
		if (!ok) { p = lsp_end; continue; }
		const char *iid_key = strstr(lsp_end, "\"iid\":\"");
		if (!iid_key) break;
		iid_key += 7;
		const char *iid_end = strchr(iid_key, '"');
		if (!iid_end || iid_end - iid_key != 64) { p = iid_end ? iid_end : lsp_end; continue; }
		uint8_t iid[32];
		for (int j = 0; j < 32; j++) {
			unsigned int b;
			if (sscanf(iid_key + j*2, "%2x", &b) != 1) { ok = false; break; }
			iid[j] = (uint8_t)b;
		}
		if (!ok) { p = iid_end; continue; }
		const char *dh_key = strstr(iid_end, "\"diff_hex\":\"");
		if (!dh_key) { p = iid_end; continue; }
		dh_key += 12;
		const char *dh_end = strchr(dh_key, '"');
		if (!dh_end) break;
		size_t hex_len = dh_end - dh_key;
		if (hex_len % 2 != 0 || hex_len > 2048) { p = dh_end; continue; }
		size_t diff_len = hex_len / 2;
		uint8_t *diff = malloc(diff_len ? diff_len : 1);
		if (!diff) { p = dh_end; continue; }
		for (size_t k = 0; k < diff_len; k++) {
			unsigned int b;
			if (sscanf(dh_key + k*2, "%2x", &b) != 1) { ok = false; break; }
			diff[k] = (uint8_t)b;
		}
		if (ok) {
			ss_factory_policy_t pol;
			ss_factory_policy_init_defaults(&pol);
			if (ss_factory_policy_decode(diff, diff_len, &pol)) {
				ss_policy_cache_put(lsp_pk, iid, &pol);
				loaded++;
			}
		}
		free(diff);
		p = dh_end;
	}
	free(blob);
	if (loaded > 0)
		plugin_log(plugin_handle, LOG_INFORM,
			   "Phase C: loaded %d policy cache entries from %s",
			   loaded, SS_POLICY_CACHE_FILE);
}

static struct command_result *json_factory_get_cached_policy(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *lsp_hex = NULL;
	const char *iid_hex = NULL;
	if (!param(cmd, buf, params,
		   p_opt("lsp_peer_id", param_string, &lsp_hex),
		   p_opt("instance_id", param_string, &iid_hex),
		   NULL))
		return command_param_failed();

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_array_start(js, "entries");

	for (int i = 0; i < SS_POLICY_CACHE_SIZE; i++) {
		struct ss_policy_cache_entry *e = &ss_policy_cache[i];
		if (!e->used) continue;
		if (lsp_hex) {
			uint8_t lsp_pk[33];
			if (strlen(lsp_hex) != 66) continue;
			if (!hex_decode(lsp_hex, 66, lsp_pk, 33)) continue;
			if (memcmp(e->lsp_peer_id, lsp_pk, 33) != 0) continue;
		}
		if (iid_hex) {
			uint8_t iid[32];
			if (strlen(iid_hex) != 64) continue;
			if (!hex_decode(iid_hex, 64, iid, 32)) continue;
			if (memcmp(e->instance_id, iid, 32) != 0) continue;
		}

		json_object_start(js, NULL);
		char lh[67], ih[65];
		for (int j = 0; j < 33; j++) sprintf(lh + j*2, "%02x", e->lsp_peer_id[j]);
		lh[66] = 0;
		for (int j = 0; j < 32; j++) sprintf(ih + j*2, "%02x", e->instance_id[j]);
		ih[64] = 0;
		json_add_string(js, "lsp_peer_id", lh);
		json_add_string(js, "instance_id", ih);
		json_add_u32(js, "cached_at_block", e->cached_at_block);

		json_object_start(js, "policy");
		const ss_factory_policy_t *p = &e->policy;
		json_add_u32(js, "schema_version", p->schema_version);
		json_add_u32(js, "arity_mode", (uint32_t)p->arity_mode);
		json_add_u32(js, "leaf_arity", p->leaf_arity);
		json_add_u32(js, "lifetime_blocks", p->lifetime_blocks);
		json_add_u32(js, "dying_period_blocks", p->dying_period_blocks);
		json_add_u64(js, "per_client_capacity_sat", p->per_client_capacity_sat);
		json_add_u64(js, "lsp_fee_sat", p->lsp_fee_sat);
		json_add_u32(js, "lsp_fee_ppm", p->lsp_fee_ppm);
		json_add_u64(js, "htlc_min_sat", p->htlc_min_sat);
		json_add_u64(js, "htlc_max_sat", p->htlc_max_sat);
		json_add_u32(js, "max_concurrent_htlcs_per_channel",
			     p->max_concurrent_htlcs_per_channel);
		json_add_u64(js, "max_in_flight_msat_per_channel",
			     p->max_in_flight_msat_per_channel);
		json_add_u32(js, "min_final_cltv_expiry_delta",
			     p->min_final_cltv_expiry_delta);
		json_add_u32(js, "cltv_expiry_delta_forward",
			     p->cltv_expiry_delta_forward);
		json_add_u64(js, "min_capacity_per_join_sat",
			     p->min_capacity_per_join_sat);
		json_add_u64(js, "max_capacity_per_join_sat",
			     p->max_capacity_per_join_sat);
		json_add_u32(js, "proof_tier_required",
			     (uint32_t)p->proof_tier_required);
		json_add_u32(js, "rotation_interval_blocks", p->rotation_interval_blocks);
		json_add_bool(js, "allow_tier_b_rollover", p->allow_tier_b_rollover);
		json_add_u32(js, "state_replay_defense_window_blocks",
			     p->state_replay_defense_window_blocks);
		json_object_end(js);
		json_object_end(js);
	}

	json_array_end(js);
	return command_finished(cmd, js);
}


static void ss_policy_cache_put(const uint8_t lsp_peer_id[33],
				  const uint8_t instance_id[32],
				  const ss_factory_policy_t *policy)
{
	if (!lsp_peer_id || !instance_id || !policy) return;
	int free_slot = -1;
	int oldest_slot = 0;
	uint32_t oldest_age = UINT32_MAX;
	for (int i = 0; i < SS_POLICY_CACHE_SIZE; i++) {
		struct ss_policy_cache_entry *e = &ss_policy_cache[i];
		if (e->used
		    && memcmp(e->lsp_peer_id, lsp_peer_id, 33) == 0
		    && memcmp(e->instance_id, instance_id, 32) == 0) {
			/* update in place */
			memcpy(&e->policy, policy, sizeof(e->policy));
			e->cached_at_block = ss_state.current_blockheight;
			ss_policy_cache_persist();
			return;
		}
		if (!e->used && free_slot < 0) free_slot = i;
		if (e->used && e->cached_at_block < oldest_age) {
			oldest_age = e->cached_at_block;
			oldest_slot = i;
		}
	}
	int target = (free_slot >= 0) ? free_slot : oldest_slot;
	struct ss_policy_cache_entry *e = &ss_policy_cache[target];
	memcpy(e->lsp_peer_id, lsp_peer_id, 33);
	memcpy(e->instance_id, instance_id, 32);
	memcpy(&e->policy, policy, sizeof(e->policy));
	e->cached_at_block = ss_state.current_blockheight;
	e->used = true;
	ss_policy_cache_persist();
}

/* B1.5: look up a cached policy.  Returns pointer into the cache (caller
 * must NOT free) or NULL if not found.  Cache entries are stable for
 * the lifetime of the plugin process. */
static const ss_factory_policy_t *ss_policy_cache_get(
	const uint8_t lsp_peer_id[33], const uint8_t instance_id[32])
{
	if (!lsp_peer_id || !instance_id) return NULL;
	for (int i = 0; i < SS_POLICY_CACHE_SIZE; i++) {
		struct ss_policy_cache_entry *e = &ss_policy_cache[i];
		if (e->used
		    && memcmp(e->lsp_peer_id, lsp_peer_id, 33) == 0
		    && memcmp(e->instance_id, instance_id, 32) == 0)
			return &e->policy;
	}
	return NULL;
}

/* B2: cache of most-recently-received FACTORY_PROPOSE parameters per
 * (lsp_peer_id, instance_id).  Populated by the client-side FACTORY_PROPOSE
 * handler immediately after parse — BEFORE the B1.5 validator runs — so the
 * wallet UI can render even refused proposals (the user can see WHY a
 * proposal was rejected, not just "rejected").  Read by the
 * factory-review-proposal RPC. */
struct ss_pending_proposal_entry {
	uint8_t  lsp_peer_id[33];
	uint8_t  instance_id[32];
	uint64_t funding_sats;
	uint32_t n_participants;
	uint32_t our_pidx;
	uint64_t allocs[MAX_FACTORY_PARTICIPANTS];
	uint8_t  n_allocs;
	/* Validation outcome from the most recent FACTORY_PROPOSE for this
	 * (lsp, instance) — populated alongside the cache write. */
	int      last_validate_result;   /* SS_POLICY_VALIDATE_* */
	uint16_t last_validate_field_tlv;
	char     last_validate_reason[128];
	uint32_t received_at_block;
	bool     used;
	/* D.6: when auto_sign_on_validator_pass=false and validator OK, the
	 * raw FACTORY_PROPOSE payload is copied here so factory-approve-
	 * proposal can re-dispatch it through the normal handler later. */
	uint8_t *held_payload;       /* heap-allocated; freed on approve/refuse */
	size_t   held_payload_len;
	/* Set by factory-approve-proposal before re-dispatch so the gate
	 * lets the next pass through.  Cleared after dispatch completes
	 * (or on refuse). */
	bool     user_approved;
	bool     user_refused;
};

static bool ss_decode_node_id_hex(const char *hex, uint8_t out[33]);
static void ss_lsp_sig_queue_deadline_tick(struct command *cmd);
static void ss_lsp_sig_queue_persist(void);
static void ss_lsp_sig_queue_load_from_disk(void);
static bool ss_ceremony_expecting_nonces(const factory_instance_t *fi);
static bool ss_ceremony_expecting_psigs(const factory_instance_t *fi);
static void ss_send_factory_abort(struct command *cmd, const char *peer_id_hex, const uint8_t instance_id[32], uint8_t reason);
static void ss_terminalize_failed(struct command *cmd, factory_instance_t *fi, uint8_t abort_reason);




/* ============================================================================
 * Phase D follow-up: ring buffer for SIGN_QUEUE_RESPONSE events the
 * client receives with non-AWAITING state (MISSED / EXPIRED / REFUSED).
 *
 * Used by client-list-recent-sign-queue-events RPC, polled by the
 * wallet's missed-ceremony banner. 32-slot circular buffer.
 * ============================================================================ */
#define SS_RECENT_SQ_EVENTS_SIZE   32

struct ss_recent_sq_event {
	uint8_t  factory_instance_id[32];
	uint8_t  lsp_peer_id[33];
	uint8_t  ceremony_id[8];
	uint8_t  state;
	uint32_t deadline_block;
	uint32_t observed_at_block;
	bool     used;
	bool     dismissed;
};
static struct ss_recent_sq_event ss_recent_sq_events[SS_RECENT_SQ_EVENTS_SIZE];
static int ss_recent_sq_next = 0;

static void ss_recent_sq_push(const uint8_t factory_iid[32],
			      const uint8_t lsp_peer_id[33],
			      const uint8_t ceremony_id[8],
			      uint8_t state, uint32_t deadline_block)
{
	struct ss_recent_sq_event *e = &ss_recent_sq_events[ss_recent_sq_next];
	memset(e, 0, sizeof(*e));
	memcpy(e->factory_instance_id, factory_iid, 32);
	memcpy(e->lsp_peer_id, lsp_peer_id, 33);
	memcpy(e->ceremony_id, ceremony_id, 8);
	e->state = state;
	e->deadline_block = deadline_block;
	e->observed_at_block = ss_state.current_blockheight;
	e->used = true;
	ss_recent_sq_next = (ss_recent_sq_next + 1) % SS_RECENT_SQ_EVENTS_SIZE;
}


/* ============================================================================
 * Phase D.2: LSP-side per-client signature queue (in-memory).
 *
 * Tracks, per (factory_iid, client_pk, ceremony_id) on the LSP node,
 * whether the client has signed yet, what state the proposal is in,
 * and the raw FACTORY_PROPOSE payload we sent (so we can replay it on
 * the client's reconnect pull).
 *
 * Populated by ss_kickoff_factory_signing's fan-out loop (each send to
 * a client adds an entry).  Updated when LSP processes inbound
 * NONCE_BUNDLE (state -> SIGNED).  Deadline tick marks remaining
 * AWAITING entries as MISSED.
 *
 * V1: in-memory only.  Lost on plugin restart.  Acceptable for V1 because
 * LSPs that restart mid-ceremony abort the ceremony anyway.
 * ============================================================================ */
#define SS_LSP_SIG_QUEUE_SIZE   256

struct ss_lsp_sig_queue_entry {
	uint8_t  factory_instance_id[32];
	uint8_t  client_peer_id[33];
	uint8_t  ceremony_id[8];
	uint8_t  state;              /* SS_SIGQUEUE_* */
	uint32_t deadline_block;
	uint8_t *proposal_blob;      /* heap-alloc; freed on eviction */
	size_t   proposal_blob_len;
	uint32_t inserted_at_block;
	bool     used;
};
static struct ss_lsp_sig_queue_entry ss_lsp_sig_queue[SS_LSP_SIG_QUEUE_SIZE];

/* Find an existing slot for this (factory, client, ceremony) triple, or
 * allocate one (overwriting the oldest if all slots are full). */
static struct ss_lsp_sig_queue_entry *ss_lsp_sig_queue_slot(
	const uint8_t factory_iid[32], const uint8_t client_pk[33],
	const uint8_t ceremony_id[8])
{
	int free_slot = -1;
	int oldest = 0;
	uint32_t oldest_age = UINT32_MAX;
	for (int i = 0; i < SS_LSP_SIG_QUEUE_SIZE; i++) {
		struct ss_lsp_sig_queue_entry *e = &ss_lsp_sig_queue[i];
		if (e->used
		    && memcmp(e->factory_instance_id, factory_iid, 32) == 0
		    && memcmp(e->client_peer_id, client_pk, 33) == 0
		    && memcmp(e->ceremony_id, ceremony_id, 8) == 0)
			return e;
		if (!e->used && free_slot < 0) free_slot = i;
		if (e->used && e->inserted_at_block < oldest_age) {
			oldest_age = e->inserted_at_block;
			oldest = i;
		}
	}
	int target = (free_slot >= 0) ? free_slot : oldest;
	struct ss_lsp_sig_queue_entry *e = &ss_lsp_sig_queue[target];
	if (e->used && e->proposal_blob) {
		free(e->proposal_blob);
		e->proposal_blob = NULL;
		e->proposal_blob_len = 0;
	}
	memset(e, 0, sizeof(*e));
	memcpy(e->factory_instance_id, factory_iid, 32);
	memcpy(e->client_peer_id, client_pk, 33);
	memcpy(e->ceremony_id, ceremony_id, 8);
	e->used = true;
	return e;
}

/* Update an existing entry's state by (factory, client) match. */
static void ss_lsp_sig_queue_mark(
	const uint8_t factory_iid[32], const uint8_t client_pk[33],
	uint8_t new_state)
{
	for (int i = 0; i < SS_LSP_SIG_QUEUE_SIZE; i++) {
		struct ss_lsp_sig_queue_entry *e = &ss_lsp_sig_queue[i];
		if (!e->used) continue;
		if (memcmp(e->factory_instance_id, factory_iid, 32) != 0) continue;
		if (memcmp(e->client_peer_id, client_pk, 33) != 0) continue;
		e->state = new_state;
		/* Drop the blob once the client has signed/missed/refused
		 * to free memory — the LSP no longer needs to replay. */
		if (new_state != SS_SIGQUEUE_AWAITING_YOUR_SIGNATURE
		    && e->proposal_blob) {
			free(e->proposal_blob);
			e->proposal_blob = NULL;
			e->proposal_blob_len = 0;
		}
	}
	ss_lsp_sig_queue_persist();
}


/* ============================================================================
 * Audit item #4: LSP signature queue persistence (flat JSON file).
 *
 * The ring buffer lives in memory; this layer mirrors mutations to a JSON
 * file so a plugin restart can re-arm clients that hadn't yet pulled their
 * AWAITING entries via SIGN_QUEUE_REQUEST. Format matches the policy_cache
 * pattern (Phase C v1): atomic write via .tmp + rename, one entry per slot.
 * ============================================================================ */
#define SS_LSP_SIG_QUEUE_FILE   "superscalar_lsp_sig_queue.json"

static void ss_lsp_sig_queue_persist(void)
{
	FILE *f = fopen(SS_LSP_SIG_QUEUE_FILE ".tmp", "wb");
	if (!f) return;
	fprintf(f, "{\n  \"version\": 1,\n  \"entries\": [\n");
	bool first = true;
	for (int i = 0; i < SS_LSP_SIG_QUEUE_SIZE; i++) {
		struct ss_lsp_sig_queue_entry *e = &ss_lsp_sig_queue[i];
		if (!e->used) continue;
		if (!first) fprintf(f, ",\n");
		first = false;
		char iid_hex[65], cli_hex[67], cid_hex[17];
		for (int j = 0; j < 32; j++)
			sprintf(iid_hex + j*2, "%02x", e->factory_instance_id[j]);
		iid_hex[64] = 0;
		for (int j = 0; j < 33; j++)
			sprintf(cli_hex + j*2, "%02x", e->client_peer_id[j]);
		cli_hex[66] = 0;
		for (int j = 0; j < 8; j++)
			sprintf(cid_hex + j*2, "%02x", e->ceremony_id[j]);
		cid_hex[16] = 0;
		fprintf(f, "    {\"iid\":\"%s\",\"cli\":\"%s\",\"cid\":\"%s\","
			"\"state\":%u,\"deadline\":%u,\"inserted\":%u,\"blob_hex\":\"",
			iid_hex, cli_hex, cid_hex,
			(unsigned)e->state, e->deadline_block, e->inserted_at_block);
		if (e->proposal_blob) {
			for (size_t k = 0; k < e->proposal_blob_len; k++)
				fprintf(f, "%02x", e->proposal_blob[k]);
		}
		fprintf(f, "\"}");
	}
	fprintf(f, "\n  ]\n}\n");
	fclose(f);
	rename(SS_LSP_SIG_QUEUE_FILE ".tmp", SS_LSP_SIG_QUEUE_FILE);
}

static void ss_lsp_sig_queue_load_from_disk(void)
{
	FILE *f = fopen(SS_LSP_SIG_QUEUE_FILE, "rb");
	if (!f) return;
	char *blob = NULL;
	size_t cap = 0, n = 0;
	while (!feof(f)) {
		if (n + 4096 > cap) {
			cap = cap ? cap * 2 : 8192;
			char *bigger = realloc(blob, cap);
			if (!bigger) { free(blob); fclose(f); return; }
			blob = bigger;
		}
		size_t r = fread(blob + n, 1, cap - n, f);
		if (r == 0) break;
		n += r;
	}
	fclose(f);
	if (!blob) return;
	if (n >= cap) n = cap - 1;
	blob[n] = '\0';

	int loaded = 0;
	const char *p = blob;
	while ((p = strstr(p, "\"iid\":\""))) {
		p += 7;
		const char *iid_end = strchr(p, '"');
		if (!iid_end || iid_end - p != 64) break;
		uint8_t iid[32];
		bool ok = true;
		for (int j = 0; j < 32; j++) {
			unsigned int b;
			if (sscanf(p + j*2, "%2x", &b) != 1) { ok = false; break; }
			iid[j] = (uint8_t)b;
		}
		if (!ok) { p = iid_end; continue; }

		const char *cli_key = strstr(iid_end, "\"cli\":\"");
		if (!cli_key) break;
		cli_key += 7;
		const char *cli_end = strchr(cli_key, '"');
		if (!cli_end || cli_end - cli_key != 66) { p = iid_end; continue; }
		uint8_t cli[33];
		for (int j = 0; j < 33; j++) {
			unsigned int b;
			if (sscanf(cli_key + j*2, "%2x", &b) != 1) { ok = false; break; }
			cli[j] = (uint8_t)b;
		}
		if (!ok) { p = cli_end; continue; }

		const char *cid_key = strstr(cli_end, "\"cid\":\"");
		if (!cid_key) break;
		cid_key += 7;
		const char *cid_end = strchr(cid_key, '"');
		if (!cid_end || cid_end - cid_key != 16) { p = cli_end; continue; }
		uint8_t cid[8];
		for (int j = 0; j < 8; j++) {
			unsigned int b;
			if (sscanf(cid_key + j*2, "%2x", &b) != 1) { ok = false; break; }
			cid[j] = (uint8_t)b;
		}
		if (!ok) { p = cid_end; continue; }

		const char *state_key = strstr(cid_end, "\"state\":");
		const char *deadline_key = strstr(cid_end, "\"deadline\":");
		const char *inserted_key = strstr(cid_end, "\"inserted\":");
		const char *blob_key = strstr(cid_end, "\"blob_hex\":\"");
		if (!state_key || !deadline_key || !inserted_key || !blob_key) {
			p = cid_end; continue;
		}
		unsigned int state_u = 0, dl = 0, ins = 0;
		sscanf(state_key + 8, "%u", &state_u);
		sscanf(deadline_key + 11, "%u", &dl);
		sscanf(inserted_key + 11, "%u", &ins);

		blob_key += 12;
		const char *blob_end = strchr(blob_key, '"');
		if (!blob_end) { p = cid_end; continue; }
		size_t hex_len = (size_t)(blob_end - blob_key);
		if (hex_len % 2 != 0) { p = blob_end; continue; }
		size_t bytes_len = hex_len / 2;
		uint8_t *blob_bytes = NULL;
		if (bytes_len > 0) {
			blob_bytes = malloc(bytes_len);
			if (!blob_bytes) { p = blob_end; continue; }
			for (size_t k = 0; k < bytes_len; k++) {
				unsigned int b;
				if (sscanf(blob_key + k*2, "%2x", &b) != 1) {
					ok = false; break;
				}
				blob_bytes[k] = (uint8_t)b;
			}
			if (!ok) { free(blob_bytes); p = blob_end; continue; }
		}

		struct ss_lsp_sig_queue_entry *e =
			ss_lsp_sig_queue_slot(iid, cli, cid);
		e->state = (uint8_t)state_u;
		e->deadline_block = dl;
		e->inserted_at_block = ins;
		if (e->proposal_blob) {
			free(e->proposal_blob);
			e->proposal_blob = NULL;
			e->proposal_blob_len = 0;
		}
		if (blob_bytes) {
			e->proposal_blob = blob_bytes;
			e->proposal_blob_len = bytes_len;
		}
		loaded++;
		p = blob_end;
	}

	free(blob);
	plugin_log(plugin_handle, LOG_INFORM,
		   "LSP sig queue: loaded %d entries from %s",
		   loaded, SS_LSP_SIG_QUEUE_FILE);
}


static struct ss_pending_proposal_entry ss_pending_proposals[SS_POLICY_CACHE_SIZE];

static struct ss_pending_proposal_entry *ss_pending_proposals_slot(
	const uint8_t lsp_peer_id[33], const uint8_t instance_id[32])
{
	int free_slot = -1;
	int oldest = 0;
	uint32_t oldest_age = UINT32_MAX;
	for (int i = 0; i < SS_POLICY_CACHE_SIZE; i++) {
		struct ss_pending_proposal_entry *e = &ss_pending_proposals[i];
		if (e->used
		    && memcmp(e->lsp_peer_id, lsp_peer_id, 33) == 0
		    && memcmp(e->instance_id, instance_id, 32) == 0)
			return e;
		if (!e->used && free_slot < 0) free_slot = i;
		if (e->used && e->received_at_block < oldest_age) {
			oldest_age = e->received_at_block;
			oldest = i;
		}
	}
	int target = (free_slot >= 0) ? free_slot : oldest;
	struct ss_pending_proposal_entry *e = &ss_pending_proposals[target];
	memset(e, 0, sizeof(*e));
	memcpy(e->lsp_peer_id, lsp_peer_id, 33);
	memcpy(e->instance_id, instance_id, 32);
	e->used = true;
	return e;
}

static const struct ss_pending_proposal_entry *ss_pending_proposals_get(
	const uint8_t lsp_peer_id[33], const uint8_t instance_id[32])
{
	if (!lsp_peer_id || !instance_id) return NULL;
	for (int i = 0; i < SS_POLICY_CACHE_SIZE; i++) {
		struct ss_pending_proposal_entry *e = &ss_pending_proposals[i];
		if (e->used
		    && memcmp(e->lsp_peer_id, lsp_peer_id, 33) == 0
		    && memcmp(e->instance_id, instance_id, 32) == 0)
			return e;
	}
	return NULL;
}

/* ============================================================================
 * B3 follow-up (task #115): client-signing-prefs-get / -set RPCs.
 *
 * Persistence: flat JSON file in the plugin cwd (= lightning data dir).
 * On init, load from disk or fall back to canonical defaults.  On set,
 * write the new prefs to disk before returning.  When the wallet daemon
 * SQLite (PR #30) lands, this migrates to wallet-set-setting via the
 * usual dual-write pattern.
 *
 * Used by the B1.5 validator hook and json_factory_review_proposal — both
 * read from g_signing_prefs instead of calling init_defaults inline.
 * ========================================================================= */

#define SS_SIGNING_PREFS_FILE "superscalar_signing_prefs.json"

/* Stock libplugin has param_array but no param_object; tiny helper. */
static struct command_result *ss_param_object(struct command *cmd, const char *name,
					      const char *buffer, const jsmntok_t *tok,
					      const jsmntok_t **obj)
{
	if (tok->type == JSMN_OBJECT) {
		*obj = tok;
		return NULL;
	}
	return command_fail_badparam(cmd, name, buffer, tok, "should be a json object");
}

static ss_client_signing_prefs_t g_signing_prefs;
static bool g_signing_prefs_loaded = false;

static void ss_signing_prefs_load_or_default(void)
{
	if (g_signing_prefs_loaded)
		return;
	ss_client_signing_prefs_init_defaults(&g_signing_prefs);
	g_signing_prefs_loaded = true;

	FILE *f = fopen(SS_SIGNING_PREFS_FILE, "rb");
	if (!f)
		return;
	char buf[8192];
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';

	/* Tiny lenient parser — keys are unique and we wrote this file, so
	 * substring-scan-for-key-then-strtoull is fine.  Skip a field if
	 * absent: defaults already in place. */
	const char *p;
#define LOAD_U64(field) do { \
		p = strstr(buf, "\"" #field "\""); \
		if (p) { p = strchr(p, ':'); \
			if (p) g_signing_prefs.field = (uint64_t)strtoull(p + 1, NULL, 10); } \
	} while (0)
#define LOAD_U32(field) do { \
		p = strstr(buf, "\"" #field "\""); \
		if (p) { p = strchr(p, ':'); \
			if (p) g_signing_prefs.field = (uint32_t)strtoul(p + 1, NULL, 10); } \
	} while (0)
#define LOAD_U16(field) do { \
		p = strstr(buf, "\"" #field "\""); \
		if (p) { p = strchr(p, ':'); \
			if (p) g_signing_prefs.field = (uint16_t)strtoul(p + 1, NULL, 10); } \
	} while (0)
#define LOAD_BOOL(field) do { \
		p = strstr(buf, "\"" #field "\""); \
		if (p) { p = strchr(p, ':'); \
			if (p) { while (*++p == ' '); \
				g_signing_prefs.field = (*p == 't'); } } \
	} while (0)
	LOAD_U64(max_htlc_min_sat);
	LOAD_U64(min_htlc_max_sat);
	LOAD_U16(min_max_concurrent_htlcs);
	LOAD_U64(min_max_in_flight_msat);
	LOAD_U32(max_min_final_cltv_delta);
	LOAD_U32(max_cltv_delta_forward);
	LOAD_U64(max_min_capacity_per_join_sat);
	LOAD_U64(min_max_capacity_per_join_sat);
	LOAD_BOOL(require_strict_proof_tier);
	{
		const char *q = strstr(buf, "\"max_proof_tier\"");
		if (q) { q = strchr(q, ':');
			if (q) g_signing_prefs.max_proof_tier = (ss_proof_tier_t)strtoul(q + 1, NULL, 10); }
	}
	LOAD_U32(min_rotation_interval_blocks);
	LOAD_BOOL(require_tier_b_rollover);
	LOAD_U32(min_state_replay_defense_window_blocks);
	LOAD_BOOL(auto_sign_on_validator_pass);
#undef LOAD_U64
#undef LOAD_U32
#undef LOAD_U16
#undef LOAD_BOOL
}

static int ss_signing_prefs_persist(void)
{
	FILE *f = fopen(SS_SIGNING_PREFS_FILE ".tmp", "wb");
	if (!f)
		return -1;
	fprintf(f, "{\n");
	fprintf(f, "  \"max_htlc_min_sat\": %" PRIu64 ",\n", g_signing_prefs.max_htlc_min_sat);
	fprintf(f, "  \"min_htlc_max_sat\": %" PRIu64 ",\n", g_signing_prefs.min_htlc_max_sat);
	fprintf(f, "  \"min_max_concurrent_htlcs\": %u,\n", (unsigned)g_signing_prefs.min_max_concurrent_htlcs);
	fprintf(f, "  \"min_max_in_flight_msat\": %" PRIu64 ",\n", g_signing_prefs.min_max_in_flight_msat);
	fprintf(f, "  \"max_min_final_cltv_delta\": %u,\n", g_signing_prefs.max_min_final_cltv_delta);
	fprintf(f, "  \"max_cltv_delta_forward\": %u,\n", g_signing_prefs.max_cltv_delta_forward);
	fprintf(f, "  \"max_min_capacity_per_join_sat\": %" PRIu64 ",\n", g_signing_prefs.max_min_capacity_per_join_sat);
	fprintf(f, "  \"min_max_capacity_per_join_sat\": %" PRIu64 ",\n", g_signing_prefs.min_max_capacity_per_join_sat);
	fprintf(f, "  \"require_strict_proof_tier\": %s,\n", g_signing_prefs.require_strict_proof_tier ? "true" : "false");
	fprintf(f, "  \"max_proof_tier\": %u,\n", (unsigned)g_signing_prefs.max_proof_tier);
	fprintf(f, "  \"min_rotation_interval_blocks\": %u,\n", g_signing_prefs.min_rotation_interval_blocks);
	fprintf(f, "  \"require_tier_b_rollover\": %s,\n", g_signing_prefs.require_tier_b_rollover ? "true" : "false");
	fprintf(f, "  \"min_state_replay_defense_window_blocks\": %u,\n", g_signing_prefs.min_state_replay_defense_window_blocks);
	fprintf(f, "  \"auto_sign_on_validator_pass\": %s\n", g_signing_prefs.auto_sign_on_validator_pass ? "true" : "false");
	fprintf(f, "}\n");
	fclose(f);
	if (rename(SS_SIGNING_PREFS_FILE ".tmp", SS_SIGNING_PREFS_FILE) != 0)
		return -1;
	return 0;
}

static void ss_signing_prefs_emit_json(struct json_stream *js,
				       const ss_client_signing_prefs_t *p)
{
	json_add_u64(js, "max_htlc_min_sat", p->max_htlc_min_sat);
	json_add_u64(js, "min_htlc_max_sat", p->min_htlc_max_sat);
	json_add_u32(js, "min_max_concurrent_htlcs", p->min_max_concurrent_htlcs);
	json_add_u64(js, "min_max_in_flight_msat", p->min_max_in_flight_msat);
	json_add_u32(js, "max_min_final_cltv_delta", p->max_min_final_cltv_delta);
	json_add_u32(js, "max_cltv_delta_forward", p->max_cltv_delta_forward);
	json_add_u64(js, "max_min_capacity_per_join_sat", p->max_min_capacity_per_join_sat);
	json_add_u64(js, "min_max_capacity_per_join_sat", p->min_max_capacity_per_join_sat);
	json_add_bool(js, "require_strict_proof_tier", p->require_strict_proof_tier);
	json_add_u32(js, "max_proof_tier", (uint32_t)p->max_proof_tier);
	json_add_u32(js, "min_rotation_interval_blocks", p->min_rotation_interval_blocks);
	json_add_bool(js, "require_tier_b_rollover", p->require_tier_b_rollover);
	json_add_u32(js, "min_state_replay_defense_window_blocks",
		     p->min_state_replay_defense_window_blocks);
	json_add_bool(js, "auto_sign_on_validator_pass", p->auto_sign_on_validator_pass);
}

static struct command_result *json_client_signing_prefs_get(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	ss_signing_prefs_load_or_default();

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_object_start(js, "prefs");
	ss_signing_prefs_emit_json(js, &g_signing_prefs);
	json_object_end(js);
	json_add_bool(js, "is_default", false);
	return command_finished(cmd, js);
}

static struct command_result *json_client_signing_prefs_set(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const jsmntok_t *prefs_tok;

	if (!param(cmd, buf, params,
		   p_req("prefs", ss_param_object, &prefs_tok),
		   NULL))
		return command_param_failed();

	if (prefs_tok->type != JSMN_OBJECT)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "prefs must be an object");

	ss_signing_prefs_load_or_default();

	const jsmntok_t *t;
#define APPLY_U64(field) do { \
		t = json_get_member(buf, prefs_tok, #field); \
		if (t) json_to_u64(buf, t, &g_signing_prefs.field); \
	} while (0)
#define APPLY_U32(field) do { \
		t = json_get_member(buf, prefs_tok, #field); \
		if (t) json_to_u32(buf, t, &g_signing_prefs.field); \
	} while (0)
#define APPLY_U16(field) do { \
		t = json_get_member(buf, prefs_tok, #field); \
		uint32_t tmp; \
		if (t && json_to_u32(buf, t, &tmp)) \
			g_signing_prefs.field = (uint16_t)tmp; \
	} while (0)
#define APPLY_BOOL(field) do { \
		t = json_get_member(buf, prefs_tok, #field); \
		bool tmp; \
		if (t && json_to_bool(buf, t, &tmp)) \
			g_signing_prefs.field = tmp; \
	} while (0)
	APPLY_U64(max_htlc_min_sat);
	APPLY_U64(min_htlc_max_sat);
	APPLY_U16(min_max_concurrent_htlcs);
	APPLY_U64(min_max_in_flight_msat);
	APPLY_U32(max_min_final_cltv_delta);
	APPLY_U32(max_cltv_delta_forward);
	APPLY_U64(max_min_capacity_per_join_sat);
	APPLY_U64(min_max_capacity_per_join_sat);
	APPLY_BOOL(require_strict_proof_tier);
	{
		uint32_t tier_u32;
		t = json_get_member(buf, prefs_tok, "max_proof_tier");
		if (t && json_to_u32(buf, t, &tier_u32))
			g_signing_prefs.max_proof_tier = (ss_proof_tier_t)tier_u32;
	}
	APPLY_U32(min_rotation_interval_blocks);
	APPLY_BOOL(require_tier_b_rollover);
	APPLY_U32(min_state_replay_defense_window_blocks);
	APPLY_BOOL(auto_sign_on_validator_pass);
#undef APPLY_U64
#undef APPLY_U32
#undef APPLY_U16
#undef APPLY_BOOL

	if (ss_signing_prefs_persist() != 0)
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "Could not persist " SS_SIGNING_PREFS_FILE
			   " — prefs apply in memory but won't survive restart");
	else
		plugin_log(plugin_handle, LOG_INFORM,
			   "Updated " SS_SIGNING_PREFS_FILE);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_bool(js, "ok", true);
	return command_finished(cmd, js);
}


/* Forward decl: ss_audit_log is defined below ss_fresh_request_id, but the
 * peer-table helpers (which appear above the helper definition) call it. */
static void ss_audit_log(enum log_level lvl, const char *event,
                         const char *fmt, ...);

/* Forward decl for factory-funding-precheck handler (Phase 4). */
static struct command_result *json_factory_funding_precheck(
	struct command *cmd, const char *buf, const jsmntok_t *params);

/* ============================================================================
 * Wallet-db (read-only) helpers — Task #84.
 *
 * The wallet plugin (Node.js, apps/cln-plugin) is the canonical writer for
 * coordination state (iid_counter, factories, lsp_join_queue, outgoing_joins)
 * and crypto-state blobs (wallet_settings.factory_blob:<iid>:<kind>). The C
 * plugin opens wallet.db read-only at restart and loads everything via direct
 * sqlite3 reads. Runtime writes go via the existing wallet-* RPC dispatch.
 *
 * No more CLN datastore touches anywhere in the plugin.
 *
 * Path resolution mirrors apps/cln-plugin/source/superscalar-db.service.ts:
 *   1. $SUPERSCALAR_WALLET_DB_PATH (env override, also honored by Node plugin)
 *   2. $XDG_CONFIG_HOME/soupwallet/wallet.db
 *   3. $HOME/.config/soupwallet/wallet.db
 * Plus an optional plugin_option override `superscalar-wallet-db`.
 * ============================================================================ */

static char *ss_wallet_db_path_override = NULL;  /* set via plugin_option */

/* Lib task #80 / SF-LIB-MUSIG-PERSIST integration flag (default off).
 * When the lib ships factory_restore_sessions(), this gates whether
 * ss_load_factories attempts session restore (true) or falls through
 * to the interim mitigation that resets in-flight ceremonies to
 * FAILED + AWAITING_JOINS (false).
 *
 * Set this to true ONLY once the lib API is available AND verified
 * via regtest crash-recovery tests. See LIB_TEAM_REPLY_MUSIG_PERSISTENCE.md
 * for the contract and security invariants. */
static bool ss_enable_session_restore = false;


static char *ss_resolve_wallet_db_path(const tal_t *ctx) {
	/* Phase 5 refactor: prefer ss_plugin_db_path_override (the new
	 * superscalar-cln-db-path option). Existing legacy code paths
	 * (ss_open_wallet_db_ro and its callers) now read from the new
	 * file with zero call-site changes. The two back-compat fallbacks
	 * remain for nodes still using the old option name. */
	if (ss_plugin_db_path_override && ss_plugin_db_path_override[0])
		return tal_strdup(ctx, ss_plugin_db_path_override);
	if (ss_wallet_db_path_override && ss_wallet_db_path_override[0])
		return tal_strdup(ctx, ss_wallet_db_path_override);
	const char *env = getenv("SUPERSCALAR_WALLET_DB_PATH");
	if (env && env[0]) return tal_strdup(ctx, env);
	const char *xdg = getenv("XDG_CONFIG_HOME");
	const char *home = getenv("HOME");
	if (!home) {
		struct passwd *pw = getpwuid(getuid());
		if (pw && pw->pw_dir) home = pw->pw_dir;
	}
	/* No override + no env var: default to the consolidated DB
	 * filename (same as what ss_db_init opens). CLN runs plugins
	 * with cwd = lightning-dir/<network>, so this resolves to the
	 * per-node file. */
	(void)xdg; (void)home;  /* legacy fallbacks unused since Phase 5 */
	return tal_strdup(ctx, "superscalar-cln.db");
}

/* Open wallet.db read-only. Returns NULL on any failure (caller treats as
 * "no persisted state" — plugin starts empty). The DB is opened once per
 * load operation; we don't keep a long-lived handle to avoid stomping on
 * the wallet plugin's WAL writer in any way. */
static sqlite3 *ss_open_wallet_db_ro(const tal_t *ctx) {
	char *path = ss_resolve_wallet_db_path(ctx);
	sqlite3 *db = NULL;
	/* SQLITE_OPEN_READONLY | NOMUTEX: we hold the handle very briefly
	 * within a single load call, single-threaded. */
	int rc = sqlite3_open_v2(path, &db,
		SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL);
	if (rc != SQLITE_OK) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "wallet.db open ro failed: %s (path=%s)",
			   sqlite3_errstr(rc), path);
		if (db) sqlite3_close(db);
		return NULL;
	}
	/* Set a short busy_timeout so we don't block forever if the wallet
	 * plugin holds a write transaction. 250ms is generous for SQLite. */
	sqlite3_busy_timeout(db, 250);
	return db;
}

/* Open wallet.db, SELECT a single hex-encoded blob from wallet_settings,
 * decode to bytes (tal-allocated under `ctx`). Returns NULL on miss or
 * malformed hex. Closes the DB on return. Convenient for the per-blob
 * reads in ss_load_factories.
 *
 * Storage format note: the wallet plugin's wallet-set-setting RPC writes
 * `setting_value` as a JSON string literal — so the row's text includes
 * a leading and trailing double-quote that wrap the hex payload. We
 * strip them here before hex-decoding. */
static uint8_t *ss_wallet_db_load_blob_tal(const tal_t *ctx,
					   const char *setting_key,
					   size_t *out_len) {
	*out_len = 0;
	sqlite3 *db = ss_open_wallet_db_ro(ctx);
	if (!db) return NULL;
	sqlite3_stmt *st = NULL;
	const char *sql = "SELECT setting_value FROM wallet_settings "
			  "WHERE setting_key = ?";
	uint8_t *out = NULL;
	if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) == SQLITE_OK) {
		sqlite3_bind_text(st, 1, setting_key, -1, SQLITE_TRANSIENT);
		if (sqlite3_step(st) == SQLITE_ROW) {
			const unsigned char *raw = sqlite3_column_text(st, 0);
			if (raw) {
				const char *hex = (const char *)raw;
				size_t hlen = strlen(hex);
				/* Strip JSON-string wrapping quotes if present. */
				if (hlen >= 2 && hex[0] == '"'
				    && hex[hlen - 1] == '"') {
					hex++;
					hlen -= 2;
				}
				if (hlen % 2 == 0) {
					size_t blen = hlen / 2;
					out = tal_arr(ctx, uint8_t, blen);
					bool ok = true;
					for (size_t i = 0; i < blen && ok; i++) {
						unsigned int b;
						if (sscanf(hex + i*2,
							   "%02x", &b) != 1) {
							ok = false;
						} else {
							out[i] = (uint8_t)b;
						}
					}
					if (ok) {
						*out_len = blen;
					} else {
						out = NULL;
					}
				}
			}
		}
		sqlite3_finalize(st);
	}
	sqlite3_close(db);
	return out;
}

/* ============================================================================
 * Per-peer rate limit + slot cap tracking (hardening: DoS resistance)
 *
 * Goal: one hostile peer cannot exhaust the 16-slot global browse/join pools.
 *
 * Limits enforced per peer node_id:
 *   - Max SS_PEER_MAX_CONCURRENT outstanding slots (browse + join combined)
 *   - Max SS_PEER_RATE_LIMIT requests per SS_PEER_RATE_WINDOW_SECS
 *
 * Implementation: fixed-size table (no dynamic allocation). Entries are
 * recycled LRU-style when full. Trade-off: under sustained attack from
 * many distinct peers, the table is evicted in FIFO order; legitimate
 * peers may briefly bypass the cap. Acceptable for v1.
 * ============================================================================ */
/* ============================================================================
 * SuperScalar JSON-RPC error codes (Task #69).
 *
 * CLN uses errcode_t int; we allocate the 2200-2299 range for
 * plugin-specific codes so clients can switch on them instead of
 * regexing the message string. Codes are stable: do NOT renumber.
 *
 * Parameter-validation errors continue to use JSONRPC2_INVALID_PARAMS
 * (CLN-defined, -32602). The codes below are for post-parse semantic
 * failures (peer rate limited, slot pool exhausted, etc.).
 *
 * Wallet adoption: clients should map unrecognized codes to "unknown
 * server error" rather than failing — the code list will grow.
 * ============================================================================ */
#define SS_ERR_INTERNAL                  2200
/* Per-peer DoS protection */
#define SS_ERR_PEER_RATE_LIMIT           2210
#define SS_ERR_PEER_CONCURRENT_LIMIT     2211
#define SS_ERR_PEER_SOFT_BANNED          2212
#define SS_ERR_PEER_TABLE_FULL           2213
/* Slot pool exhaustion */
#define SS_ERR_SLOT_EXHAUSTED            2220
/* Peer connectivity */
#define SS_ERR_PEER_NOT_CONNECTED        2230
#define SS_ERR_PEER_NOT_BLIP56           2231
/* Factory state */
#define SS_ERR_UNKNOWN_FACTORY           2240
#define SS_ERR_FACTORY_QUEUE_FULL        2241
#define SS_ERR_DUPLICATE_JOIN            2242
#define SS_ERR_OUTGOING_JOINS_FULL       2243
#define SS_ERR_INSTANCE_ID_INVALID       2244
/* Wire/timing */
#define SS_ERR_REQUEST_TIMEOUT           2250
/* Funding (Phase 4) */
#define SS_ERR_INSUFFICIENT_FUNDS        2270

#define SS_PEER_TABLE_SIZE          64
/* Bug B: cap how many times the LSP will re-send FACTORY_PROPOSE
 * to a single non-responsive client across reconnects. After this
 * many attempts, the LSP stops retrying and waits for the client
 * to make the first move (or for the factory to be reaped). */
#define SS_MAX_PROPOSE_RETRIES 3

#define SS_PEER_MAX_CONCURRENT       2
#define SS_PEER_RATE_LIMIT          10
#define SS_PEER_RATE_WINDOW_SECS    60
/* Soft-ban (#71): N fails within window triggers M-second ban. */
#define SS_PEER_MAX_FAILS            5
#define SS_PEER_FAIL_WINDOW_SECS    60
#define SS_PEER_SOFT_BAN_SECS      300

struct ss_peer_usage {
	uint8_t node_id[33];
	bool in_use;
	int concurrent_slots;       /* current outstanding browse + join slots */
	time_t window_start;        /* start of current rate-limit window */
	int requests_in_window;     /* requests counted in current window */
	time_t last_seen;           /* LRU tracking for eviction */
	/* Soft-ban (#71): fails counted within fail_window_start..+SECS;
	 * crossing SS_PEER_MAX_FAILS sets ban_until = now + SOFT_BAN_SECS.
	 * 0 ban_until means not banned. */
	int fail_count;
	time_t fail_window_start;
	time_t ban_until;
};

static struct ss_peer_usage ss_peer_table[SS_PEER_TABLE_SIZE];

/* Find or allocate a peer-usage entry by node_id. Returns NULL only if
 * the entry can't be allocated (shouldn't happen with LRU eviction). */
static struct ss_peer_usage *ss_peer_usage_get(const uint8_t node_id[33])
{
	time_t now = time(NULL);

	/* Pass 1: existing entry */
	for (int i = 0; i < SS_PEER_TABLE_SIZE; i++) {
		if (ss_peer_table[i].in_use &&
		    memcmp(ss_peer_table[i].node_id, node_id, 33) == 0) {
			ss_peer_table[i].last_seen = now;
			return &ss_peer_table[i];
		}
	}

	/* Pass 2: find a free slot */
	for (int i = 0; i < SS_PEER_TABLE_SIZE; i++) {
		if (!ss_peer_table[i].in_use) {
			memcpy(ss_peer_table[i].node_id, node_id, 33);
			ss_peer_table[i].in_use = true;
			ss_peer_table[i].concurrent_slots = 0;
			ss_peer_table[i].window_start = now;
			ss_peer_table[i].requests_in_window = 0;
			ss_peer_table[i].last_seen = now;
			ss_peer_table[i].fail_count = 0;
			ss_peer_table[i].fail_window_start = now;
			ss_peer_table[i].ban_until = 0;
			return &ss_peer_table[i];
		}
	}

	/* Pass 3: LRU eviction. Find the oldest in_use entry whose
	 * concurrent_slots == 0 (don't evict peers with live slots). */
	int oldest_idx = -1;
	time_t oldest_seen = now;
	for (int i = 0; i < SS_PEER_TABLE_SIZE; i++) {
		if (ss_peer_table[i].concurrent_slots > 0) continue;
		if (ss_peer_table[i].last_seen < oldest_seen) {
			oldest_seen = ss_peer_table[i].last_seen;
			oldest_idx = i;
		}
	}
	if (oldest_idx >= 0) {
		memcpy(ss_peer_table[oldest_idx].node_id, node_id, 33);
		ss_peer_table[oldest_idx].in_use = true;
		ss_peer_table[oldest_idx].concurrent_slots = 0;
		ss_peer_table[oldest_idx].window_start = now;
		ss_peer_table[oldest_idx].requests_in_window = 0;
		ss_peer_table[oldest_idx].last_seen = now;
		ss_peer_table[oldest_idx].fail_count = 0;
		ss_peer_table[oldest_idx].fail_window_start = now;
		ss_peer_table[oldest_idx].ban_until = 0;
		return &ss_peer_table[oldest_idx];
	}

	/* Table fully saturated with peers holding live slots — extreme
	 * pathological case. Return NULL; caller will reject. */
	return NULL;
}

/* Check if peer can take a new slot. Returns NULL on OK, or a static
 * error reason string. Does NOT mutate state — caller commits on success
 * via ss_peer_usage_commit_slot. */
static const char *ss_peer_check_limits(const uint8_t node_id[33])
{
	struct ss_peer_usage *u = ss_peer_usage_get(node_id);
	if (!u)
		return "internal: per-peer tracking table saturated";

	time_t now = time(NULL);
	/* Reset window if expired */
	if (now - u->window_start >= SS_PEER_RATE_WINDOW_SECS) {
		u->window_start = now;
		u->requests_in_window = 0;
	}

	/* Soft-ban check (#71). Returns the static "banned" string while
	 * within ban_until; auto-clears when window expires. */
	if (u->ban_until > 0) {
		if (now < u->ban_until)
			return "peer is soft-banned (too many recent failures)";
		u->ban_until = 0;
		u->fail_count = 0;
		u->fail_window_start = now;
	}

	if (u->concurrent_slots >= SS_PEER_MAX_CONCURRENT)
		return "peer has too many concurrent requests (max 2)";
	if (u->requests_in_window >= SS_PEER_RATE_LIMIT)
		return "peer exceeded rate limit (max 10 requests/minute)";

	return NULL;
}

/* Record a soft-ban-eligible failure for the given peer. Resets the
 * fail-window if it has elapsed; increments fail_count; triggers a
 * ban if count >= SS_PEER_MAX_FAILS. Idempotent if peer table is
 * saturated (no-op). */
static void ss_peer_record_fail(const uint8_t node_id[33])
{
	struct ss_peer_usage *u = ss_peer_usage_get(node_id);
	if (!u) return;
	time_t now = time(NULL);
	if (now - u->fail_window_start >= SS_PEER_FAIL_WINDOW_SECS) {
		u->fail_window_start = now;
		u->fail_count = 0;
	}
	u->fail_count++;
	if (u->fail_count >= SS_PEER_MAX_FAILS && u->ban_until == 0) {
		u->ban_until = now + SS_PEER_SOFT_BAN_SECS;
		ss_audit_log(LOG_UNUSUAL, "peer_soft_banned",
			     "\"fail_count\":%d,\"ban_secs\":%d",
			     u->fail_count, SS_PEER_SOFT_BAN_SECS);
	}
}

/* Commit a slot allocation. Caller must have already called check_limits
 * and gotten NULL back. */
static void ss_peer_usage_commit_slot(const uint8_t node_id[33])
{
	struct ss_peer_usage *u = ss_peer_usage_get(node_id);
	if (!u) return;
	u->concurrent_slots++;
	u->requests_in_window++;
}

/* Release a slot when its RPC completes (success, failure, or timeout). */
static void ss_peer_usage_release_slot(const uint8_t node_id[33])
{
	struct ss_peer_usage *u = ss_peer_usage_get(node_id);
	if (!u) return;
	if (u->concurrent_slots > 0)
		u->concurrent_slots--;
}

/* Generate a fresh 64-bit request_id from /dev/urandom (CSPRNG). Birthday
 * collision at 2^32 requests is ~10^-14 — safe at any realistic scale.
 *
 * Why not a counter? Counters reset on plugin restart. An old response
 * with request_id=42 arriving after restart could match a fresh request
 * slot that also got request_id=42 → wrong data returned to caller.
 *
 * Falls back to time(NULL) ^ rand() if /dev/urandom unavailable (tests
 * only; production CLN nodes always have /dev/urandom).
 */
static uint64_t ss_fresh_request_id(void)
{
	uint64_t id = 0;
	FILE *urandom = fopen("/dev/urandom", "rb");
	if (urandom) {
		if (fread(&id, sizeof(id), 1, urandom) != 1)
			id = 0;
		fclose(urandom);
	}
	if (id == 0) {
		/* Fallback: time-mixed PRNG. Not collision-safe but better
		 * than zero. Should never hit this path on a real CLN node. */
		id = ((uint64_t)time(NULL) << 32) | (uint64_t)rand();
	}
	/* Avoid 0 (sentinel for "slot free" in slot tables). */
	return id ? id : 1;
}

/* Structured audit log helper. Emits a single-line JSON object as the
 * message body of an ordinary plugin_log call:
 *
 *   {"audit":"<event>",<caller json fragment>}
 *
 * Downstream log ingest (loki/elastic/etc.) can recognize lines whose
 * body parses as JSON with an "audit" key and route them to a
 * dedicated audit index. Free-form plugin_log calls are preserved for
 * developer diagnostics; this helper is reserved for events relevant
 * to ops/forensics (slot exhaustion, rate-limit rejections, join
 * lifecycle transitions, timeouts).
 *
 * Caller writes the inner k:v fragment. All migration in this codebase
 * is us-writes-both, so injection from untrusted strings is not a
 * concern; if a future caller needs to embed peer-controlled data, it
 * must escape JSON quotes first. */
static void ss_audit_log(enum log_level lvl, const char *event,
                         const char *fmt, ...)
{
	char body[1024];
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(body, sizeof(body), fmt, ap);
	va_end(ap);
	if (n < 0) n = 0;
	if ((size_t)n >= sizeof(body)) n = sizeof(body) - 1;
	body[n] = '\0';
	plugin_log(plugin_handle, lvl,
	           "{\"audit\":\"%s\",%s}", event, body);
}


/* Kept for backward compatibility — will be deleted once all callers
 * use ss_fresh_request_id. Currently unused after this commit. */
static uint64_t ss_browse_next_request_id = 1;

static int ss_browse_alloc_slot(void)
{
	time_t now = time(NULL);
	int free_slot = -1;
	for (int i = 0; i < SS_BROWSE_MAX_PENDING; i++) {
		if (ss_browse_pending[i].request_id == 0) {
			if (free_slot < 0) free_slot = i;
			continue;
		}
		if (now > ss_browse_pending[i].deadline) {
			struct command *stuck = ss_browse_pending[i].cmd;
			uint64_t stuck_id = ss_browse_pending[i].request_id;
			ss_browse_pending[i].request_id = 0;
			ss_browse_pending[i].cmd = NULL;
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "browse: timing out stuck request_id=%llu",
				   (unsigned long long)stuck_id);
			ss_audit_log(LOG_UNUSUAL, "request_timeout",
				     "\"rpc\":\"factory-browse-host\","
				     "\"request_id\":%llu",
				     (unsigned long long)stuck_id);
			if (stuck) {
				struct command_result *_cfail = command_fail(stuck, LIGHTNINGD,
					"factory-browse-host: timeout waiting for peer response (req_id=%llu)",
					(unsigned long long)stuck_id);
				(void)_cfail;
			}
			if (free_slot < 0) free_slot = i;
		}
	}
	return free_slot;
}

static int ss_browse_find_slot(uint64_t request_id)
{
	for (int i = 0; i < SS_BROWSE_MAX_PENDING; i++) {
		if (ss_browse_pending[i].request_id == request_id) return i;
	}
	return -1;
}

/* ============================================================================
 * Phase 3: client-side join-request pending tracking. Mirrors the browse
 * slot pattern — a client RPC factory-join-request returns
 * command_still_pending while waiting for the LSP's JOIN_RESPONSE; this
 * table maps request_id -> cmd so the dispatch handler can resolve the
 * right RPC when 0x0143 arrives.
 *
 * Memory-only: persistence lives in ss_state.outgoing_joins. This slot
 * table is just RPC-correlation state.
 * ============================================================================ */
#define SS_JOIN_MAX_PENDING		16
#define SS_JOIN_TIMEOUT_SECS		30
/* Runtime-mutable copy set by --superscalar-join-timeout-secs.
 * See note on ss_browse_timeout_secs. */
static u32 ss_join_timeout_secs = SS_JOIN_TIMEOUT_SECS;
struct ss_join_pending_slot {
	uint64_t request_id;
	struct command *cmd;
	time_t deadline;
	uint8_t peer_id[33];        /* for per-peer cap release */
};
static struct ss_join_pending_slot ss_join_pending[SS_JOIN_MAX_PENDING];
static uint64_t ss_join_next_request_id = 1;

static int ss_join_alloc_slot(void)
{
	time_t now = time(NULL);
	int free_slot = -1;
	for (int i = 0; i < SS_JOIN_MAX_PENDING; i++) {
		if (ss_join_pending[i].request_id == 0) {
			if (free_slot < 0) free_slot = i;
			continue;
		}
		if (now > ss_join_pending[i].deadline) {
			struct command *stuck = ss_join_pending[i].cmd;
			uint64_t stuck_id = ss_join_pending[i].request_id;
			ss_join_pending[i].request_id = 0;
			ss_join_pending[i].cmd = NULL;
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "join: timing out stuck request_id=%llu",
				   (unsigned long long)stuck_id);
			ss_audit_log(LOG_UNUSUAL, "request_timeout",
				     "\"rpc\":\"factory-join-request\","
				     "\"request_id\":%llu",
				     (unsigned long long)stuck_id);
			if (stuck) {
				struct command_result *_cf = command_fail(stuck,
					LIGHTNINGD,
					"factory-join-request: timeout waiting for LSP "
					"response (req_id=%llu)",
					(unsigned long long)stuck_id);
				(void)_cf;
			}
			if (free_slot < 0) free_slot = i;
		}
	}
	return free_slot;
}

static int ss_join_find_slot(uint64_t request_id)
{
	for (int i = 0; i < SS_JOIN_MAX_PENDING; i++) {
		if (ss_join_pending[i].request_id == request_id) return i;
	}
	return -1;
}

/* Phase 3: join reaper logic. Called from ss_browse_reap_tick (combined
 * timer) — registering it as its own global_timer alongside the browse
 * reaper crashed the plugin after ~13s. Reason: libplugin has a problem
 * with two concurrent global_timer registrations on the same interval. */
static void ss_join_reap_scan(void)
{
	time_t now = time(NULL);
	for (int i = 0; i < SS_JOIN_MAX_PENDING; i++) {
		if (ss_join_pending[i].request_id == 0) continue;
		if (now <= ss_join_pending[i].deadline) continue;
		struct command *stuck = ss_join_pending[i].cmd;
		uint64_t stuck_id = ss_join_pending[i].request_id;
		ss_peer_usage_release_slot(ss_join_pending[i].peer_id);
		ss_join_pending[i].request_id = 0;
		ss_join_pending[i].cmd = NULL;
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "join: reaper timing out stuck req_id=%llu",
			   (unsigned long long)stuck_id);
		if (stuck) {
			struct command_result *_cf = command_fail(stuck,
				LIGHTNINGD,
				"factory-join-request: timeout waiting for "
				"LSP response (req_id=%llu)",
				(unsigned long long)stuck_id);
			(void)_cf;
		}
	}
}

/* Legacy entry point for forward-decl compatibility — no longer registered
 * as its own timer. Just calls the scan + re-registers itself (defensive,
 * but unreachable in normal init flow). */
static struct command_result *ss_join_reap_tick(struct command *timer_cmd,
						 void *unused)
{
	(void)unused;
	ss_join_reap_scan();
	notleak(global_timer(plugin_handle, time_from_sec(5),
			     ss_join_reap_tick, NULL));
	return timer_complete(timer_cmd);
}

/* Bug B fix: active slot reaper. Registered as a global_timer at plugin
 * init, fires every 5s. Scans the pending-slot table for entries whose
 * deadline has passed and fails their associated RPC commands with a
 * timeout error. Without this active tick, the only reaper is the
 * lazy-reap in ss_browse_alloc_slot — so a single stuck browse RPC
 * stays stuck forever (until another browse runs). */
static void ss_lsp_sig_queue_deadline_tick(struct command *cmd)
{
	(void)cmd;
	uint32_t now = ss_state.current_blockheight;
	bool dirty = false;
	for (int i = 0; i < SS_LSP_SIG_QUEUE_SIZE; i++) {
		struct ss_lsp_sig_queue_entry *e = &ss_lsp_sig_queue[i];
		if (!e->used) continue;
		if (e->state != SS_SIGQUEUE_AWAITING_YOUR_SIGNATURE) continue;
		if (e->deadline_block == 0) continue;
		if (now <= e->deadline_block) continue;
		plugin_log(plugin_handle, LOG_INFORM,
			   "LSP sig queue: AWAITING -> MISSED for factory "
			   "%02x%02x%02x%02x (deadline=%u, now=%u)",
			   e->factory_instance_id[0], e->factory_instance_id[1],
			   e->factory_instance_id[2], e->factory_instance_id[3],
			   e->deadline_block, now);
		e->state = SS_SIGQUEUE_MISSED;
		if (e->proposal_blob) {
			free(e->proposal_blob);
			e->proposal_blob = NULL;
			e->proposal_blob_len = 0;
		}
		dirty = true;
	}
	if (dirty) ss_lsp_sig_queue_persist();
}

static struct command_result *ss_browse_reap_tick(struct command *timer_cmd,
						  void *unused)
{
	/* Phase D follow-up: deadline transitions for the LSP signature
	 * queue, piggybacked on the same 5s tick. */
	ss_lsp_sig_queue_deadline_tick(timer_cmd);

	/* Phase 3: also reap join slots in this same timer tick. Avoids
	 * registering two separate global_timer callbacks which crashes
	 * the plugin after ~13s. */
	ss_join_reap_scan();

	time_t now = time(NULL);
	for (int i = 0; i < SS_BROWSE_MAX_PENDING; i++) {
		if (ss_browse_pending[i].request_id == 0) continue;
		if (now <= ss_browse_pending[i].deadline) continue;
		struct command *stuck = ss_browse_pending[i].cmd;
		uint64_t stuck_id = ss_browse_pending[i].request_id;
		ss_peer_usage_release_slot(ss_browse_pending[i].peer_id);
		ss_browse_pending[i].request_id = 0;
		ss_browse_pending[i].cmd = NULL;
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "browse: reaper timing out stuck req_id=%llu",
			   (unsigned long long)stuck_id);
		if (stuck) {
			struct command_result *_cf = command_fail(stuck,
				LIGHTNINGD,
				"factory-browse-host: timeout waiting for "
				"peer response (req_id=%llu)",
				(unsigned long long)stuck_id);
			(void)_cf;
		}
	}
	notleak(global_timer(plugin_handle, time_from_sec(5),
			     ss_browse_reap_tick, NULL));
	return timer_complete(timer_cmd);
}

/* --------------------------------------------------------------------- *
 * BIP-141 parser helpers (Phase 2b)
 *
 * Used for two purposes:
 *   (a) Compute segwit txid (double-SHA256 of non-witness serialization)
 *       of a signed TX we hold in memory — needed to precompute
 *       dist_signed_txid at coop-signing time.
 *   (b) Extract the first witness-stack item of the first input, which
 *       for a key-path P2TR spend is the 64-byte Schnorr signature —
 *       used to snapshot kickoff witnesses at rotation time, and to
 *       match a spending TX's witness against stored per-epoch sigs
 *       during classification.
 *
 * BIP-141 serialization (segwit):
 *   version (4 LE)
 *   [marker 0x00][flag 0x01]            if witness present
 *   input_count (varint)
 *   inputs[] = prevout (32+4) + scriptSig (varint+bytes) + sequence (4)
 *   output_count (varint)
 *   outputs[] = value (8 LE) + scriptPubKey (varint+bytes)
 *   [witness[] = for each input: stack_count (varint) + stack items
 *     (each varint+bytes)]                 if witness present
 *   nLockTime (4 LE)
 *
 * Non-witness (txid) serialization omits the marker/flag/witness.
 * --------------------------------------------------------------------- */

/* Read a BIP-141 varint from p[0..rem]. On success advances p, decrements
 * rem, sets *out. Returns true on success, false on overrun. */
static bool ss_read_varint(const uint8_t **p, size_t *rem, uint64_t *out)
{
	if (*rem < 1) return false;
	uint8_t first = **p; (*p)++; (*rem)--;
	if (first < 0xfd) { *out = first; return true; }
	if (first == 0xfd) {
		if (*rem < 2) return false;
		*out = (uint64_t)(*p)[0] | ((uint64_t)(*p)[1] << 8);
		*p += 2; *rem -= 2;
		return true;
	}
	if (first == 0xfe) {
		if (*rem < 4) return false;
		*out = (uint64_t)(*p)[0] | ((uint64_t)(*p)[1] << 8)
		     | ((uint64_t)(*p)[2] << 16) | ((uint64_t)(*p)[3] << 24);
		*p += 4; *rem -= 4;
		return true;
	}
	/* 0xff: 8-byte little-endian */
	if (*rem < 8) return false;
	*out = 0;
	for (int i = 0; i < 8; i++) *out |= (uint64_t)(*p)[i] << (i*8);
	*p += 8; *rem -= 8;
	return true;
}

/* Write a BIP-141 varint; returns number of bytes written (1, 3, 5, or 9). */
static size_t ss_write_varint(uint8_t *out, uint64_t v)
{
	if (v < 0xfd) { out[0] = (uint8_t)v; return 1; }
	if (v <= 0xffff) {
		out[0] = 0xfd; out[1] = v & 0xff; out[2] = (v >> 8) & 0xff;
		return 3;
	}
	if (v <= 0xffffffffULL) {
		out[0] = 0xfe;
		for (int i = 0; i < 4; i++) out[1+i] = (v >> (i*8)) & 0xff;
		return 5;
	}
	out[0] = 0xff;
	for (int i = 0; i < 8; i++) out[1+i] = (v >> (i*8)) & 0xff;
	return 9;
}

/* Parse a segwit TX, output both the segwit txid (double-SHA256 of the
 * non-witness serialization, internal little-endian byte order) AND the
 * first witness-stack item of the first input.
 *
 * out_txid[32]: required, always populated on success.
 * out_witness_sig: optional (NULL to skip); must be at least 64 bytes if
 *                  provided. Populated only when has_witness && stack item
 *                  is exactly 64 bytes (BIP-340 Schnorr sig). For
 *                  non-witness TXs or non-64-byte stack items, zeroed.
 * out_has_witness: optional; set true if the TX had a witness marker.
 *
 * Returns true on success, false on malformed input.
 */
static bool ss_parse_tx(const uint8_t *tx, size_t tx_len,
			uint8_t out_txid[32],
			uint8_t *out_witness_sig /* 64 bytes, NULLable */,
			bool *out_has_witness /* NULLable */)
{
	if (tx_len < 10) return false;
	const uint8_t *p = tx;
	size_t rem = tx_len;

	/* Build non-witness serialization into scratch buffer. Max ~= tx_len. */
	uint8_t *nw = malloc(tx_len);
	if (!nw) return false;
	size_t nw_len = 0;

	/* version */
	memcpy(nw + nw_len, p, 4); nw_len += 4; p += 4; rem -= 4;

	/* Detect witness marker/flag. */
	bool has_witness = false;
	if (rem >= 2 && p[0] == 0x00 && p[1] == 0x01) {
		has_witness = true;
		p += 2; rem -= 2;
	}

	/* input_count */
	uint64_t n_in;
	if (!ss_read_varint(&p, &rem, &n_in)) { free(nw); return false; }
	if (n_in > 1000) { free(nw); return false; }
	size_t n_in_w = ss_write_varint(nw + nw_len, n_in);
	nw_len += n_in_w;

	/* Track per-input scriptSig region for witness stack ordering later. */
	for (uint64_t i = 0; i < n_in; i++) {
		if (rem < 36) { free(nw); return false; }
		memcpy(nw + nw_len, p, 36); nw_len += 36; p += 36; rem -= 36;

		uint64_t script_len;
		const uint8_t *script_len_start = p;
		if (!ss_read_varint(&p, &rem, &script_len)) { free(nw); return false; }
		size_t vi_len = (size_t)(p - script_len_start);
		memcpy(nw + nw_len, script_len_start, vi_len);
		nw_len += vi_len;

		if (rem < script_len) { free(nw); return false; }
		memcpy(nw + nw_len, p, script_len); nw_len += script_len;
		p += script_len; rem -= script_len;

		if (rem < 4) { free(nw); return false; }
		memcpy(nw + nw_len, p, 4); nw_len += 4;
		p += 4; rem -= 4;
	}

	/* output_count */
	uint64_t n_out;
	const uint8_t *no_start = p;
	if (!ss_read_varint(&p, &rem, &n_out)) { free(nw); return false; }
	if (n_out > 1000) { free(nw); return false; }
	size_t no_vi_len = (size_t)(p - no_start);
	memcpy(nw + nw_len, no_start, no_vi_len); nw_len += no_vi_len;

	for (uint64_t i = 0; i < n_out; i++) {
		if (rem < 8) { free(nw); return false; }
		memcpy(nw + nw_len, p, 8); nw_len += 8; p += 8; rem -= 8;

		uint64_t spk_len;
		const uint8_t *spk_len_start = p;
		if (!ss_read_varint(&p, &rem, &spk_len)) { free(nw); return false; }
		size_t vi_len = (size_t)(p - spk_len_start);
		memcpy(nw + nw_len, spk_len_start, vi_len);
		nw_len += vi_len;

		if (rem < spk_len) { free(nw); return false; }
		memcpy(nw + nw_len, p, spk_len); nw_len += spk_len;
		p += spk_len; rem -= spk_len;
	}

	/* witness section, if present. Extract first stack item of first
	 * input, if requested and its length is 64 bytes. */
	bool got_witness_sig = false;
	if (has_witness) {
		/* For each input, parse its witness stack. We only keep the
		 * first item of the first input — rest is skipped. */
		for (uint64_t i = 0; i < n_in; i++) {
			uint64_t stack_count;
			if (!ss_read_varint(&p, &rem, &stack_count)) { free(nw); return false; }
			for (uint64_t j = 0; j < stack_count; j++) {
				uint64_t item_len;
				if (!ss_read_varint(&p, &rem, &item_len)) { free(nw); return false; }
				if (rem < item_len) { free(nw); return false; }
				if (i == 0 && j == 0 && item_len == 64
				    && out_witness_sig) {
					memcpy(out_witness_sig, p, 64);
					got_witness_sig = true;
				}
				p += item_len; rem -= item_len;
			}
		}
	}

	/* nLockTime */
	if (rem < 4) { free(nw); return false; }
	memcpy(nw + nw_len, p, 4); nw_len += 4;
	p += 4; rem -= 4;

	/* Compute double-SHA256 over the non-witness serialization. */
	struct sha256 h1, h2;
	sha256(&h1, nw, nw_len);
	sha256(&h2, &h1, sizeof(h1));
	memcpy(out_txid, &h2, 32);
	free(nw);

	if (out_has_witness) *out_has_witness = has_witness;
	if (out_witness_sig && !got_witness_sig) memset(out_witness_sig, 0, 64);
	return true;
}

/* Phase 2b helpers.
 *
 * ss_compute_dist_signed_txid: populate fi->dist_signed_txid from the
 * currently-set fi->dist_signed_tx bytes. Called once when the coop dist
 * TX is signed/loaded. Idempotent; re-computing on an unchanged TX
 * yields the same txid.
 */
static void ss_compute_dist_signed_txid(factory_instance_t *fi)
{
	if (!fi->dist_signed_tx || fi->dist_signed_tx_len == 0) {
		memset(fi->dist_signed_txid, 0, 32);
		return;
	}
	if (!ss_parse_tx(fi->dist_signed_tx, fi->dist_signed_tx_len,
			 fi->dist_signed_txid, NULL, NULL)) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "Failed to compute dist_signed_txid from %zu-byte "
			   "dist TX — classifier won't detect coop close for "
			   "this factory.",
			   fi->dist_signed_tx_len);
		memset(fi->dist_signed_txid, 0, 32);
	}
}

/* Snapshot the current epoch's kickoff witness sig before rotating. Call
 * right before any line that advances fi->epoch past its current value.
 *
 * The snapshot reads nodes[0].signed_tx from lib_factory, parses out the
 * first input's first witness stack item, and appends (epoch, sig) to
 * fi->history_kickoff_sigs. Duplicates are skipped (if same epoch was
 * already captured).
 *
 * On serialization failure (TX not signed yet, malformed bytes) we skip
 * capture and log — the classifier handles missing-epoch-sig gracefully
 * (falls back to CLOSED_BY_COUNTERPARTY without breach label). */
static void ss_snapshot_current_epoch_kickoff_sig(factory_instance_t *fi)
{
	factory_t *f = (factory_t *)fi->lib_factory;
	if (!f || f->n_nodes == 0) return;
	tx_buf_t *stx = &f->nodes[0].signed_tx;
	if (!stx->data || stx->len == 0) return;

	/* Dedup: don't double-capture same epoch. */
	for (size_t i = 0; i < fi->n_history_kickoff_sigs; i++)
		if (fi->history_kickoff_epochs[i] == fi->epoch) return;

	if (fi->n_history_kickoff_sigs >= MAX_HISTORY_SIGS) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "Kickoff-sig history full (%zu slots); skipping "
			   "capture for epoch %u. Factory has rotated more "
			   "than MAX_HISTORY_SIGS times, which is above the "
			   "max_epochs configured for the default factory "
			   "shape — increase MAX_HISTORY_SIGS if you hit this.",
			   fi->n_history_kickoff_sigs, fi->epoch);
		return;
	}

	uint8_t txid_unused[32];
	uint8_t sig[64];
	bool has_witness = false;
	if (!ss_parse_tx(stx->data, stx->len, txid_unused, sig, &has_witness)) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "Failed to parse kickoff TX at epoch %u for sig "
			   "snapshot; breach classification for this epoch "
			   "will be unavailable.",
			   fi->epoch);
		return;
	}
	if (!has_witness) return;

	/* Check sig isn't all-zero (extraction fell through to "not 64 bytes"). */
	bool any = false;
	for (int i = 0; i < 64; i++) if (sig[i]) { any = true; break; }
	if (!any) return;

	size_t slot = fi->n_history_kickoff_sigs;
	fi->history_kickoff_epochs[slot] = fi->epoch;
	memcpy(fi->history_kickoff_sigs[slot], sig, 64);

	/* Phase 3b: also snapshot the state-tree-root TXID for this
	 * epoch. nodes[1] is the state TX that spends the kickoff's
	 * output; its txid is epoch-specific (different revocation
	 * commitments per epoch produce different output scripts → different
	 * txid). Stored alongside the kickoff sig under the same slot so
	 * the downstream classifier can match by either signal. */
	if (f->n_nodes > 1) {
		memcpy(fi->history_state_root_txids[slot],
		       f->nodes[1].txid, 32);
	} else {
		memset(fi->history_state_root_txids[slot], 0, 32);
	}

	fi->n_history_kickoff_sigs++;

	plugin_log(plugin_handle, LOG_DBG,
		   "Captured kickoff witness sig + state-root txid for epoch %u "
		   "(history slot %zu)",
		   fi->epoch, slot);
}

/* Derive a deterministic seckey from instance_id + participant index.
 * When HSM-derived master key is available, uses HMAC-SHA256 for
 * proper key derivation. Falls back to demo XOR otherwise.
 * NOTE: Only our OWN seckey uses the HSM path. Other participants'
 * pubkeys come from their actual node keys exchanged during setup. */
static void derive_factory_seckey(unsigned char seckey[32],
				  const uint8_t instance_id[32],
				  int participant_idx)
{
	if (ss_state.has_master_key) {
		/* HMAC-SHA256(master_key, instance_id || idx) */
		unsigned char hmac_input[34];
		memcpy(hmac_input, instance_id, 32);
		hmac_input[32] = (uint8_t)(participant_idx & 0xFF);
		hmac_input[33] = (uint8_t)((participant_idx >> 8) & 0xFF);

		/* Use secp256k1's nonce_function_rfc6979 as HMAC proxy:
		 * We XOR master_key with input through SHA256 for now.
		 * A proper HMAC would use openssl/libsodium. */
		struct sha256 hash;
		struct sha256_ctx sctx;
		sha256_init(&sctx);
		sha256_update(&sctx, ss_state.factory_master_key, 32);
		sha256_update(&sctx, hmac_input, sizeof(hmac_input));
		sha256_done(&sctx, &hash);
		memcpy(seckey, hash.u.u8, 32);
	} else {
		/* Demo fallback: XOR instance_id with participant index */
		memcpy(seckey, instance_id, 32);
		seckey[0] ^= (uint8_t)(participant_idx & 0xFF);
		seckey[1] ^= (uint8_t)((participant_idx >> 8) & 0xFF);
	}
	/* Ensure valid seckey (nonzero, well below curve order) */
	if (seckey[0] == 0) seckey[0] = 0x01;
}

/* Derive a placeholder seckey for building tree topology only.
 * NOT used for signing — only to get valid pubkeys for tree construction
 * before real pubkeys are collected from participants. */
static void derive_placeholder_seckey(unsigned char seckey[32],
				      const uint8_t instance_id[32],
				      int participant_idx)
{
	/* Simple deterministic XOR — same result on all nodes */
	memcpy(seckey, instance_id, 32);
	seckey[0] ^= (uint8_t)(participant_idx & 0xFF);
	seckey[1] ^= (uint8_t)((participant_idx >> 8) & 0xFF);
	seckey[2] ^= 0x77; /* extra differentiation from derive_factory_seckey */
	if (seckey[0] == 0) seckey[0] = 0x01;
}

/* Gap 8: derive a deterministic instance_id from the HSM master key.
 *
 *   iid = SHA256(master_key || "ss-iid-v1" || block_le4 || counter_le4)
 *
 * Matches the pseudo-HMAC shape of derive_factory_seckey so all
 * HSM-keyed derivations look alike. The counter is per-plugin-instance,
 * incremented on every factory-create, persisted to the datastore. On
 * datastore loss but HSM intact, operator recovers by enumerating
 * counter 0..N for plausible block heights and matching against on-chain
 * funding addresses. Two factories created in the same block get
 * different iids because the counter ticks every call. */
static void derive_instance_id_from_hsm(uint8_t iid_out[32],
					uint32_t creation_block,
					uint32_t counter)
{
	struct sha256 hash;
	struct sha256_ctx sctx;
	sha256_init(&sctx);
	sha256_update(&sctx, ss_state.factory_master_key, 32);
	static const char TAG[] = "ss-iid-v1";
	sha256_update(&sctx, TAG, sizeof(TAG) - 1);
	uint8_t block_le[4];
	block_le[0] = creation_block & 0xFF;
	block_le[1] = (creation_block >> 8) & 0xFF;
	block_le[2] = (creation_block >> 16) & 0xFF;
	block_le[3] = (creation_block >> 24) & 0xFF;
	sha256_update(&sctx, block_le, 4);
	uint8_t ctr_le[4];
	ctr_le[0] = counter & 0xFF;
	ctr_le[1] = (counter >> 8) & 0xFF;
	ctr_le[2] = (counter >> 16) & 0xFF;
	ctr_le[3] = (counter >> 24) & 0xFF;
	sha256_update(&sctx, ctr_le, 4);
	sha256_done(&sctx, &hash);
	memcpy(iid_out, hash.u.u8, 32);
}

/* Derive N L-stock revocation secrets deterministically from the HSM master
 * key and instance_id. Previously used /dev/urandom which made recovery
 * impossible after datastore loss — secrets were never persisted.
 *
 * Construction: secret[i] = SHA256(master_key || "ss-l-stock-v1" || iid || i_le4).
 * This is a straightforward HKDF-style expansion. Same security model as
 * before: the LSP holds all secrets; reveals secret[epoch-1] to the client
 * during rotation so the client can burn the old L-stock if the LSP cheats.
 *
 * Output: fills `secrets_out[n_epochs][32]` with derived secrets.
 * Callers must have ss_state.has_master_key == true. */
static void derive_l_stock_secrets(unsigned char secrets_out[][32],
				   size_t n_epochs,
				   const uint8_t instance_id[32])
{
	static const char INFO[] = "ss-l-stock-v1";
	for (size_t i = 0; i < n_epochs; i++) {
		struct sha256 hash;
		struct sha256_ctx sctx;
		sha256_init(&sctx);
		sha256_update(&sctx, ss_state.factory_master_key, 32);
		sha256_update(&sctx, INFO, sizeof(INFO) - 1);
		sha256_update(&sctx, instance_id, 32);
		uint8_t ibuf[4];
		ibuf[0] = (uint8_t)(i & 0xFF);
		ibuf[1] = (uint8_t)((i >> 8) & 0xFF);
		ibuf[2] = (uint8_t)((i >> 16) & 0xFF);
		ibuf[3] = (uint8_t)((i >> 24) & 0xFF);
		sha256_update(&sctx, ibuf, 4);
		sha256_done(&sctx, &hash);
		memcpy(secrets_out[i], hash.u.u8, 32);
		/* Avoid the vanishingly unlikely zero/curve-order cases by
		 * never producing a zero first byte. Revocation secrets are
		 * just hash preimages — strict validity not required, but
		 * nonzero is cheap insurance. */
		if (secrets_out[i][0] == 0) secrets_out[i][0] = 0x01;
	}
}

/* Forward declarations */
static void ss_save_factory(struct command *cmd, factory_instance_t *fi);

/* Forward declarations for RPC callbacks */
static struct command_result *rpc_done(struct command *cmd,
				       const char *method,
				       const char *buf,
				       const jsmntok_t *result,
				       void *arg);
static struct command_result *rpc_err(struct command *cmd,
				      const char *method,
				      const char *buf,
				      const jsmntok_t *result,
				      void *arg);
static struct command_result *rpc_err_browse(struct command *cmd,
					     const char *method,
					     const char *buf,
					     const jsmntok_t *result,
					     void *arg);
static struct command_result *rpc_err_join(struct command *cmd,
					   const char *method,
					   const char *buf,
					   const jsmntok_t *result,
					   void *arg);

/* Per-client context for async fundchannel_start → fundchannel_complete chain.
 * Carries the factory pointer and the specific client index so callbacks
 * know which peer they're completing with. */
struct open_channel_ctx {
	factory_instance_t *fi;
	size_t client_idx;
	size_t *channels_done;  /* shared counter among all clients */
	size_t n_total;         /* total channels to open */
	struct command *orig_cmd; /* original RPC command to complete */
};

/* Context for async funding TX creation (withdraw → continue ceremony).
 * After all nonces collected, LSP creates real funding UTXO via CLN's
 * withdraw RPC, then continues with tree rebuild and ALL_NONCES. */
struct funding_ctx {
	factory_instance_t *fi;
	uint8_t funding_spk[34];
	uint8_t funding_spk_len;
};

/* Gap 9: capture/restore MuSig2 keyagg cache snapshots.
 *
 * After factory_build_tree, every node's keyagg (agg_pubkey + opaque
 * cache) has been recomputed from pubkeys + arity. The signet-recovery
 * incident showed that this recompute can produce a cache whose agg
 * pubkey matches the originally-signed value yet still produces sigs
 * that fail on-chain validation — likely subtle non-determinism in
 * tweaking / parity state inside the opaque cache.
 *
 * Capture: serialize lib_factory->nodes[i].keyagg into fi->keyagg_-
 * snapshots, replacing any previous blob. Persisted in meta v15.
 *
 * Restore: walk fi->keyagg_snapshots after factory_build_tree and
 * memcpy each entry back onto lib_factory->nodes[node_idx].keyagg.
 *
 * Blob format (matches the structure documented on
 * factory_instance_t.keyagg_snapshots):
 *   u16 BE n_entries
 *   for each entry:
 *     u16 BE node_idx
 *     u32 BE payload_size
 *     payload_size bytes : raw memcpy of musig_keyagg_t */
static void ss_keyagg_snapshot_capture(factory_instance_t *fi)
{
	factory_t *lf = (factory_t *)fi->lib_factory;
	if (!lf || lf->n_nodes == 0) return;

	const size_t entry_size = sizeof(musig_keyagg_t);
	const size_t blob_len =
		2 + lf->n_nodes * (2 + 4 + entry_size);

	uint8_t *buf = malloc(blob_len);
	if (!buf) return;
	size_t off = 0;
	buf[off++] = (lf->n_nodes >> 8) & 0xFF;
	buf[off++] = lf->n_nodes & 0xFF;
	for (size_t i = 0; i < lf->n_nodes; i++) {
		buf[off++] = (i >> 8) & 0xFF;
		buf[off++] = i & 0xFF;
		buf[off++] = (entry_size >> 24) & 0xFF;
		buf[off++] = (entry_size >> 16) & 0xFF;
		buf[off++] = (entry_size >>  8) & 0xFF;
		buf[off++] = entry_size & 0xFF;
		memcpy(buf + off, &lf->nodes[i].keyagg, entry_size);
		off += entry_size;
	}

	free(fi->keyagg_snapshots);
	fi->keyagg_snapshots = buf;
	fi->keyagg_snapshots_len = blob_len;
}

static void ss_keyagg_snapshot_restore(factory_instance_t *fi)
{
	factory_t *lf = (factory_t *)fi->lib_factory;
	if (!lf || lf->n_nodes == 0) return;
	if (!fi->keyagg_snapshots || fi->keyagg_snapshots_len < 2) return;

	const uint8_t *p = fi->keyagg_snapshots;
	size_t rem = fi->keyagg_snapshots_len;
	uint16_t n_entries = ((uint16_t)p[0] << 8) | p[1];
	p += 2; rem -= 2;

	size_t restored = 0;
	for (uint16_t i = 0; i < n_entries; i++) {
		if (rem < 2 + 4) return;
		uint16_t node_idx = ((uint16_t)p[0] << 8) | p[1];
		uint32_t sz = ((uint32_t)p[2] << 24) | ((uint32_t)p[3] << 16)
			    | ((uint32_t)p[4] <<  8) | p[5];
		p += 6; rem -= 6;
		if (rem < sz) return;
		if (node_idx < lf->n_nodes
		    && sz == sizeof(musig_keyagg_t)) {
			memcpy(&lf->nodes[node_idx].keyagg, p, sz);
			restored++;
		}
		p += sz; rem -= sz;
	}
	if (restored > 0)
		plugin_log(plugin_handle, LOG_DBG,
			   "Gap 9: restored %zu keyagg snapshot(s) onto "
			   "rebuilt tree (n_nodes=%zu)",
			   restored, lf->n_nodes);
}

/* Apply per-client allocations to every leaf's output amounts.
 * Uses fi->allocations[] (populated from factory-create RPC or from
 * FACTORY_PROPOSE/ALL_NONCES payload). Falls back to even split when
 * an allocation slot is 0. Must be called AFTER factory_build_tree. */
static void apply_allocations_to_leaves(factory_instance_t *fi,
					factory_t *factory,
					size_t n_total)
{
	if (!factory || factory->n_leaf_nodes <= 0 || n_total <= 1)
		return;
	if (fi->n_allocations == 0 || fi->funding_amount_sats == 0)
		return;

	uint64_t total = fi->funding_amount_sats;
	uint64_t lstock_total = total * 20 / 100;
	uint64_t client_total = total - lstock_total;
	uint64_t default_per = client_total / (n_total - 1);

	for (int ls = 0; ls < factory->n_leaf_nodes; ls++) {
		size_t leaf_ni = factory->leaf_node_indices[ls];
		factory_node_t *ln = &factory->nodes[leaf_ni];
		size_t nclients = 0;
		for (size_t s = 0; s < ln->n_signers; s++)
			if (ln->signer_indices[s] != 0)
				nclients++;
		size_t n_outputs = nclients + 1;
		uint64_t *amts = calloc(n_outputs, sizeof(uint64_t));
		if (!amts) continue;
		size_t out_idx = 0;
		uint64_t csum = 0;
		for (size_t s = 0; s < ln->n_signers; s++) {
			int pidx = ln->signer_indices[s];
			if (pidx == 0) continue;
			size_t ci = (size_t)(pidx - 1);
			uint64_t a = (ci < fi->n_allocations
				      && fi->allocations[ci] > 0)
				? fi->allocations[ci]
				: default_per;
			amts[out_idx++] = a;
			csum += a;
		}
		/* Library enforces strict fund conservation: new_total must
		 * equal sum(node->outputs[].amount_sats), NOT ln->input_amount.
		 * The library deducts internal tree fees from outputs at
		 * build time, so input_amount is larger than the output sum.
		 * Mismatch → factory_set_leaf_amounts returns 0 silently and
		 * the rewrite is dropped. Compute current_total from outputs. */
		uint64_t current_total = 0;
		for (size_t o = 0; o < ln->n_outputs; o++)
			current_total += ln->outputs[o].amount_sats;
		if (csum + 546 > current_total) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "apply_allocations: leaf=%d allocations sum %"PRIu64
				   " leaves L-stock below dust (current_total=%"PRIu64
				   "); skipping rewrite", ls, csum, current_total);
			free(amts);
			continue;
		}
		amts[nclients] = current_total - csum;
		factory_set_leaf_amounts(factory, ls, amts, n_outputs);
		free(amts);
	}
}

/* Forward declaration */
static void continue_after_funding(struct command *cmd,
				   struct funding_ctx *fctx);

/* Callback after CLN's `withdraw` RPC returns the real funding TX.
 * Parses txid, finds our P2TR output vout, stores real funding data
 * on the factory instance, then continues the ceremony. */
static struct command_result *withdraw_funding_ok(struct command *cmd,
						   const char *method,
						   const char *buf,
						   const jsmntok_t *result,
						   void *arg)
{
	struct funding_ctx *fctx = (struct funding_ctx *)arg;
	factory_instance_t *fi = fctx->fi;

	/* Parse txid from response */
	const jsmntok_t *txid_tok = json_get_member(buf, result, "txid");
	if (!txid_tok) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "withdraw: no txid in response");
		ss_terminalize_failed(cmd, fi, SS_CEREMONY_ABORT_OTHER);
		return notification_handled(cmd);
	}

	const char *txid_hex = json_strdup(cmd, buf, txid_tok);
	if (!txid_hex || strlen(txid_hex) != 64) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "withdraw: bad txid hex");
		ss_terminalize_failed(cmd, fi, SS_CEREMONY_ABORT_OTHER);
		return notification_handled(cmd);
	}

	/* Store real funding txid (internal byte order = reversed hex) */
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		sscanf(txid_hex + j*2, "%02x", &b);
		fi->funding_txid[31 - j] = (uint8_t)b;
	}

	/* Find the vout by scanning TX outputs for our P2TR scriptpubkey.
	 * The withdraw TX may have multiple outputs (our P2TR + change). */
	const jsmntok_t *tx_tok = json_get_member(buf, result, "tx");
	fi->funding_outnum = 0; /* default to first output */
	if (tx_tok) {
		/* For now, assume our output is vout 0 or 1.
		 * A proper implementation would deserialize the TX and scan.
		 * TODO: parse raw TX to find exact vout matching our spk. */
		plugin_log(plugin_handle, LOG_INFORM,
			   "withdraw: funding TX broadcast, txid=%s",
			   txid_hex);
	}

	/* Store funding scriptpubkey and amount */
	memcpy(fi->funding_spk, fctx->funding_spk, fctx->funding_spk_len);
	fi->funding_spk_len = fctx->funding_spk_len;

	plugin_log(plugin_handle, LOG_INFORM,
		   "Real funding UTXO created: txid=%s vout=%u amount=%"PRIu64,
		   txid_hex, fi->funding_outnum, fi->funding_amount_sats);

	/* Now continue the ceremony: rebuild tree with real funding,
	 * finalize sessions, send ALL_NONCES. */
	continue_after_funding(cmd, fctx);

	return command_hook_success(cmd);
}

static struct command_result *withdraw_funding_err(struct command *cmd,
						    const char *method,
						    const char *buf,
						    const jsmntok_t *result,
						    void *arg)
{
	struct funding_ctx *fctx = (struct funding_ctx *)arg;
	const char *err_str = json_strdup(tmpctx, buf, result);
	plugin_log(plugin_handle, LOG_BROKEN,
		   "withdraw failed: %s", err_str ? err_str : "unknown");
	ss_terminalize_failed(cmd, fctx->fi, SS_CEREMONY_ABORT_OTHER);
	return command_hook_success(cmd);
}

/* Send a SuperScalar message wrapped in factory_piggyback (submsg 4).
 * Wire format: type(2) + submsg_id=4(2) + TLV[0]=protocol_id(34) +
 *              TLV[1024]=payload(4+len) where payload = ss_submsg(2)+data */

/* ============================================================================
 * Task #123: send_factory_msg auto-reconnect via aux_command.
 *
 * Wraps the base sendcustommsg in a connect-first dance so disconnected
 * peers get re-peered before the message goes out.  Uses aux_command()
 * to give the async chain its own lifetime, independent of the
 * originating user RPC (which usually returns command_success before
 * the chain finishes — and freeing the original cmd would UAF the
 * context, which is exactly the bug task #120 v1 hit).
 *
 * Lifecycle:
 *   send_factory_msg(cmd, ...)
 *     -> aux = aux_command(cmd)
 *     -> ctx = tal(aux, ss_send_ctx)
 *     -> jsonrpc_request_start(aux, "connect", ...)
 *     return                              <-- original cmd can finalize
 *   ... connect RPC completes async ...
 *     -> ss_send_aux_sendcustommsg(aux)
 *        -> jsonrpc_request_start(aux, "sendcustommsg", ...)
 *   ... sendcustommsg RPC completes ...
 *     -> ss_send_aux_done(aux)
 *        -> aux_command_done(aux)         <-- releases ctx + aux
 * ============================================================================ */
struct ss_send_ctx {
	char *peer_id;
	char *hex_payload;
};

static struct command_result *ss_send_aux_done(
	struct command *aux_cmd, const char *method UNUSED,
	const char *buf UNUSED, const jsmntok_t *result UNUSED, void *arg UNUSED)
{
	return aux_command_done(aux_cmd);
}

static struct command_result *ss_send_aux_sendcustommsg_err(
	struct command *aux_cmd, const char *method UNUSED,
	const char *buf, const jsmntok_t *result, void *arg)
{
	struct ss_send_ctx *sc = arg;
	const jsmntok_t *m = json_get_member(buf, result, "message");
	plugin_log(plugin_handle, LOG_UNUSUAL,
		   "send_factory_msg: sendcustommsg to %s failed: %s",
		   sc->peer_id,
		   m ? json_strdup(aux_cmd, buf, m) : "(no message)");
	return aux_command_done(aux_cmd);
}

static struct command_result *ss_send_aux_sendcustommsg(
	struct command *aux_cmd, const char *method UNUSED,
	const char *buf UNUSED, const jsmntok_t *result UNUSED, void *arg)
{
	struct ss_send_ctx *sc = arg;
	struct out_req *req = jsonrpc_request_start(aux_cmd, "sendcustommsg",
		ss_send_aux_done, ss_send_aux_sendcustommsg_err, sc);
	json_add_string(req->js, "node_id", sc->peer_id);
	json_add_string(req->js, "msg", sc->hex_payload);
	send_outreq(req);
	return command_still_pending(aux_cmd);
}

static struct command_result *ss_send_aux_connect_failed(
	struct command *aux_cmd, const char *method UNUSED,
	const char *buf, const jsmntok_t *result, void *arg)
{
	struct ss_send_ctx *sc = arg;
	const jsmntok_t *m = json_get_member(buf, result, "message");
	const char *msg = m ? json_strdup(aux_cmd, buf, m) : "connect failed";
	plugin_log(plugin_handle, LOG_UNUSUAL,
		   "send_factory_msg: connect to %s failed (%s); "
		   "attempting sendcustommsg anyway",
		   sc->peer_id, msg);
	/* Hail Mary: try send regardless — connect can spuriously fail when
	 * a BOLT-8 handshake is mid-flight; the message may still land. */
	return ss_send_aux_sendcustommsg(aux_cmd, NULL, NULL, NULL, sc);
}

static void send_factory_msg(struct command *cmd, const char *peer_id,
			     uint16_t ss_submsg, const uint8_t *data,
			     size_t data_len)
{
	/* Build factory_piggyback TLV payload:
	 * TLV type 0: protocol_id (1+1+32 = 34 bytes)
	 * TLV type 1024: header(3) + varint_len(1 or 3) + ss_submsg(2) + data */
	size_t inner_len = 2 + data_len; /* ss_submsg(2) + data */
	size_t varint_size = (inner_len < 253) ? 1 : 3;
	size_t tlv1024_len = 3 + varint_size + inner_len;
	size_t wire_len = 4 + 34 + tlv1024_len;

	uint8_t *wire = calloc(1, wire_len);
	wire[0] = (FACTORY_MSG_TYPE >> 8) & 0xFF;
	wire[1] = FACTORY_MSG_TYPE & 0xFF; /* type 33001 (ODD) */
	wire[2] = 0x00; wire[3] = 0x04; /* submsg 4 = factory_piggyback */

	uint8_t *p = wire + 4;
	/* TLV type 0: factory_protocol_id */
	*p++ = 0x00; /* type */
	*p++ = 32;   /* length */
	memcpy(p, SUPERSCALAR_PROTOCOL_ID, 32); p += 32;

	/* TLV type 1024 (0x0400): factory_piggyback_payload */
	*p++ = 0xfd; /* varint prefix for 2-byte type */
	*p++ = 0x04; *p++ = 0x00; /* type 1024 */
	/* length as varint */
	if (inner_len < 253) {
		*p++ = (uint8_t)inner_len;
	} else {
		*p++ = 0xfd;
		*p++ = (inner_len >> 8) & 0xFF;
		*p++ = inner_len & 0xFF;
	}
	/* SuperScalar submessage ID */
	*p++ = (ss_submsg >> 8) & 0xFF;
	*p++ = ss_submsg & 0xFF;
	/* Data */
	if (data_len > 0)
		memcpy(p, data, data_len);
	p += data_len;

	size_t actual_len = (size_t)(p - wire);
	/* Stage the hex into a temp buffer before we copy it into the aux
	 * context — wire is freed at the end of this function. */
	char *hex_tmp = tal_arr(tmpctx, char, actual_len * 2 + 1);
	for (size_t h = 0; h < actual_len; h++)
		sprintf(hex_tmp + h*2, "%02x", wire[h]);

	/* Task #123: spin off an aux_command so the async connect ->
	 * sendcustommsg chain survives the original RPC's command_success.
	 * The ss_send_ctx is tal'd against the aux_cmd; both die together
	 * via aux_command_done in the final callback. */
	struct command *aux_cmd = aux_command(cmd);
	struct ss_send_ctx *sc = tal(aux_cmd, struct ss_send_ctx);
	sc->peer_id = tal_strdup(sc, peer_id);
	sc->hex_payload = tal_strdup(sc, hex_tmp);

	struct out_req *req = jsonrpc_request_start(aux_cmd, "connect",
		ss_send_aux_sendcustommsg,
		ss_send_aux_connect_failed, sc);
	json_add_string(req->js, "id", sc->peer_id);
	send_outreq(req);
	free(wire);
}

/* Phase 3: join variant of send_factory_msg. Same shape as
 * send_factory_msg_browse but plumbs rpc_err_join as the failure callback. */
static void send_factory_msg_join(struct command *cmd, const char *peer_id,
				  uint16_t ss_submsg, const uint8_t *data,
				  size_t data_len)
{
	size_t inner_len = 2 + data_len;
	size_t varint_size = (inner_len < 253) ? 1 : 3;
	size_t tlv1024_len = 3 + varint_size + inner_len;
	size_t wire_len = 4 + 34 + tlv1024_len;

	uint8_t *wire = calloc(1, wire_len);
	wire[0] = (FACTORY_MSG_TYPE >> 8) & 0xFF;
	wire[1] = FACTORY_MSG_TYPE & 0xFF;
	wire[2] = 0x00; wire[3] = 0x04;

	uint8_t *p = wire + 4;
	*p++ = 0x00;
	*p++ = 32;
	memcpy(p, SUPERSCALAR_PROTOCOL_ID, 32); p += 32;

	*p++ = 0xfd;
	*p++ = 0x04; *p++ = 0x00;
	if (inner_len < 253) {
		*p++ = (uint8_t)inner_len;
	} else {
		*p++ = 0xfd;
		*p++ = (inner_len >> 8) & 0xFF;
		*p++ = inner_len & 0xFF;
	}
	*p++ = (ss_submsg >> 8) & 0xFF;
	*p++ = ss_submsg & 0xFF;
	if (data_len > 0)
		memcpy(p, data, data_len);
	p += data_len;

	size_t actual_len = (size_t)(p - wire);
	char *hex = tal_arr(cmd, char, actual_len * 2 + 1);
	for (size_t h = 0; h < actual_len; h++)
		sprintf(hex + h*2, "%02x", wire[h]);

	struct out_req *req = jsonrpc_request_start(cmd,
		"sendcustommsg", rpc_done, rpc_err_join, cmd);
	json_add_string(req->js, "node_id", peer_id);
	json_add_string(req->js, "msg", hex);
	send_outreq(req);
	free(wire);
}

/* Bug A fix: browse variant of send_factory_msg. Identical wire formatting
 * but plumbs rpc_err_browse as the failure callback so synchronous
 * sendcustommsg errors (peer not connected, unknown node, etc.) fail the
 * original RPC immediately instead of leaving it pending. */
static void send_factory_msg_browse(struct command *cmd, const char *peer_id,
				    uint16_t ss_submsg, const uint8_t *data,
				    size_t data_len)
{
	size_t inner_len = 2 + data_len;
	size_t varint_size = (inner_len < 253) ? 1 : 3;
	size_t tlv1024_len = 3 + varint_size + inner_len;
	size_t wire_len = 4 + 34 + tlv1024_len;

	uint8_t *wire = calloc(1, wire_len);
	wire[0] = (FACTORY_MSG_TYPE >> 8) & 0xFF;
	wire[1] = FACTORY_MSG_TYPE & 0xFF;
	wire[2] = 0x00; wire[3] = 0x04;

	uint8_t *p = wire + 4;
	*p++ = 0x00;
	*p++ = 32;
	memcpy(p, SUPERSCALAR_PROTOCOL_ID, 32); p += 32;

	*p++ = 0xfd;
	*p++ = 0x04; *p++ = 0x00;
	if (inner_len < 253) {
		*p++ = (uint8_t)inner_len;
	} else {
		*p++ = 0xfd;
		*p++ = (inner_len >> 8) & 0xFF;
		*p++ = inner_len & 0xFF;
	}
	*p++ = (ss_submsg >> 8) & 0xFF;
	*p++ = ss_submsg & 0xFF;
	if (data_len > 0)
		memcpy(p, data, data_len);
	p += data_len;

	size_t actual_len = (size_t)(p - wire);
	char *hex = tal_arr(cmd, char, actual_len * 2 + 1);
	for (size_t h = 0; h < actual_len; h++)
		sprintf(hex + h*2, "%02x", wire[h]);

	struct out_req *req = jsonrpc_request_start(cmd,
		"sendcustommsg", rpc_done, rpc_err_browse, cmd);
	json_add_string(req->js, "node_id", peer_id);
	json_add_string(req->js, "msg", hex);
	send_outreq(req);
	free(wire);
}

/* Send supported_factory_protocols (submsg 2) to a peer.
 * TLV type 512: list of 32-byte protocol IDs we support. */
static void send_supported_protocols(struct command *cmd, const char *peer_id)
{
	/* Wire: type(2)+submsg(2) + TLV[512](4+32=36 bytes) = 40 total */
	uint8_t wire[40];
	wire[0] = (FACTORY_MSG_TYPE >> 8) & 0xFF;
	wire[1] = FACTORY_MSG_TYPE & 0xFF;
	wire[2] = 0x00; wire[3] = 0x02; /* submsg 2 = supported_factory_protocols */

	/* TLV type 512 (0x0200): protocol_ids */
	wire[4] = 0xfd; /* varint prefix for 2-byte type */
	wire[5] = 0x02; wire[6] = 0x00; /* type 512 */
	wire[7] = 32; /* length: 1 protocol * 32 bytes */
	memcpy(wire + 8, SUPERSCALAR_PROTOCOL_ID, 32);

	char hex[81]; /* (4+36)*2 + 1 */
	for (size_t h = 0; h < 40; h++)
		sprintf(hex + h*2, "%02x", wire[h]);

	struct out_req *req = jsonrpc_request_start(cmd,
		"sendcustommsg", rpc_done, rpc_err, cmd);
	json_add_string(req->js, "node_id", peer_id);
	json_add_string(req->js, "msg", hex);
	send_outreq(req);

	plugin_log(plugin_handle, LOG_DBG,
		   "Sent supported_factory_protocols to %s", peer_id);
}

/* Ceremony state is now per-factory in ss_state */

/* --- Tier 2.6: LEAF_ADVANCE wire helpers (per-leaf advance ceremony) ---
 *
 * Three fixed-size payloads (no TLV, everything packed big-endian):
 *   PROPOSE:  32 iid | 4 leaf_side | 66 lsp_pubnonce          = 102 bytes
 *   PSIG:     32 iid | 4 leaf_side | 66 client_pubnonce |
 *             32 client_psig                                  = 134 bytes
 *   DONE:     32 iid | 4 leaf_side | 32 lsp_psig              =  68 bytes
 *
 * DONE carries LSP's partial sig (not the full aggregate) so the involved
 * client can set_partial_sig + complete_node locally, ending up with a
 * signed chain[N] TX identical to LSP's.  Non-involved clients receive
 * DONE as a tree-state notification and ignore the psig payload. */
static size_t ss_leaf_advance_propose_build(uint8_t *out, size_t cap,
					    const uint8_t iid[32],
					    uint32_t leaf_side,
					    const uint8_t lsp_pubnonce66[66])
{
	if (cap < 102) return 0;
	memcpy(out, iid, 32);
	out[32] = (leaf_side >> 24) & 0xFF;
	out[33] = (leaf_side >> 16) & 0xFF;
	out[34] = (leaf_side >>  8) & 0xFF;
	out[35] = leaf_side & 0xFF;
	memcpy(out + 36, lsp_pubnonce66, 66);
	return 102;
}

static bool ss_leaf_advance_propose_parse(const uint8_t *data, size_t len,
					  uint8_t iid_out[32],
					  uint32_t *leaf_side_out,
					  uint8_t lsp_pubnonce66_out[66])
{
	if (len < 102) return false;
	memcpy(iid_out, data, 32);
	*leaf_side_out = ((uint32_t)data[32] << 24)
		       | ((uint32_t)data[33] << 16)
		       | ((uint32_t)data[34] <<  8)
		       |  (uint32_t)data[35];
	memcpy(lsp_pubnonce66_out, data + 36, 66);
	return true;
}

static size_t ss_leaf_advance_psig_build(uint8_t *out, size_t cap,
					 const uint8_t iid[32],
					 uint32_t leaf_side,
					 const uint8_t client_pubnonce66[66],
					 const uint8_t client_psig32[32])
{
	if (cap < 134) return 0;
	memcpy(out, iid, 32);
	out[32] = (leaf_side >> 24) & 0xFF;
	out[33] = (leaf_side >> 16) & 0xFF;
	out[34] = (leaf_side >>  8) & 0xFF;
	out[35] = leaf_side & 0xFF;
	memcpy(out + 36, client_pubnonce66, 66);
	memcpy(out + 102, client_psig32, 32);
	return 134;
}

static bool ss_leaf_advance_psig_parse(const uint8_t *data, size_t len,
				       uint8_t iid_out[32],
				       uint32_t *leaf_side_out,
				       uint8_t client_pubnonce66_out[66],
				       uint8_t client_psig32_out[32])
{
	if (len < 134) return false;
	memcpy(iid_out, data, 32);
	*leaf_side_out = ((uint32_t)data[32] << 24)
		       | ((uint32_t)data[33] << 16)
		       | ((uint32_t)data[34] <<  8)
		       |  (uint32_t)data[35];
	memcpy(client_pubnonce66_out, data + 36, 66);
	memcpy(client_psig32_out, data + 102, 32);
	return true;
}

static size_t ss_leaf_advance_done_build(uint8_t *out, size_t cap,
					 const uint8_t iid[32],
					 uint32_t leaf_side,
					 const uint8_t lsp_psig32[32])
{
	if (cap < 68) return 0;
	memcpy(out, iid, 32);
	out[32] = (leaf_side >> 24) & 0xFF;
	out[33] = (leaf_side >> 16) & 0xFF;
	out[34] = (leaf_side >>  8) & 0xFF;
	out[35] = leaf_side & 0xFF;
	memcpy(out + 36, lsp_psig32, 32);
	return 68;
}

static bool ss_leaf_advance_done_parse(const uint8_t *data, size_t len,
				       uint8_t iid_out[32],
				       uint32_t *leaf_side_out,
				       uint8_t lsp_psig32_out[32])
{
	if (len < 68) return false;
	memcpy(iid_out, data, 32);
	*leaf_side_out = ((uint32_t)data[32] << 24)
		       | ((uint32_t)data[33] << 16)
		       | ((uint32_t)data[34] <<  8)
		       |  (uint32_t)data[35];
	memcpy(lsp_psig32_out, data + 36, 32);
	return true;
}

/* --- Follow-up #4 impl: LEAF_REALLOC wire helpers ---
 *
 * LEAF_REALLOC_PROPOSE carries the new output amounts so the client can
 * mirror factory_set_leaf_amounts locally before signing. Layout:
 *   [32 iid | 4 leaf_side | 2 n_amounts | 8*n_amounts amounts_BE | 66 pubnonce]
 *
 * LEAF_REALLOC_PSIG and LEAF_REALLOC_DONE have the same wire shape as the
 * corresponding LEAF_ADVANCE variants; only the submsg ID differs. Handlers
 * can reuse ss_leaf_advance_psig_parse / ss_leaf_advance_done_parse for
 * those two. */
#define SS_LEAF_REALLOC_PROPOSE_MAX_OUTPUTS 8

static size_t ss_leaf_realloc_propose_build(uint8_t *out, size_t cap,
					    const uint8_t iid[32],
					    uint32_t leaf_side,
					    const uint64_t *amounts,
					    size_t n_amounts,
					    const uint8_t lsp_pubnonce66[66])
{
	if (n_amounts > SS_LEAF_REALLOC_PROPOSE_MAX_OUTPUTS) return 0;
	size_t need = 32 + 4 + 2 + n_amounts * 8 + 66;
	if (cap < need) return 0;
	memcpy(out, iid, 32);
	out[32] = (leaf_side >> 24) & 0xFF;
	out[33] = (leaf_side >> 16) & 0xFF;
	out[34] = (leaf_side >>  8) & 0xFF;
	out[35] = leaf_side & 0xFF;
	out[36] = (n_amounts >> 8) & 0xFF;
	out[37] = n_amounts & 0xFF;
	uint8_t *p = out + 38;
	for (size_t i = 0; i < n_amounts; i++) {
		uint64_t a = amounts[i];
		p[0] = (a >> 56) & 0xFF; p[1] = (a >> 48) & 0xFF;
		p[2] = (a >> 40) & 0xFF; p[3] = (a >> 32) & 0xFF;
		p[4] = (a >> 24) & 0xFF; p[5] = (a >> 16) & 0xFF;
		p[6] = (a >>  8) & 0xFF; p[7] = a & 0xFF;
		p += 8;
	}
	memcpy(p, lsp_pubnonce66, 66);
	return need;
}

static bool ss_leaf_realloc_propose_parse(const uint8_t *data, size_t len,
					  uint8_t iid_out[32],
					  uint32_t *leaf_side_out,
					  uint64_t *amounts_out,
					  size_t *n_amounts_out,
					  size_t amounts_cap,
					  uint8_t lsp_pubnonce66_out[66])
{
	if (len < 38) return false;
	memcpy(iid_out, data, 32);
	*leaf_side_out = ((uint32_t)data[32] << 24)
		       | ((uint32_t)data[33] << 16)
		       | ((uint32_t)data[34] <<  8)
		       |  (uint32_t)data[35];
	uint16_t n = ((uint16_t)data[36] << 8) | data[37];
	if (n > SS_LEAF_REALLOC_PROPOSE_MAX_OUTPUTS || n > amounts_cap)
		return false;
	size_t need = 38 + (size_t)n * 8 + 66;
	if (len < need) return false;
	const uint8_t *p = data + 38;
	for (uint16_t i = 0; i < n; i++) {
		amounts_out[i] =
			((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
			((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
			((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
			((uint64_t)p[6] <<  8) |  (uint64_t)p[7];
		p += 8;
	}
	memcpy(lsp_pubnonce66_out, p, 66);
	*n_amounts_out = n;
	return true;
}

/* Blocks after which an in-flight PS advance is abandoned and state cleared.
 * 3 blocks ≈ 30 min on mainnet; plenty for async PSIG/DONE round trip even
 * across a reconnect. */
#define PS_PENDING_TIMEOUT_BLOCKS 3

/* Task #151: client-side ceremony self-timeout. If the client's ceremony
 * stays in an in-flight state (PROPOSED / NONCES_COLLECTED / PSIGS_COLLECTED
 * / FUNDING_PENDING / ROTATING) for more than this many blocks without
 * reaching COMPLETE, the per-block handler calls ss_terminalize_failed so
 * the factory leaves the wallet's Live bucket on its own. 36 blocks is
 * roughly 6 hours on mainnet -- long enough to absorb a normal LSP outage
 * + reconnect dance, short enough that a dead LSP doesn't strand the client
 * waiting for days. */
#define CEREMONY_TIMEOUT_BLOCKS 36

/* --- Task #93: ARITY_2 3-of-3 LEAF_REALLOC wire helpers ---
 *
 * These parallel the 2-of-2 realloc helpers above. Layouts:
 *
 *   REALLOC_NONCE       [32 iid | 4 leaf_side | 66 pubnonce]              = 102 B
 *   REALLOC_ALL_NONCES  [32 iid | 4 leaf_side | 3 * 66 pubnonces]         = 234 B
 *                       (slot order: 0=LSP, 1=clientA, 2=clientB)
 *   REALLOC_PSIG_3      [32 iid | 4 leaf_side | 66 pubnonce | 32 psig]    = 134 B
 *                       (own pubnonce repeated for symmetry with 2-of-2 PSIG;
 *                        the receiver already has it from ALL_NONCES, but
 *                        having it on the wire keeps the parser uniform)
 *   REALLOC_DONE_3      [32 iid | 4 leaf_side | 32 lsp_psig |
 *                        32 clientA_psig | 32 clientB_psig]                = 132 B
 *                       (broadcast to both clients; each ignores own slot)
 */

static size_t ss_leaf_realloc_nonce_build(uint8_t *out, size_t cap,
					  const uint8_t iid[32],
					  uint32_t leaf_side,
					  const uint8_t pubnonce66[66])
{
	if (cap < 102) return 0;
	memcpy(out, iid, 32);
	out[32] = (leaf_side >> 24) & 0xFF;
	out[33] = (leaf_side >> 16) & 0xFF;
	out[34] = (leaf_side >>  8) & 0xFF;
	out[35] = leaf_side & 0xFF;
	memcpy(out + 36, pubnonce66, 66);
	return 102;
}

static bool ss_leaf_realloc_nonce_parse(const uint8_t *data, size_t len,
					uint8_t iid_out[32],
					uint32_t *leaf_side_out,
					uint8_t pubnonce66_out[66])
{
	if (len < 102) return false;
	memcpy(iid_out, data, 32);
	*leaf_side_out = ((uint32_t)data[32] << 24)
		       | ((uint32_t)data[33] << 16)
		       | ((uint32_t)data[34] <<  8)
		       |  (uint32_t)data[35];
	memcpy(pubnonce66_out, data + 36, 66);
	return true;
}

static size_t ss_leaf_realloc_all_nonces_build(uint8_t *out, size_t cap,
					       const uint8_t iid[32],
					       uint32_t leaf_side,
					       const uint8_t nonces[3][66])
{
	if (cap < 234) return 0;
	memcpy(out, iid, 32);
	out[32] = (leaf_side >> 24) & 0xFF;
	out[33] = (leaf_side >> 16) & 0xFF;
	out[34] = (leaf_side >>  8) & 0xFF;
	out[35] = leaf_side & 0xFF;
	memcpy(out + 36, nonces[0], 66);
	memcpy(out + 102, nonces[1], 66);
	memcpy(out + 168, nonces[2], 66);
	return 234;
}

static bool ss_leaf_realloc_all_nonces_parse(const uint8_t *data, size_t len,
					     uint8_t iid_out[32],
					     uint32_t *leaf_side_out,
					     uint8_t nonces_out[3][66])
{
	if (len < 234) return false;
	memcpy(iid_out, data, 32);
	*leaf_side_out = ((uint32_t)data[32] << 24)
		       | ((uint32_t)data[33] << 16)
		       | ((uint32_t)data[34] <<  8)
		       |  (uint32_t)data[35];
	memcpy(nonces_out[0], data + 36, 66);
	memcpy(nonces_out[1], data + 102, 66);
	memcpy(nonces_out[2], data + 168, 66);
	return true;
}

/* PSIG_3 reuses the same 134-byte shape as ss_leaf_advance_psig_*; just the
 * submsg ID differs.  We keep dedicated helpers in case the format diverges
 * in the future, but they call through. */
static size_t ss_leaf_realloc_psig3_build(uint8_t *out, size_t cap,
					  const uint8_t iid[32],
					  uint32_t leaf_side,
					  const uint8_t pubnonce66[66],
					  const uint8_t psig32[32])
{
	return ss_leaf_advance_psig_build(out, cap, iid, leaf_side,
					  pubnonce66, psig32);
}

static bool ss_leaf_realloc_psig3_parse(const uint8_t *data, size_t len,
					uint8_t iid_out[32],
					uint32_t *leaf_side_out,
					uint8_t pubnonce66_out[66],
					uint8_t psig32_out[32])
{
	return ss_leaf_advance_psig_parse(data, len, iid_out, leaf_side_out,
					  pubnonce66_out, psig32_out);
}

static size_t ss_leaf_realloc_done3_build(uint8_t *out, size_t cap,
					  const uint8_t iid[32],
					  uint32_t leaf_side,
					  const uint8_t lsp_psig32[32],
					  const uint8_t clientA_psig32[32],
					  const uint8_t clientB_psig32[32])
{
	if (cap < 132) return 0;
	memcpy(out, iid, 32);
	out[32] = (leaf_side >> 24) & 0xFF;
	out[33] = (leaf_side >> 16) & 0xFF;
	out[34] = (leaf_side >>  8) & 0xFF;
	out[35] = leaf_side & 0xFF;
	memcpy(out + 36, lsp_psig32, 32);
	memcpy(out + 68, clientA_psig32, 32);
	memcpy(out + 100, clientB_psig32, 32);
	return 132;
}

static bool ss_leaf_realloc_done3_parse(const uint8_t *data, size_t len,
					uint8_t iid_out[32],
					uint32_t *leaf_side_out,
					uint8_t lsp_psig32_out[32],
					uint8_t clientA_psig32_out[32],
					uint8_t clientB_psig32_out[32])
{
	if (len < 132) return false;
	memcpy(iid_out, data, 32);
	*leaf_side_out = ((uint32_t)data[32] << 24)
		       | ((uint32_t)data[33] << 16)
		       | ((uint32_t)data[34] <<  8)
		       |  (uint32_t)data[35];
	memcpy(lsp_psig32_out, data + 36, 32);
	memcpy(clientA_psig32_out, data + 68, 32);
	memcpy(clientB_psig32_out, data + 100, 32);
	return true;
}

/* Send FACTORY_READY to a single client, with signed-tree trailer.
 *
 * Wire format (backward-compatible):
 *   [32 bytes: instance_id]        (legacy clients read only this)
 *   [N bytes: signed-txs blob]     (same format as ss_persist_serialize_signed_txs:
 *                                   u16 count + per-node u16 node_idx | u8[32] txid |
 *                                   u32 tx_len | tx_bytes)
 *
 * Clients that predate this change ignore anything past byte 32 and keep
 * their old behavior (no signed tree TXs). Clients that DO parse the
 * trailer will end up with node->signed_tx populated for every node the
 * LSP considered signed — enough to drive a trustless unilateral exit.
 *
 * Returns the size of the payload sent (for logging). */
static size_t ss_send_factory_ready(struct command *cmd,
				    factory_instance_t *fi,
				    const char *peer_hex)
{
	uint8_t *blob = NULL;
	size_t blob_len = 0;
	if (fi->lib_factory)
		blob_len = ss_persist_serialize_signed_txs(fi->lib_factory, &blob);

	size_t payload_len = 32 + blob_len;
	uint8_t *payload = malloc(payload_len);
	if (!payload) {
		free(blob);
		return 0;
	}
	memcpy(payload, fi->instance_id, 32);
	if (blob_len > 0 && blob)
		memcpy(payload + 32, blob, blob_len);
	free(blob);

	send_factory_msg(cmd, peer_hex, SS_SUBMSG_FACTORY_READY,
			 payload, payload_len);
	free(payload);

	/* Task #92 + follow-up: the ceremony just completed on the LSP side —
	 * promote lifecycle to SIGNED so factory-list reports the SAME state on
	 * the LSP and the client. The client does the identical promotion in its
	 * FACTORY_READY handler (see SS_SUBMSG_FACTORY_READY below).
	 *
	 * Two paths reach here, and BOTH must end at SIGNED:
	 *   - factory-trigger-ceremony: INIT -> CEREMONY_RUNNING -> (here) SIGNED
	 *   - factory-create with all client pubkeys known up front: the ceremony
	 *     runs synchronously inside the create call and never transitions
	 *     through CEREMONY_RUNNING, so we arrive here still at INIT.
	 *
	 * Previously this branch only matched CEREMONY_RUNNING, which stranded
	 * the create-time path at INIT while the client showed SIGNED. The
	 * wallet's canOpenChannels gate requires lifecycle == SIGNED, so the
	 * operator never saw the "Open Channels" button for a factory created
	 * with a known client set. factory-open-channels accepts INIT and SIGNED
	 * alike and promotes either to ACTIVE, so widening this is safe. */
	if (fi->lifecycle == FACTORY_LIFECYCLE_CEREMONY_RUNNING
	    || fi->lifecycle == FACTORY_LIFECYCLE_INIT)
		fi->lifecycle = FACTORY_LIFECYCLE_SIGNED;
	return payload_len;
}

/* Clear in-flight PS advance state.  Frees the secnonce, resets pending
 * leaf index.  Safe to call when nothing is pending. */
static void ss_clear_ps_pending(factory_instance_t *fi)
{
	if (!fi) return;
	if (fi->ps_pending_secnonce) {
		free(fi->ps_pending_secnonce);
		fi->ps_pending_secnonce = NULL;
	}
	if (fi->cached_ps_propose_wire) {
		free(fi->cached_ps_propose_wire);
		fi->cached_ps_propose_wire = NULL;
		fi->cached_ps_propose_len = 0;
		memset(fi->cached_ps_propose_target_pid, 0, 33);
	}
	if (fi->cached_ps_psig_wire) {
		free(fi->cached_ps_psig_wire);
		fi->cached_ps_psig_wire = NULL;
		fi->cached_ps_psig_len = 0;
	}
	fi->ps_pending_leaf = -1;
	fi->ps_pending_node_idx = 0;
	fi->ps_pending_start_block = 0;
	fi->ps_pending_is_realloc = 0;
	/* Task #93: zero ARITY_2 3-of-3 ceremony scratch space. */
	memset(fi->realloc_subtree_clients, 0,
	       sizeof(fi->realloc_subtree_clients));
	memset(fi->realloc_pubnonces, 0, sizeof(fi->realloc_pubnonces));
	memset(fi->realloc_psigs, 0, sizeof(fi->realloc_psigs));
	memset(fi->realloc_has_pubnonce, 0, sizeof(fi->realloc_has_pubnonce));
	memset(fi->realloc_has_psig, 0, sizeof(fi->realloc_has_psig));
}

/* Persist one PS leaf chain entry at its current (just-signed) state.
 * Keyed by leaf_node_idx + chain_pos so advances don't rewrite history.
 * Called after factory_session_complete_node succeeds on a PS leaf. */
static void ss_save_ps_chain_entry(struct command *cmd,
				   factory_instance_t *fi,
				   uint32_t leaf_node_idx)
{
	if (!fi || !fi->lib_factory) return;
	factory_t *f = (factory_t *)fi->lib_factory;
	if (leaf_node_idx >= f->n_nodes) return;
	factory_node_t *node = &f->nodes[leaf_node_idx];
	if (!node->is_ps_leaf) return;
	if (!node->is_signed || !node->signed_tx.data ||
	    node->signed_tx.len == 0)
		return;

	uint32_t chain_pos = (uint32_t)node->ps_chain_len;
	char key[192];
	ss_persist_key_ps_chain_entry(fi, leaf_node_idx, chain_pos,
				      key, sizeof(key));

	uint8_t *buf = NULL;
	size_t len = ss_persist_serialize_ps_chain_entry(
		node->txid,
		node->outputs[0].amount_sats,
		node->signed_tx.data, node->signed_tx.len,
		&buf);
	if (len > 0 && buf) {
		free(buf);
	}
}

/* Persist chain[0] for every PS leaf in the factory.  Called once after
 * factory_sign_all completes during ceremony — chain[0] is the leaf's
 * initial 2-output state (channel + L-stock) that subsequent advances
 * chain atop. */
static void ss_save_all_ps_chain0(struct command *cmd,
				  factory_instance_t *fi)
{
	if (!fi || !fi->lib_factory) return;
	factory_t *f = (factory_t *)fi->lib_factory;
	for (int i = 0; i < f->n_leaf_nodes; i++) {
		size_t nidx = f->leaf_node_indices[i];
		if (nidx >= f->n_nodes) continue;
		if (!f->nodes[nidx].is_ps_leaf) continue;
		ss_save_ps_chain_entry(cmd, fi, (uint32_t)nidx);
	}
}

/* Generic RPC callback — just log and ignore result */
static struct command_result *rpc_done(struct command *cmd,
				       const char *method,
				       const char *buf,
				       const jsmntok_t *result,
				       void *arg)
{
	return command_still_pending(cmd);
}

static struct command_result *rpc_err(struct command *cmd,
				      const char *method,
				      const char *buf,
				      const jsmntok_t *result,
				      void *arg)
{
	const jsmntok_t *msg_tok = json_get_member(buf, result, "message");
	if (msg_tok) {
		const char *errmsg = json_strdup(cmd, buf, msg_tok);
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "RPC %s failed: %s", method,
			   errmsg ? errmsg : "(null)");
	} else {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "RPC %s failed (no message)", method);
	}
	return command_still_pending(cmd);
}

/* Phase 3: join-specific error callback. Same pattern as rpc_err_browse —
 * synchronous sendcustommsg failures must fail the original RPC immediately
 * and free the slot, rather than leaving it pending. */
static struct command_result *rpc_err_join(struct command *cmd,
					   const char *method,
					   const char *buf,
					   const jsmntok_t *result,
					   void *arg)
{
	for (int i = 0; i < SS_JOIN_MAX_PENDING; i++) {
		if (ss_join_pending[i].cmd == cmd) {
			uint64_t freed_id = ss_join_pending[i].request_id;
			ss_peer_usage_release_slot(ss_join_pending[i].peer_id);
			ss_join_pending[i].request_id = 0;
			ss_join_pending[i].cmd = NULL;
			plugin_log(plugin_handle, LOG_DBG,
				   "join: freed slot for failed RPC "
				   "(req_id=%llu)",
				   (unsigned long long)freed_id);
			break;
		}
	}
	const jsmntok_t *msg_tok = json_get_member(buf, result, "message");
	const char *errmsg = msg_tok
		? json_strdup(cmd, buf, msg_tok)
		: "sendcustommsg failed (no error message)";
	return command_fail(cmd, LIGHTNINGD,
			    "factory-join-request: %s", errmsg);
}

/* Bug A fix: browse-specific error callback. The generic rpc_err returns
 * command_still_pending which is correct for ceremony state machines
 * (they get resolved later by an incoming wire message) but wrong for
 * one-shot browse RPCs that have no follow-up path. */
static struct command_result *rpc_err_browse(struct command *cmd,
					     const char *method,
					     const char *buf,
					     const jsmntok_t *result,
					     void *arg)
{
	for (int i = 0; i < SS_BROWSE_MAX_PENDING; i++) {
		if (ss_browse_pending[i].cmd == cmd) {
			uint64_t freed_id = ss_browse_pending[i].request_id;
			ss_peer_usage_release_slot(ss_browse_pending[i].peer_id);
			ss_browse_pending[i].request_id = 0;
			ss_browse_pending[i].cmd = NULL;
			plugin_log(plugin_handle, LOG_DBG,
				   "browse: freed slot for failed RPC "
				   "(req_id=%llu)",
				   (unsigned long long)freed_id);
			break;
		}
	}
	const jsmntok_t *msg_tok = json_get_member(buf, result, "message");
	const char *errmsg = msg_tok
		? json_strdup(cmd, buf, msg_tok)
		: "sendcustommsg failed (no error message)";
	return command_fail(cmd, LIGHTNINGD,
			    "factory-browse-host: %s", errmsg);
}

/* Callback after fundchannel_complete succeeds */
static struct command_result *fundchannel_complete_ok(struct command *cmd,
						      const char *method,
						      const char *buf,
						      const jsmntok_t *result,
						      void *arg)
{
	struct open_channel_ctx *ctx = (struct open_channel_ctx *)arg;
	factory_instance_t *fi = ctx->fi;
	size_t ci = ctx->client_idx;
	const jsmntok_t *cid_tok;

	cid_tok = json_get_member(buf, result, "channel_id");
	if (cid_tok) {
		const char *cid_hex = json_strdup(cmd, buf, cid_tok);
		plugin_log(plugin_handle, LOG_INFORM,
			   "Factory channel opened for client %zu: "
			   "channel_id=%s", ci, cid_hex ? cid_hex : "?");

		/* Map channel to its DW tree leaf node.
		 * Use factory_find_leaf_for_client to get the correct
		 * node index (ci+1 is the participant index for this client). */
		if (cid_hex && strlen(cid_hex) == 64) {
			uint8_t cid[32];
			for (int j = 0; j < 32; j++) {
				unsigned int b;
				sscanf(cid_hex + j*2, "%02x", &b);
				cid[j] = (uint8_t)b;
			}
			factory_t *f = (factory_t *)fi->lib_factory;
			uint32_t pi = (uint32_t)(ci + 1);
			int leaf_idx = f ? factory_find_leaf_for_client(
				f, pi) : (int)ci;
			if (leaf_idx < 0) leaf_idx = (int)ci;
			/* Compute output index within leaf (leaf_side) */
			int leaf_side = 0;
			if (f && leaf_idx >= 0 &&
			    (size_t)leaf_idx < f->n_nodes) {
				factory_node_t *ln = &f->nodes[leaf_idx];
				for (size_t s = 0; s < ln->n_signers; s++) {
					if (ln->signer_indices[s] == pi)
						break;
					if (ln->signer_indices[s] != 0)
						leaf_side++;
				}
			}
			ss_factory_map_channel(fi, cid, leaf_idx, leaf_side);
			plugin_log(plugin_handle, LOG_INFORM,
				   "Mapped channel to leaf node %d "
				   "output %d (client %zu, participant %u)",
				   leaf_idx, leaf_side, ci, pi);
		}
	}

	fi->lifecycle = FACTORY_LIFECYCLE_ACTIVE;
	ss_save_factory(cmd, fi);
	plugin_log(plugin_handle, LOG_INFORM,
		   "Factory lifecycle=active, n_channels=%zu",
		   fi->n_channels);

	/* Track completion — when all channels are open, reply to RPC */
	if (ctx->channels_done) {
		(*ctx->channels_done)++;
		if (*ctx->channels_done >= ctx->n_total && ctx->orig_cmd) {
			struct json_stream *js =
				jsonrpc_stream_success(ctx->orig_cmd);
			char id_hex[65];
			for (int j = 0; j < 32; j++)
				sprintf(id_hex + j*2, "%02x",
					fi->instance_id[j]);
			json_add_string(js, "instance_id", id_hex);
			json_add_u64(js, "n_channels", fi->n_channels);
			json_add_string(js, "status", "channels_open");
			return command_finished(ctx->orig_cmd, js);
		}
	}
	return command_still_pending(cmd);
}

/* Callback after fundchannel_start succeeds — build PSBT, call complete */
static struct command_result *fundchannel_start_ok(struct command *cmd,
						   const char *method,
						   const char *buf,
						   const jsmntok_t *result,
						   void *arg)
{
	struct open_channel_ctx *ctx = (struct open_channel_ctx *)arg;
	factory_instance_t *fi = ctx->fi;
	size_t ci = ctx->client_idx;
	const jsmntok_t *spk_tok;

	spk_tok = json_get_member(buf, result, "scriptpubkey");
	if (!spk_tok) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "fundchannel_start: no scriptpubkey in response");
		return command_still_pending(cmd);
	}

	/* Parse scriptpubkey from hex */
	const char *spk_hex = json_strdup(cmd, buf, spk_tok);
	size_t spk_hex_len = spk_hex ? strlen(spk_hex) : 0;
	size_t spk_len = spk_hex_len / 2;
	u8 *spk = tal_arr(cmd, u8, spk_len);
	for (size_t i = 0; i < spk_len; i++) {
		unsigned int b;
		sscanf(spk_hex + i*2, "%02x", &b);
		spk[i] = (uint8_t)b;
	}

	/* Task #93: must match the amount we requested in
	 * fundchannel_start (open_factory_channels), which is derived
	 * from fi->funding_amount_sats × (1 - L-stock pct) / n_clients.
	 * Previously hardcoded to DEFAULT_FUNDING_SATS — coincidentally
	 * matched while open_factory_channels also defaulted to 500k,
	 * but now diverges and CLN rejects fundchannel_complete with
	 * "Output to open channel is 500000sat, should be 24000sat". */
	struct amount_sat funding_amt;
	{
		uint64_t amt = fi->clients[ci].allocation_sats;
		if (amt == 0) {
			uint64_t total = fi->funding_amount_sats;
			uint64_t lstock = total * 20 / 100;
			uint64_t client_pool = total > lstock
				? total - lstock : 0;
			amt = fi->n_clients > 0
				? client_pool / fi->n_clients
				: client_pool;
			if (amt == 0)
				amt = DEFAULT_FUNDING_SATS;
		}
		funding_amt.satoshis = amt;
	}

	plugin_log(plugin_handle, LOG_INFORM,
		   "fundchannel_start ok for client %zu, building PSBT "
		   "(spk=%s, amt=%"PRIu64")",
		   ci, spk_hex, funding_amt.satoshis);

	/* Build minimal PSBT: 0 inputs, 1 output matching funding script */
	struct wally_psbt *psbt = create_psbt(cmd, 0, 0, 0);
	psbt_append_output(psbt, spk, funding_amt);

	/* Get the peer node_id for this specific client */
	char nid[67];
	for (int j = 0; j < 33; j++)
		sprintf(nid + j*2, "%02x", fi->clients[ci].node_id[j]);
	nid[66] = '\0';

	/* Look up the real DW leaf node for this client so the channel's
	 * funding outpoint references the actual tree transaction. */
	factory_t *factory = (factory_t *)fi->lib_factory;
	int leaf_node_idx = -1;
	uint32_t leaf_outnum = 0;
	char leaf_txid_hex[65] = {0};

	if (factory) {
		uint32_t participant_idx = (uint32_t)(ci + 1);
		leaf_node_idx = factory_find_leaf_for_client(factory,
							     participant_idx);
		if (leaf_node_idx >= 0 &&
		    (size_t)leaf_node_idx < factory->n_nodes) {
			for (int j = 0; j < 32; j++)
				sprintf(leaf_txid_hex + j*2, "%02x",
					factory->nodes[leaf_node_idx].txid[31 - j]);
			leaf_txid_hex[64] = '\0';

			/* Compute output index: client's position among
			 * non-LSP signers on this leaf node.
			 * Signers are ordered by participant_idx; outputs
			 * follow the same order (LSP L-stock is last). */
			factory_node_t *ln = &factory->nodes[leaf_node_idx];
			uint32_t client_pos = 0;
			for (size_t s = 0; s < ln->n_signers; s++) {
				if (ln->signer_indices[s] == participant_idx)
					break;
				if (ln->signer_indices[s] != 0) /* skip LSP */
					client_pos++;
			}
			leaf_outnum = client_pos;
		}
	}

	/* Call fundchannel_complete with the PSBT + factory funding override */
	struct out_req *req = jsonrpc_request_start(cmd,
		"fundchannel_complete",
		fundchannel_complete_ok, rpc_err, ctx);
	json_add_string(req->js, "id", nid);
	json_add_psbt(req->js, "psbt", psbt);
	if (leaf_txid_hex[0]) {
		json_add_string(req->js, "factory_funding_txid", leaf_txid_hex);
		json_add_u32(req->js, "factory_funding_outnum", leaf_outnum);
		plugin_log(plugin_handle, LOG_INFORM,
			   "fundchannel_complete: factory funding override "
			   "leaf_node=%d outnum=%u txid=%s",
			   leaf_node_idx, leaf_outnum, leaf_txid_hex);
	}
	send_outreq(req);

	plugin_log(plugin_handle, LOG_INFORM,
		   "Called fundchannel_complete for client %zu (%s)",
		   ci, nid);

	return command_still_pending(cmd);
}

/* Open factory channels for each client.
 * Called from factory-open-channels RPC (separate cmd context). */
static void open_factory_channels(struct command *cmd,
				   factory_instance_t *fi)
{
	/* Shared counter — freed with cmd (tal parent) */
	size_t *done_counter = tal(cmd, size_t);
	*done_counter = 0;

	for (size_t ci = 0; ci < fi->n_clients; ci++) {
		char nid[67];
		for (int j = 0; j < 33; j++)
			sprintf(nid + j*2, "%02x",
				fi->clients[ci].node_id[j]);
		nid[66] = '\0';

		char proto_hex[65], inst_hex[65];
		for (int j = 0; j < 32; j++) {
			sprintf(proto_hex + j*2, "%02x",
				SUPERSCALAR_PROTOCOL_ID[j]);
			sprintf(inst_hex + j*2, "%02x",
				fi->instance_id[j]);
		}

		struct open_channel_ctx *ctx = tal(cmd, struct open_channel_ctx);
		ctx->fi = fi;
		ctx->client_idx = ci;
		ctx->channels_done = done_counter;
		ctx->n_total = fi->n_clients;
		ctx->orig_cmd = cmd;

		struct out_req *req = jsonrpc_request_start(cmd,
			"fundchannel_start",
			fundchannel_start_ok, rpc_err, ctx);
		json_add_string(req->js, "id", nid);
		{
			/* Task #93: compute per-client channel size from the
			 * factory's actual funding, NOT a 500k fallback.
			 * Mirrors apply_allocations_to_leaves: 20% L-stock,
			 * rest split equally among n_clients. Previously the
			 * code defaulted to DEFAULT_FUNDING_SATS=500_000 sat
			 * whenever allocations weren't explicit, producing
			 * channels whose total_msat (500k) was divorced from
			 * the actual on-chain UTXO amount — making force-close
			 * publish a TX that wouldn't validate at consensus. */
			uint64_t amt = fi->clients[ci].allocation_sats;
			if (amt == 0) {
				uint64_t total = fi->funding_amount_sats;
				uint64_t lstock = total * 20 / 100;
				uint64_t client_pool = total > lstock
					? total - lstock : 0;
				amt = fi->n_clients > 0
					? client_pool / fi->n_clients
					: client_pool;
				if (amt == 0)
					amt = DEFAULT_FUNDING_SATS; /* safety net */
			}
			char amt_str[32];
			snprintf(amt_str, sizeof(amt_str), "%"PRIu64"sat", amt);
			json_add_string(req->js, "amount", amt_str);
		}
		json_add_bool(req->js, "announce", false);
		json_add_u32(req->js, "mindepth", 0);
		json_add_string(req->js, "factory_protocol_id", proto_hex);
		json_add_string(req->js, "factory_instance_id", inst_hex);
		json_add_u64(req->js, "factory_early_warning_time",
			     fi->early_warning_time > 0
			     ? fi->early_warning_time
			     : compute_early_warning_time(fi->n_clients,
				   ss_effective_arity(fi)));
		/* Audit #5 follow-up: always pass explicit feerate so CLN never
		 * tries to auto-estimate (which fails on test networks where the
		 * fee estimator isn't primed). Same default as the funding withdraw. */
		{
			uint32_t fr_perkw = fi->requested_feerate_perkw > 0
				? fi->requested_feerate_perkw
				: 253; /* 1 sat/vb floor; CLN min_acceptable */
			char fr_str[32];
			snprintf(fr_str, sizeof(fr_str), "%uperkw", fr_perkw);
			json_add_string(req->js, "feerate", fr_str);
		}
		send_outreq(req);

		plugin_log(plugin_handle, LOG_INFORM,
			   "Opening factory channel with client %zu (%s)",
			   ci, nid);
	}
}

/* Complete rotation: send REVOKE for old epoch, ROTATE_COMPLETE,
 * and trigger factory-change on open channels. Called after both
 * rotation tree and distribution TX are signed. */
static void rotate_finish_and_notify(struct command *cmd,
				     factory_instance_t *fi)
{
	factory_t *f = (factory_t *)fi->lib_factory;
	if (!f) return;

	fi->ceremony = CEREMONY_ROTATE_COMPLETE;
	fi->rotation_in_progress = false;

	/* Rotation done — release the cached ROTATE_PROPOSE payload used
	 * for reconnect recovery. It would be misleading to leave it
	 * around since the next rotation allocates a fresh one. */
	if (fi->cached_rotate_propose_wire) {
		free(fi->cached_rotate_propose_wire);
		fi->cached_rotate_propose_wire = NULL;
		fi->cached_rotate_propose_len = 0;
	}

	/* Send revocation secret for old epoch */
	uint32_t old_ep = fi->epoch - 1;
	unsigned char rev_secret[32];
	if (factory_get_revocation_secret(f, old_ep, rev_secret)) {
		uint8_t rev_payload[36];
		rev_payload[0] = (old_ep >> 24) & 0xFF;
		rev_payload[1] = (old_ep >> 16) & 0xFF;
		rev_payload[2] = (old_ep >> 8) & 0xFF;
		rev_payload[3] = old_ep & 0xFF;
		memcpy(rev_payload + 4, rev_secret, 32);

		for (size_t ci = 0; ci < fi->n_clients; ci++) {
			char nid[67];
			for (int j = 0; j < 33; j++)
				sprintf(nid + j*2, "%02x",
					fi->clients[ci].node_id[j]);
			nid[66] = '\0';
			send_factory_msg(cmd, nid,
				SS_SUBMSG_REVOKE, rev_payload, 36);
			/* Track pending ack per client. Cleared on
			 * REVOKE_ACK receipt; resent on reconnect if still
			 * UINT32_MAX != old_ep. Persisted in meta. */
			fi->clients[ci].pending_revoke_epoch = old_ep;
		}
		ss_save_factory(cmd, fi);
		plugin_log(plugin_handle, LOG_INFORM,
			   "LSP: sent REVOKE for epoch %u (awaiting ack from "
			   "%zu clients)", old_ep, fi->n_clients);
	}

	/* Follow-up #1 sub-PR 3C: ROTATE_COMPLETE carries the new epoch's
	 * signed tree TXs as a backward-compatible trailer after the 32-byte
	 * instance_id (same format as FACTORY_READY's trailer in sub-PR 3A).
	 * Legacy clients that read only 32 bytes keep their old behavior;
	 * new clients apply the signed tree to their factory_t so they have
	 * trustless force-close for the rotated epoch. */
	uint8_t *rc_blob = NULL;
	size_t rc_blob_len = 0;
	if (fi->lib_factory)
		rc_blob_len = ss_persist_serialize_signed_txs(fi->lib_factory,
							      &rc_blob);
	size_t rc_payload_len = 32 + rc_blob_len;
	uint8_t *rc_payload = malloc(rc_payload_len);
	if (rc_payload) {
		memcpy(rc_payload, fi->instance_id, 32);
		if (rc_blob_len > 0 && rc_blob)
			memcpy(rc_payload + 32, rc_blob, rc_blob_len);
	}
	free(rc_blob);

	/* Send ROTATE_COMPLETE to clients */
	for (size_t ci = 0; ci < fi->n_clients; ci++) {
		char nid[67];
		for (int j = 0; j < 33; j++)
			sprintf(nid + j*2, "%02x",
				fi->clients[ci].node_id[j]);
		nid[66] = '\0';
		if (rc_payload)
			send_factory_msg(cmd, nid,
				SS_SUBMSG_ROTATE_COMPLETE,
				rc_payload, rc_payload_len);
		else
			send_factory_msg(cmd, nid,
				SS_SUBMSG_ROTATE_COMPLETE,
				fi->instance_id, 32);
	}
	plugin_log(plugin_handle, LOG_INFORM,
		   "LSP: sent ROTATE_COMPLETE to %zu clients "
		   "(%zu bytes incl signed-tree trailer)",
		   fi->n_clients, rc_payload_len);
	free(rc_payload);

	/* Trigger factory-change on open channels */
	if (fi->n_channels > 0) {
		for (size_t ch = 0; ch < fi->n_channels; ch++) {
			char cid_hex[65];
			for (int j = 0; j < 32; j++)
				sprintf(cid_hex + j*2, "%02x",
					fi->channels[ch].channel_id[j]);

			char txid_hex[65];
			size_t leaf_idx = fi->channels[ch].leaf_index;
			if (leaf_idx < f->n_nodes) {
				for (int j = 0; j < 32; j++)
					sprintf(txid_hex + j*2, "%02x",
						f->nodes[leaf_idx].txid[31-j]);
			} else {
				memset(txid_hex, '0', 64);
			}
			txid_hex[64] = '\0';

			struct out_req *creq = jsonrpc_request_start(
				cmd, "factory-change",
				rpc_done, rpc_err, fi);
			json_add_string(creq->js, "channel_id", cid_hex);
			json_add_string(creq->js, "new_funding_txid", txid_hex);
			json_add_u32(creq->js, "new_funding_outnum",
				     (uint32_t)fi->channels[ch].leaf_side);
			send_outreq(creq);

			plugin_log(plugin_handle, LOG_INFORM,
				   "LSP: triggered factory-change on channel %zu"
				   " (leaf=%d, outnum=%d)",
				   ch, fi->channels[ch].leaf_index,
				   fi->channels[ch].leaf_side);
		}
	}

	ss_save_factory(cmd, fi);

	/* Reconnect each client peer after factory-change to force CLN
	 * to re-exchange channel_reestablish. This re-registers the
	 * channel in CLN's routing table with the updated funding
	 * outpoint, fixing the "no path found" issue after rotation.
	 * Workaround for CLN not natively routing via alias SCIDs
	 * after a funding outpoint change. */
	for (size_t ci = 0; ci < fi->n_clients; ci++) {
		char nid[67];
		for (int j = 0; j < 33; j++)
			sprintf(nid + j*2, "%02x",
				fi->clients[ci].node_id[j]);
		nid[66] = '\0';

		struct out_req *dreq = jsonrpc_request_start(
			cmd, "disconnect",
			rpc_done, rpc_err, fi);
		json_add_string(dreq->js, "id", nid);
		json_add_bool(dreq->js, "force", true);
		send_outreq(dreq);

		struct out_req *creq = jsonrpc_request_start(
			cmd, "connect",
			rpc_done, rpc_err, fi);
		json_add_string(creq->js, "id", nid);
		send_outreq(creq);

		plugin_log(plugin_handle, LOG_INFORM,
			   "LSP: reconnecting client %zu after factory-change",
			   ci);
	}

	plugin_log(plugin_handle, LOG_INFORM,
		   "LSP: ROTATION COMPLETE epoch=%u", fi->epoch);
}

/* Persist a factory's state to CLN datastore (fire-and-forget) */
/* ============================================================================
 * Phase 3: join queue + outgoing joins persistence helpers
 *
 * Serialized formats use a leading u8 schema_version so future changes can
 * detect and migrate old blobs. Current schema_version = 1.
 *
 * TODO(privacy): pre-mainnet, audit what subset of these fields can be
 * hashed/dropped after lifecycle completes. Currently we retain everything.
 * ============================================================================ */
#define SS_JOIN_SCHEMA_V1 1

/* Per-entry sizes are written explicitly so a parser at a different version
 * can sanity-check before trying to deserialize. v1 entry sizes: */
#define SS_JOIN_QUEUE_ENTRY_V1_SZ      126   /* 33+8+8+4+4+4+1+64 */
#define SS_OUTGOING_JOIN_ENTRY_V1_SZ   158   /* 33+32+8+8+4+4+4+1+64 */

/* Datastore key for an LSP's join queue: superscalar/<iid_hex>/join-queue */
static void ss_persist_key_join_queue(const factory_instance_t *fi,
				       char *key, size_t keylen)
{
	char iid_hex[65];
	for (int j = 0; j < 32; j++)
		sprintf(iid_hex + j*2, "%02x", fi->instance_id[j]);
	iid_hex[64] = 0;
	snprintf(key, keylen, "superscalar/%s/join-queue", iid_hex);
}

/* Serialize the LSP-side join_queue to a freshly-allocated buffer.
 * Caller frees the returned buffer (via free()). Returns 0 on empty queue. */
static size_t ss_persist_serialize_join_queue(const factory_instance_t *fi,
					       uint8_t **out_buf)
{
	*out_buf = NULL;
	if (fi->n_join_queue == 0)
		return 0;
	size_t len = 3 + fi->n_join_queue * SS_JOIN_QUEUE_ENTRY_V1_SZ;
	uint8_t *buf = calloc(1, len);
	if (!buf) return 0;
	uint8_t *p = buf;
	*p++ = SS_JOIN_SCHEMA_V1;
	*p++ = (fi->n_join_queue >> 8) & 0xFF;
	*p++ = fi->n_join_queue & 0xFF;
	for (size_t i = 0; i < fi->n_join_queue; i++) {
		const factory_join_t *j = &fi->join_queue[i];
		memcpy(p, j->client_node_id, 33); p += 33;
		for (int k = 7; k >= 0; k--) *p++ = (j->request_id >> (k*8)) & 0xFF;
		for (int k = 7; k >= 0; k--) *p++ = (j->contribution_sats >> (k*8)) & 0xFF;
		for (int k = 3; k >= 0; k--) *p++ = (j->received_at_block >> (k*8)) & 0xFF;
		for (int k = 3; k >= 0; k--) *p++ = (j->accepted_at_block >> (k*8)) & 0xFF;
		for (int k = 3; k >= 0; k--) *p++ = (j->decided_at_block >> (k*8)) & 0xFF;
		*p++ = (uint8_t)j->status;
		memcpy(p, j->reason, 64); p += 64;
	}
	*out_buf = buf;
	return len;
}

/* Deserialize a join_queue blob into fi->join_queue. Returns true on success,
 * false on schema-version mismatch or length mismatch (in which case the
 * caller should treat as "no saved queue"). */
static bool ss_persist_deserialize_join_queue(factory_instance_t *fi,
					       const uint8_t *buf, size_t len)
{
	if (len < 3) return false;
	if (buf[0] != SS_JOIN_SCHEMA_V1) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "join_queue blob has unknown schema_version=%u for "
			   "factory, refusing to load (will start fresh)",
			   buf[0]);
		return false;
	}
	uint16_t n = ((uint16_t)buf[1] << 8) | buf[2];
	if (n > MAX_JOIN_QUEUE) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "join_queue blob declares %u entries, exceeds "
			   "MAX_JOIN_QUEUE=%u, refusing to load",
			   (unsigned)n, MAX_JOIN_QUEUE);
		return false;
	}
	if (len != (size_t)(3 + n * SS_JOIN_QUEUE_ENTRY_V1_SZ)) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "join_queue blob length mismatch (got %zu, "
			   "expected %zu for n=%u)", len,
			   (size_t)(3 + n * SS_JOIN_QUEUE_ENTRY_V1_SZ),
			   (unsigned)n);
		return false;
	}
	const uint8_t *p = buf + 3;
	fi->n_join_queue = 0;
	for (uint16_t i = 0; i < n; i++) {
		factory_join_t *j = &fi->join_queue[i];
		memcpy(j->client_node_id, p, 33); p += 33;
		j->request_id = 0;
		for (int k = 0; k < 8; k++) j->request_id = (j->request_id << 8) | *p++;
		j->contribution_sats = 0;
		for (int k = 0; k < 8; k++) j->contribution_sats = (j->contribution_sats << 8) | *p++;
		j->received_at_block = 0;
		for (int k = 0; k < 4; k++) j->received_at_block = (j->received_at_block << 8) | *p++;
		j->accepted_at_block = 0;
		for (int k = 0; k < 4; k++) j->accepted_at_block = (j->accepted_at_block << 8) | *p++;
		j->decided_at_block = 0;
		for (int k = 0; k < 4; k++) j->decided_at_block = (j->decided_at_block << 8) | *p++;
		j->status = (factory_join_status_t)*p++;
		memcpy(j->reason, p, 64); p += 64;
		fi->n_join_queue++;
	}
	plugin_log(plugin_handle, LOG_INFORM,
		   "Loaded join_queue: %u entries", (unsigned)n);
	return true;
}

/* ----- Client-side outgoing joins ----------------------------------------- */

#define SS_OUTGOING_JOINS_KEY "superscalar/outgoing-joins"

/* Serialize the client-side outgoing_joins to a freshly-allocated buffer.
 * Caller frees via free(). Returns 0 on empty list. */
static size_t ss_persist_serialize_outgoing_joins(uint8_t **out_buf)
{
	*out_buf = NULL;
	if (ss_state.n_outgoing_joins == 0)
		return 0;
	size_t len = 3 + ss_state.n_outgoing_joins * SS_OUTGOING_JOIN_ENTRY_V1_SZ;
	uint8_t *buf = calloc(1, len);
	if (!buf) return 0;
	uint8_t *p = buf;
	*p++ = SS_JOIN_SCHEMA_V1;
	*p++ = (ss_state.n_outgoing_joins >> 8) & 0xFF;
	*p++ = ss_state.n_outgoing_joins & 0xFF;
	for (size_t i = 0; i < ss_state.n_outgoing_joins; i++) {
		const outgoing_join_t *o = &ss_state.outgoing_joins[i];
		memcpy(p, o->lsp_node_id, 33); p += 33;
		memcpy(p, o->instance_id, 32); p += 32;
		for (int k = 7; k >= 0; k--) *p++ = (o->request_id >> (k*8)) & 0xFF;
		for (int k = 7; k >= 0; k--) *p++ = (o->contribution_sats >> (k*8)) & 0xFF;
		for (int k = 3; k >= 0; k--) *p++ = (o->sent_at_block >> (k*8)) & 0xFF;
		for (int k = 3; k >= 0; k--) *p++ = (o->expected_signing_block >> (k*8)) & 0xFF;
		for (int k = 3; k >= 0; k--) *p++ = (o->updated_at_block >> (k*8)) & 0xFF;
		*p++ = (uint8_t)o->status;
		memcpy(p, o->reason, 64); p += 64;
	}
	*out_buf = buf;
	return len;
}

/* Persist outgoing_joins to the datastore. Caller is responsible for not
 * calling this excessively — current pattern saves on every mutation. */
static void ss_save_outgoing_joins(struct command *cmd)
{
	uint8_t *buf = NULL;
	size_t len = ss_persist_serialize_outgoing_joins(&buf);
	if (len > 0 && buf) {
		free(buf);
		plugin_log(plugin_handle, LOG_DBG,
			   "Persisted outgoing_joins (%zu entries, %zu bytes)",
			   ss_state.n_outgoing_joins, len);
	} else if (ss_state.n_outgoing_joins == 0) {
		/* Persist an empty marker so a later load knows "we exist
		 * but have no joins" rather than "no data ever". v1
		 * marker is just the 3-byte header. */
		uint8_t empty[3] = { SS_JOIN_SCHEMA_V1, 0, 0 };
	}

	/* Task #72: dual-write each outgoing_join entry to the soupwallet
	 * plugin. Per-entry upserts. Best-effort; failures here don't affect
	 * the canonical datastore write above. */
	for (size_t k = 0; k < ss_state.n_outgoing_joins; k++) {
		const outgoing_join_t *o = &ss_state.outgoing_joins[k];
		char fiid_hex[65], lsp_hex[67];
		for (int j = 0; j < 32; j++)
			sprintf(fiid_hex + j*2, "%02x", o->instance_id[j]);
		fiid_hex[64] = 0;
		for (int j = 0; j < 33; j++)
			sprintf(lsp_hex + j*2, "%02x", o->lsp_node_id[j]);
		lsp_hex[66] = 0;
		char req_id_str[24], contrib_str[24];
		snprintf(req_id_str, sizeof req_id_str, "%llu",
			 (unsigned long long)o->request_id);
		snprintf(contrib_str, sizeof contrib_str, "%llu",
			 (unsigned long long)o->contribution_sats);
		struct out_req *wreq = jsonrpc_request_start(cmd,
			"wallet-upsert-outgoing-join",
			rpc_done, rpc_err, NULL);
		json_add_string(wreq->js, "factory_instance_id_hex", fiid_hex);
		json_add_string(wreq->js, "lsp_pubkey_hex", lsp_hex);
		json_add_string(wreq->js, "request_id", req_id_str);
		json_add_string(wreq->js, "contribution_sats", contrib_str);
		json_add_u32(wreq->js, "sent_at_block", o->sent_at_block);
		if (o->expected_signing_block)
			json_add_u32(wreq->js, "expected_signing_block",
				     o->expected_signing_block);
		json_add_u32(wreq->js, "updated_at_block", o->updated_at_block);
		json_add_u32(wreq->js, "status", (u32)o->status);
		if (o->reason[0])
			json_add_string(wreq->js, "reason",
					(const char *)o->reason);
		send_outreq(wreq);
	}
}

/* Called from init() — load outgoing_joins from wallet.db at startup so
 * wallet restarts don't lose pending-rotation memberships. */
static void ss_load_outgoing_joins(struct command *cmd)
{
	(void)cmd;
	ss_state.n_outgoing_joins = 0;
	sqlite3 *db = ss_open_wallet_db_ro(tmpctx);
	if (!db) return;
	sqlite3_stmt *st = NULL;
	const char *sql =
		"SELECT factory_instance_id, lsp_pubkey, request_id, "
		"       contribution_sats, sent_at_block, "
		"       expected_signing_block, updated_at_block, "
		"       status, reason "
		"FROM outgoing_joins";
	if (sqlite3_prepare_v2(db, sql, -1, &st, NULL) != SQLITE_OK) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "load outgoing_joins prepare failed: %s",
			   sqlite3_errmsg(db));
		sqlite3_close(db);
		return;
	}
	while (sqlite3_step(st) == SQLITE_ROW
	       && ss_state.n_outgoing_joins < MAX_OUTGOING_JOINS) {
		outgoing_join_t *o =
			&ss_state.outgoing_joins[ss_state.n_outgoing_joins];
		const void *iid = sqlite3_column_blob(st, 0);
		const void *lsp = sqlite3_column_blob(st, 1);
		int iidlen = sqlite3_column_bytes(st, 0);
		int lsplen = sqlite3_column_bytes(st, 1);
		if (iidlen != 32 || lsplen != 33) continue;
		memcpy(o->instance_id, iid, 32);
		memcpy(o->lsp_node_id, lsp, 33);
		o->request_id = (uint64_t)sqlite3_column_int64(st, 2);
		o->contribution_sats = (uint64_t)sqlite3_column_int64(st, 3);
		o->sent_at_block = (uint32_t)sqlite3_column_int64(st, 4);
		o->expected_signing_block =
			(uint32_t)sqlite3_column_int64(st, 5);
		o->updated_at_block = (uint32_t)sqlite3_column_int64(st, 6);
		o->status = (outgoing_join_status_t)sqlite3_column_int(st, 7);
		memset(o->reason, 0, sizeof(o->reason));
		const unsigned char *reason = sqlite3_column_text(st, 8);
		if (reason) {
			size_t rlen = strlen((const char *)reason);
			if (rlen >= sizeof(o->reason)) rlen = sizeof(o->reason) - 1;
			memcpy(o->reason, reason, rlen);
		}
		ss_state.n_outgoing_joins++;
	}
	sqlite3_finalize(st);
	sqlite3_close(db);
	plugin_log(plugin_handle, LOG_INFORM,
		   "Loaded outgoing_joins from wallet.db: %u entries",
		   (unsigned)ss_state.n_outgoing_joins);
}

static void ss_save_factory(struct command *cmd, factory_instance_t *fi)
{
	char key[128];
	uint8_t *buf;
	size_t len;

	/* Save metadata */
	ss_persist_key_meta(fi, key, sizeof(key));
	len = ss_persist_serialize_meta(fi, &buf);
	if (len > 0 && buf) {
		/* Task #72: dual-write meta blob to soupwallet plugin. */
		{
			char wiid[65];
			for (int j = 0; j < 32; j++)
				sprintf(wiid + j*2, "%02x", fi->instance_id[j]);
			wiid[64] = 0;
			char wkey[160];
			snprintf(wkey, sizeof wkey, "factory_blob:%s:meta", wiid);
			char *blob_hex = malloc(len * 2 + 1);
			if (blob_hex) {
				for (size_t bi = 0; bi < len; bi++)
					sprintf(blob_hex + bi*2, "%02x", buf[bi]);
				blob_hex[len * 2] = 0;
				struct out_req *wreq = jsonrpc_request_start(cmd,
					"wallet-set-setting", rpc_done, rpc_err, NULL);
				json_add_string(wreq->js, "setting_key", wkey);
				json_add_string(wreq->js, "setting_value", blob_hex);
				send_outreq(wreq);
				free(blob_hex);
			}
		}
		free(buf);
	}

	/* Save channel mappings */
	if (fi->n_channels > 0) {
		ss_persist_key_channels(fi, key, sizeof(key));
		len = ss_persist_serialize_channels(fi, &buf);
		if (len > 0 && buf) {
		/* Task #72: dual-write channels blob to soupwallet plugin. */
		{
			char wiid[65];
			for (int j = 0; j < 32; j++)
				sprintf(wiid + j*2, "%02x", fi->instance_id[j]);
			wiid[64] = 0;
			char wkey[160];
			snprintf(wkey, sizeof wkey, "factory_blob:%s:channels", wiid);
			char *blob_hex = malloc(len * 2 + 1);
			if (blob_hex) {
				for (size_t bi = 0; bi < len; bi++)
					sprintf(blob_hex + bi*2, "%02x", buf[bi]);
				blob_hex[len * 2] = 0;
				struct out_req *wreq = jsonrpc_request_start(cmd,
					"wallet-set-setting", rpc_done, rpc_err, NULL);
				json_add_string(wreq->js, "setting_key", wkey);
				json_add_string(wreq->js, "setting_value", blob_hex);
				send_outreq(wreq);
				free(blob_hex);
			}
		}
			free(buf);
		}
	}

	/* Save breach data for current epoch */
	for (size_t i = 0; i < fi->n_breach_epochs; i++) {
		ss_persist_key_breach(fi, fi->breach_data[i].epoch,
				      key, sizeof(key));
		len = ss_persist_serialize_breach(&fi->breach_data[i], &buf);
		if (len > 0 && buf) {
			/* Task #72: dual-write breach blob to wallet plugin. */
			{
				char wiid[65];
				for (int j = 0; j < 32; j++)
					sprintf(wiid + j*2, "%02x", fi->instance_id[j]);
				wiid[64] = 0;
				char wkey[160];
				snprintf(wkey, sizeof wkey, "factory_blob:%s:breach:%u",
					 wiid, fi->breach_data[i].epoch);
				char *blob_hex = malloc(len * 2 + 1);
				if (blob_hex) {
					for (size_t bi = 0; bi < len; bi++)
						sprintf(blob_hex + bi*2, "%02x", buf[bi]);
					blob_hex[len * 2] = 0;
					struct out_req *wreq = jsonrpc_request_start(cmd,
						"wallet-set-setting", rpc_done, rpc_err, NULL);
					json_add_string(wreq->js, "setting_key", wkey);
					json_add_string(wreq->js, "setting_value", blob_hex);
					send_outreq(wreq);
					free(blob_hex);
				}
			}
			free(buf);
		}
	}

	/* Save breach index: count(2) + epoch0(4) + epoch1(4) + ...
	 * Lets ss_load_factories enumerate saved epochs without listdatastore. */
	if (fi->n_breach_epochs > 0) {
		size_t bi_len = 2 + fi->n_breach_epochs * 4;
		uint8_t *bi_buf = malloc(bi_len);
		if (bi_buf) {
			bi_buf[0] = (fi->n_breach_epochs >> 8) & 0xFF;
			bi_buf[1] = fi->n_breach_epochs & 0xFF;
			for (size_t i = 0; i < fi->n_breach_epochs; i++) {
				uint32_t ep = fi->breach_data[i].epoch;
				bi_buf[2 + i*4]     = (ep >> 24) & 0xFF;
				bi_buf[2 + i*4 + 1] = (ep >> 16) & 0xFF;
				bi_buf[2 + i*4 + 2] = (ep >>  8) & 0xFF;
				bi_buf[2 + i*4 + 3] = ep & 0xFF;
			}
			ss_persist_key_breach_index(fi, key, sizeof(key));
			/* Task #72: dual-write breach-index blob to wallet plugin. */
			{
				char wiid[65];
				for (int j = 0; j < 32; j++)
					sprintf(wiid + j*2, "%02x", fi->instance_id[j]);
				wiid[64] = 0;
				char wkey[160];
				snprintf(wkey, sizeof wkey,
					 "factory_blob:%s:breach-index", wiid);
				char *blob_hex = malloc(bi_len * 2 + 1);
				if (blob_hex) {
					for (size_t bi = 0; bi < bi_len; bi++)
						sprintf(blob_hex + bi*2, "%02x", bi_buf[bi]);
					blob_hex[bi_len * 2] = 0;
					struct out_req *wreq = jsonrpc_request_start(cmd,
						"wallet-set-setting", rpc_done, rpc_err, NULL);
					json_add_string(wreq->js, "setting_key", wkey);
					json_add_string(wreq->js, "setting_value", blob_hex);
					send_outreq(wreq);
					free(blob_hex);
				}
			}
			free(bi_buf);
		}
	}

	/* Update factory index — list of all known instance IDs.
	 * Format: count(2) + instance_ids(32 each) */
	size_t idx_len = 2 + ss_state.n_factories * 32;
	uint8_t *idx_buf = calloc(1, idx_len);
	idx_buf[0] = (ss_state.n_factories >> 8) & 0xFF;
	idx_buf[1] = ss_state.n_factories & 0xFF;
	for (size_t i = 0; i < ss_state.n_factories; i++)
		memcpy(idx_buf + 2 + i * 32,
		       ss_state.factories[i]->instance_id, 32);
	free(idx_buf);

	/* Task #72: dual-write the current factory's user-perspective row to
	 * the soupwallet CLN plugin. Per-factory upsert (the wallet plugin's
	 * factories table mirrors the datastore index by accumulating these
	 * upserts). Best-effort; an error here doesn't affect the canonical
	 * datastore write above. */
	{
		char iid_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(iid_hex + j*2, "%02x", fi->instance_id[j]);
		iid_hex[64] = 0;
		struct out_req *wreq = jsonrpc_request_start(cmd,
			"wallet-upsert-factory",
			rpc_done, rpc_err, NULL);
		json_add_string(wreq->js, "factory_instance_id_hex", iid_hex);
		json_add_u32(wreq->js, "my_role", fi->is_lsp ? 1 : 0);
		json_add_u32(wreq->js, "created_at_block", ss_state.current_blockheight);
		json_add_u32(wreq->js, "state", (u32)fi->lifecycle);
		json_add_u32(wreq->js, "archived", 0);
		send_outreq(wreq);
	}

	/* Save signed DW tree transactions (for force-close after restart).
	 * Both LSP and client persist independently — each must be able
	 * to unilaterally exit without the other's cooperation. */
	if (fi->lib_factory) {
		ss_persist_key_signed_txs(fi, key, sizeof(key));
		len = ss_persist_serialize_signed_txs(fi->lib_factory, &buf);
		if (len > 0 && buf) {
		/* Task #72: dual-write signed-txs blob to soupwallet plugin. */
		{
			char wiid[65];
			for (int j = 0; j < 32; j++)
				sprintf(wiid + j*2, "%02x", fi->instance_id[j]);
			wiid[64] = 0;
			char wkey[160];
			snprintf(wkey, sizeof wkey, "factory_blob:%s:signed-txs", wiid);
			char *blob_hex = malloc(len * 2 + 1);
			if (blob_hex) {
				for (size_t bi = 0; bi < len; bi++)
					sprintf(blob_hex + bi*2, "%02x", buf[bi]);
				blob_hex[len * 2] = 0;
				struct out_req *wreq = jsonrpc_request_start(cmd,
					"wallet-set-setting", rpc_done, rpc_err, NULL);
				json_add_string(wreq->js, "setting_key", wkey);
				json_add_string(wreq->js, "setting_value", blob_hex);
				send_outreq(wreq);
				free(blob_hex);
			}
		}
			free(buf);
		}
	}

	/* Save signed distribution TX (inverted timeout default).
	 * After expiry, this TX gives clients their funds without LSP. */
	if (fi->dist_signed_tx && fi->dist_signed_tx_len > 0) {
		ss_persist_key_dist_tx(fi, key, sizeof(key));
		len = ss_persist_serialize_dist_tx(fi, &buf);
		if (len > 0 && buf) {
		/* Task #72: dual-write dist-tx blob to soupwallet plugin. */
		{
			char wiid[65];
			for (int j = 0; j < 32; j++)
				sprintf(wiid + j*2, "%02x", fi->instance_id[j]);
			wiid[64] = 0;
			char wkey[160];
			snprintf(wkey, sizeof wkey, "factory_blob:%s:dist-tx", wiid);
			char *blob_hex = malloc(len * 2 + 1);
			if (blob_hex) {
				for (size_t bi = 0; bi < len; bi++)
					sprintf(blob_hex + bi*2, "%02x", buf[bi]);
				blob_hex[len * 2] = 0;
				struct out_req *wreq = jsonrpc_request_start(cmd,
					"wallet-set-setting", rpc_done, rpc_err, NULL);
				json_add_string(wreq->js, "setting_key", wkey);
				json_add_string(wreq->js, "setting_value", blob_hex);
				send_outreq(wreq);
				free(blob_hex);
			}
		}
			free(buf);
		}
	}

	/* Phase 3: persist LSP-side join queue (only meaningful for is_lsp).
	 * Empty queues are still saved (as a 3-byte header) so loaders can
	 * distinguish "no entries yet" from "factory not yet seen at all". */
	if (fi->is_lsp) {
		ss_persist_key_join_queue(fi, key, sizeof(key));
		len = ss_persist_serialize_join_queue(fi, &buf);
		if (len > 0 && buf) {
			free(buf);
		} else if (fi->n_join_queue == 0) {
			uint8_t empty[3] = { SS_JOIN_SCHEMA_V1, 0, 0 };
		}

		/* Task #72: dual-write each join_queue entry to the soupwallet
		 * plugin. Per-entry upserts (wallet's lsp_join_queue table
		 * mirrors the blob). Best-effort; failures here don't affect
		 * the canonical datastore write above. */
		char fiid_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(fiid_hex + j*2, "%02x", fi->instance_id[j]);
		fiid_hex[64] = 0;
		for (size_t k = 0; k < fi->n_join_queue; k++) {
			const factory_join_t *jq = &fi->join_queue[k];
			char cpk_hex[67];
			for (int j = 0; j < 33; j++)
				sprintf(cpk_hex + j*2, "%02x", jq->client_node_id[j]);
			cpk_hex[66] = 0;
			char req_id_str[24], contrib_str[24];
			snprintf(req_id_str, sizeof req_id_str, "%llu",
				 (unsigned long long)jq->request_id);
			snprintf(contrib_str, sizeof contrib_str, "%llu",
				 (unsigned long long)jq->contribution_sats);
			struct out_req *wreq = jsonrpc_request_start(cmd,
				"wallet-upsert-join-queue-entry",
				rpc_done, rpc_err, NULL);
			json_add_string(wreq->js, "factory_instance_id_hex", fiid_hex);
			json_add_string(wreq->js, "client_pubkey_hex", cpk_hex);
			json_add_string(wreq->js, "request_id", req_id_str);
			json_add_string(wreq->js, "contribution_sats", contrib_str);
			json_add_u32(wreq->js, "received_at_block",
				     jq->received_at_block);
			if (jq->accepted_at_block)
				json_add_u32(wreq->js, "accepted_at_block",
					     jq->accepted_at_block);
			if (jq->decided_at_block)
				json_add_u32(wreq->js, "decided_at_block",
					     jq->decided_at_block);
			if (jq->last_seen_block)
				json_add_u32(wreq->js, "last_seen_block",
					     jq->last_seen_block);
			json_add_u32(wreq->js, "status", (u32)jq->status);
			if (jq->reason[0])
				json_add_string(wreq->js, "reason",
						(const char *)jq->reason);
			send_outreq(wreq);
		}
		if (0) {
		}
	}

	plugin_log(plugin_handle, LOG_DBG,
		   "Persisted factory state (epoch=%u, channels=%zu, "
		   "join_queue=%zu)",
		   fi->epoch, fi->n_channels, fi->n_join_queue);
}

/* Load factories from CLN datastore on startup.
 * Reads factory-index key to discover instance IDs, then
 * loads each factory's meta and channel mappings. */
/* Task #72 (transitional): persist the monotonic iid counter to BOTH the
 * CLN datastore (legacy path, still authoritative for restart-load) AND
 * the soupwallet CLN plugin (new path, warming up). Once we migrate the
 * load path off the datastore (lazy-load at first factory-create), the
 * datastore write here can be dropped and the wallet plugin becomes the
 * sole authority. */
static void ss_save_iid_counter(struct command *cmd)
{
	/* Legacy: write to CLN datastore. */
	u8 buf[4];
	buf[0] = ss_state.factory_counter & 0xFF;
	buf[1] = (ss_state.factory_counter >> 8) & 0xFF;
	buf[2] = (ss_state.factory_counter >> 16) & 0xFF;
	buf[3] = (ss_state.factory_counter >> 24) & 0xFF;

	/* New: push to wallet plugin (best-effort; an error here doesn't
	 * affect the canonical datastore write above). */
	struct out_req *req = jsonrpc_request_start(cmd,
		"wallet-set-iid-counter",
		rpc_done, rpc_err, NULL);
	json_add_u32(req->js, "counter", ss_state.factory_counter);
	send_outreq(req);
}

/* Load the iid counter at plugin init. If no prior value exists
 * (fresh plugin or never-written), start from 0 and mark loaded so
 * subsequent factory-creates save after increment. Called before
 * ss_load_factories so the counter is ready for any early work.
 *
 * Task #72 (transitional): reads from the CLN datastore (the historical
 * location). Future PR migrates this to wallet-get-iid-counter via lazy-
 * load at first factory-create — the init cmd context doesn't survive
 * the async wallet RPC reply (libplugin reports "JSON reply with unknown
 * id"). The save side already dual-writes; once load is migrated, the
 * datastore write can be dropped. */
static void ss_load_iid_counter(struct command *cmd)
{
	(void)cmd;  /* unused — wallet.db read is synchronous */
	ss_state.factory_counter = 0;
	sqlite3 *db = ss_open_wallet_db_ro(tmpctx);
	if (db) {
		sqlite3_stmt *st = NULL;
		if (sqlite3_prepare_v2(db,
			"SELECT counter FROM iid_counter WHERE id = 0",
			-1, &st, NULL) == SQLITE_OK) {
			if (sqlite3_step(st) == SQLITE_ROW) {
				int64_t v = sqlite3_column_int64(st, 0);
				if (v > 0)
					ss_state.factory_counter = (uint32_t)v;
			}
			sqlite3_finalize(st);
		}
		sqlite3_close(db);
	}
	plugin_log(plugin_handle, LOG_INFORM,
		   "Loaded iid counter from wallet.db: %u",
		   ss_state.factory_counter);
	ss_state.has_counter_loaded = true;
}

/* Gap 7: funding-pending chain reconciliation.
 *
 * After a crash between `withdraw` broadcast and txid persistence, a
 * factory loads with funding_spk set but funding_txid all-zeros. The
 * funds are recoverable on-chain — we just need to find which TX paid
 * the expected address. Rather than make the operator resolve manually,
 * walk the wallet's transaction history (`listtransactions`) and match
 * any output's scriptPubKey against fi->funding_spk. On a match: fill
 * in funding_txid + funding_outnum and persist.
 *
 * Best-effort. If the TX is not in the wallet (foreign-funded factory)
 * or the wallet was wiped, the factory stays in funding-pending state
 * and the existing operator-facing log line still fires. */
struct reconcile_ctx {
	factory_instance_t *fi;
};

static struct command_result *
ss_reconcile_listtx_ok(struct command *cmd, const char *method,
		       const char *buf, const jsmntok_t *result,
		       void *arg)
{
	struct reconcile_ctx *rc = (struct reconcile_ctx *)arg;
	factory_instance_t *fi = rc->fi;

	const jsmntok_t *txs = json_get_member(buf, result, "transactions");
	if (!txs || txs->type != JSMN_ARRAY) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "Reconcile: listtransactions response missing "
			   "transactions[] for fi=%p", (void *)fi);
		free(rc);
		return command_finished(cmd, result);
	}

	/* Hex-encode the expected scriptPubKey for substring compare. */
	char exp_spk_hex[34*2 + 1] = {0};
	for (size_t k = 0; k < fi->funding_spk_len && k < 34; k++)
		sprintf(exp_spk_hex + k*2, "%02x", fi->funding_spk[k]);

	const jsmntok_t *tx;
	size_t ti;
	bool found = false;
	json_for_each_arr(ti, tx, txs) {
		const jsmntok_t *outs = json_get_member(buf, tx, "outputs");
		if (!outs || outs->type != JSMN_ARRAY) continue;
		const jsmntok_t *o;
		size_t oi;
		json_for_each_arr(oi, o, outs) {
			const jsmntok_t *spk_t =
				json_get_member(buf, o, "scriptPubKey");
			if (!spk_t) continue;
			/* Hex-compare; CLN emits lowercase hex. */
			if ((size_t)(spk_t->end - spk_t->start) !=
			    strlen(exp_spk_hex))
				continue;
			if (strncmp(buf + spk_t->start, exp_spk_hex,
				    strlen(exp_spk_hex)) != 0)
				continue;
			/* Match — pull txid (display order) and vout. */
			const jsmntok_t *txid_t =
				json_get_member(buf, tx, "hash");
			if (!txid_t)
				txid_t = json_get_member(buf, tx, "txid");
			const jsmntok_t *vout_t =
				json_get_member(buf, o, "index");
			if (!txid_t || !vout_t) continue;
			char txid_hex[65] = {0};
			size_t tlen = txid_t->end - txid_t->start;
			if (tlen != 64) continue;
			memcpy(txid_hex, buf + txid_t->start, 64);
			/* Reverse hex into internal byte order. */
			for (int j = 0; j < 32; j++) {
				unsigned int b;
				sscanf(txid_hex + j*2, "%02x", &b);
				fi->funding_txid[31 - j] = (uint8_t)b;
			}
			u64 vout;
			if (!json_to_u64(buf, vout_t, &vout)) continue;
			fi->funding_outnum = (uint32_t)vout;
			found = true;
			plugin_log(plugin_handle, LOG_INFORM,
				   "Reconciled funding-pending factory: "
				   "txid=%.64s outnum=%u",
				   buf + txid_t->start, fi->funding_outnum);
			break;
		}
		if (found) break;
	}

	if (found) {
		/* Persist updated meta so the next load sees the txid. */
		ss_save_factory(cmd, fi);
	} else {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "Reconcile: no wallet TX matches funding_spk; "
			   "factory stays in funding-pending state");
	}
	free(rc);
	return command_finished(cmd, result);
}

static struct command_result *
ss_reconcile_listtx_err(struct command *cmd, const char *method,
			const char *buf, const jsmntok_t *err, void *arg)
{
	struct reconcile_ctx *rc = (struct reconcile_ctx *)arg;
	plugin_log(plugin_handle, LOG_UNUSUAL,
		   "Reconcile: listtransactions failed: %.*s",
		   err ? err->end - err->start : 0,
		   err ? buf + err->start : "");
	free(rc);
	return command_finished(cmd, err);
}

static void ss_reconcile_funding_pending(struct command *cmd,
					 factory_instance_t *fi)
{
	struct reconcile_ctx *rc = malloc(sizeof(*rc));
	if (!rc) return;
	rc->fi = fi;
	struct out_req *req = jsonrpc_request_start(cmd,
		"listtransactions",
		ss_reconcile_listtx_ok, ss_reconcile_listtx_err, rc);
	send_outreq(req);
}


/* ============================================================================
 * Audit #5 follow-up: log the resolved wallet.db path at startup so the
 * plugin <-> sidecar path agreement is operator-verifiable.
 *
 * The soupwallet-cln-plugin sidecar writes coordination state to a SQLite
 * file. This C plugin reads from that same file at startup via
 * ss_load_factories. They must agree on the path.
 *
 * Each plugin has its own option that resolves to a path:
 *   - Sidecar:     `soupwallet-db-path=`        (where it writes)
 *   - This plugin: `superscalar-wallet-db=`     (where we read)
 *
 * Both fall back to `~/.config/soupwallet/wallet.db`. If only one is set,
 * they silently diverge. We log our resolved path at INFORM so the
 * operator can grep both plugins' init logs and verify they match. If
 * we resolved to the fallback path (no explicit option), we log at
 * UNUSUAL since that's the foot-gun.
 * ============================================================================ */
static void ss_log_resolved_db_path(void)
{
	const char *p = ss_resolve_wallet_db_path(tmpctx);
	bool is_default_fallback = (ss_wallet_db_path_override == NULL
				    || ss_wallet_db_path_override[0] == '\0')
				   && getenv("SUPERSCALAR_WALLET_DB_PATH") == NULL;

	if (is_default_fallback) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "wallet.db path resolved to %s via default fallback. "
			   "If using the soupwallet-cln-plugin sidecar, set "
			   "superscalar-wallet-db=<path> explicitly so it matches "
			   "the sidecar's soupwallet-db-path option.",
			   p ? p : "(null)");
	} else {
		plugin_log(plugin_handle, LOG_INFORM,
			   "wallet.db path: %s. Ensure sidecar's "
			   "soupwallet-db-path option matches.",
			   p ? p : "(null)");
	}
}

static void ss_load_factories(struct command *cmd)
{
	(void)cmd;  /* unused — all reads go through wallet.db directly */
	size_t loaded = 0;

	/* PR Task #84: enumerate factories from wallet.db `factories` table
	 * instead of the legacy "superscalar/factory-index" blob. We collect
	 * all instance_ids upfront so we can close the db handle before the
	 * (per-factory) blob loads — each blob read re-opens wallet.db. */
	struct iid32 { uint8_t b[32]; };
	struct iid32 *iids = NULL;
	size_t n_iids = 0;
	{
		sqlite3 *db = ss_open_wallet_db_ro(tmpctx);
		if (db) {
			sqlite3_stmt *st = NULL;
			if (sqlite3_prepare_v2(db,
				"SELECT factory_instance_id FROM factories WHERE archived = 0 "
				"ORDER BY created_at_block",
				-1, &st, NULL) == SQLITE_OK) {
				size_t cap = 16;
				iids = tal_arr(tmpctx, struct iid32, cap);
				while (sqlite3_step(st) == SQLITE_ROW) {
					const void *b = sqlite3_column_blob(st, 0);
					int blen = sqlite3_column_bytes(st, 0);
					if (blen != 32 || !b) continue;
					if (n_iids >= cap) {
						cap *= 2;
						tal_resize(&iids, cap);
					}
					memcpy(iids[n_iids++].b, b, 32);
				}
				sqlite3_finalize(st);
			}
			sqlite3_close(db);
		}
	}

	if (n_iids > 0) {
		{
			for (size_t i = 0; i < n_iids; i++) {
				const u8 *p = iids[i].b;
				char id_hex[65];
				for (int j = 0; j < 32; j++)
					sprintf(id_hex + j*2, "%02x", p[j]);
				id_hex[64] = '\0';

				/* Load meta blob from wallet.db */
				char setting_key[160];
				snprintf(setting_key, sizeof(setting_key),
					 "factory_blob:%s:meta", id_hex);
				size_t fmeta_len = 0;
				u8 *fmeta = ss_wallet_db_load_blob_tal(
					tmpctx, setting_key, &fmeta_len);
				if (!fmeta) {
					continue;
				}

				/* Deserialize */
				factory_instance_t *fi = ss_factory_new(
					&ss_state, p);
				if (!fi) {
					continue;
				}

				if (!ss_persist_deserialize_meta(fi,
					fmeta, fmeta_len)) {
					plugin_log(plugin_handle, LOG_UNUSUAL,
						   "Failed to deserialize "
						   "factory %s", id_hex);
					continue;
				}

				/* Task #97: re-derive fi->our_seckey from
				 * (instance_id, our_participant_idx). The
				 * seckey is intentionally NOT persisted in
				 * meta — it's regenerable from the HSM-
				 * derived factory key + our slot. Pre-#97 it
				 * stayed zero after restart, breaking any RPC
				 * that called secp256k1_ec_pubkey_create on
				 * fi->our_seckey (factory-buy-liquidity, the
				 * coop close path, etc.). Discovered during
				 * the Tier 2.6 signet deploy — all old
				 * factories on the VPS were silently
				 * unsignable until the next live ceremony
				 * write set it again. */
				derive_factory_seckey(fi->our_seckey,
						      fi->instance_id,
						      fi->our_participant_idx);

				/* Audit #5 follow-up: reset in-flight ceremony state.
				 * The in-memory MuSig2 session_t isn't persisted (lib task
				 * #80). A factory loaded mid-ceremony would otherwise
				 * accept incoming NONCE_BUNDLE/PSIG_BUNDLE and then panic
				 * at factory_sessions_finalize. Mark it FAILED and reset
				 * lifecycle to AWAITING_JOINS so the operator can re-fire
				 * factory-trigger-ceremony.
				 *
				 * Integration point for lib task #80: when
				 * factory_restore_sessions() ships and
				 * --enable-session-restore=true, replace this block with:
				 *     if (factory_restore_sessions(f, tx)) continue;
				 * and fall through to the reset only on restore failure
				 * (defense in depth). See LIB_TEAM_REPLY_MUSIG_PERSISTENCE.md.
				 */
				if (fi->ceremony == CEREMONY_PROPOSED
				    || fi->ceremony == CEREMONY_FUNDING_PENDING
				    || fi->ceremony == CEREMONY_NONCES_COLLECTED
				    || fi->ceremony == CEREMONY_PSIGS_COLLECTED
				    || fi->ceremony == CEREMONY_ROTATING) {
					if (ss_enable_session_restore) {
						plugin_log(plugin_handle, LOG_UNUSUAL,
							   "Factory %s: --enable-session-restore=true "
							   "but lib factory_restore_sessions() not yet "
							   "linked; falling through to interim reset. "
							   "Tracks SF-LIB-MUSIG-PERSIST.",
							   id_hex);
					} else {
						plugin_log(plugin_handle, LOG_UNUSUAL,
							   "Factory %s loaded with in-flight "
							   "ceremony=%d; resetting to FAILED + "
							   "AWAITING_JOINS (session not resumable "
							   "across restart; lib task #80). Operator "
							   "can re-fire factory-trigger-ceremony.",
							   id_hex, (int)fi->ceremony);
					}
					fi->ceremony = CEREMONY_FAILED;
					if (fi->is_lsp)
						fi->lifecycle = FACTORY_LIFECYCLE_AWAITING_JOINS;
				}

				/* Load channel mappings from wallet.db */
				{
					char ch_key[160];
					snprintf(ch_key, sizeof(ch_key),
						"factory_blob:%s:channels", id_hex);
					size_t chlen = 0;
					u8 *chdata = ss_wallet_db_load_blob_tal(
						tmpctx, ch_key, &chlen);
					if (chdata)
						ss_persist_deserialize_channels(fi,
							chdata, chlen);
				}

				/* Load breach data from wallet.db */
				{
				char bi_key[160];
				snprintf(bi_key, sizeof(bi_key),
					"factory_blob:%s:breach-index", id_hex);
				size_t bi_len = 0;
				u8 *bidata = ss_wallet_db_load_blob_tal(
					tmpctx, bi_key, &bi_len);
				if (bidata) {
					if (bi_len >= 2) {
						uint16_t bn = ((uint16_t)bidata[0] << 8)
								| bidata[1];
						for (uint16_t bi = 0;
						     bi < bn
						     && bi_len >= (size_t)(2 + (bi+1)*4);
						     bi++) {
							uint32_t ep =
							    ((uint32_t)bidata[2+bi*4] << 24)
							    | ((uint32_t)bidata[2+bi*4+1] << 16)
							    | ((uint32_t)bidata[2+bi*4+2] << 8)
							    | bidata[2+bi*4+3];
							char breach_key[160];
							snprintf(breach_key, sizeof(breach_key),
								 "factory_blob:%s:breach:%u",
								 id_hex, ep);
							size_t bdlen = 0;
							u8 *bdata = ss_wallet_db_load_blob_tal(
								tmpctx, breach_key, &bdlen);
							if (bdata) {
								epoch_breach_data_t bd;
								memset(&bd, 0, sizeof(bd));
								if (ss_persist_deserialize_breach(
									&bd, bdata, bdlen)) {
									ss_factory_add_breach_data(
										fi, bd.epoch,
										bd.has_revocation
										  ? bd.revocation_secret
										  : NULL,
										bd.commitment_data,
										bd.commitment_data_len);
								}
								if (bd.commitment_data)
									free(bd.commitment_data);
							}
						}
					}
				}
				}

				/* PR Task #84: load LSP-side join queue from
				 * wallet.db lsp_join_queue table (one row per joiner). */
				if (fi->is_lsp) {
					sqlite3 *jdb = ss_open_wallet_db_ro(tmpctx);
					if (jdb) {
						sqlite3_stmt *jst = NULL;
						const char *jsql =
							"SELECT client_pubkey, request_id, "
							"       contribution_sats, received_at_block, "
							"       accepted_at_block, decided_at_block, "
							"       last_seen_block, status, reason "
							"FROM lsp_join_queue "
							"WHERE factory_instance_id = ? "
							"ORDER BY received_at_block";
						if (sqlite3_prepare_v2(jdb, jsql, -1, &jst, NULL) == SQLITE_OK) {
							sqlite3_bind_blob(jst, 1, fi->instance_id, 32, SQLITE_TRANSIENT);
							while (sqlite3_step(jst) == SQLITE_ROW
							       && fi->n_join_queue < MAX_JOIN_QUEUE) {
								factory_join_t *j = &fi->join_queue[fi->n_join_queue];
								memset(j, 0, sizeof(*j));
								const void *pk = sqlite3_column_blob(jst, 0);
								int pklen = sqlite3_column_bytes(jst, 0);
								if (pklen != 33) continue;
								memcpy(j->client_node_id, pk, 33);
								j->request_id = (uint64_t)sqlite3_column_int64(jst, 1);
								j->contribution_sats = (uint64_t)sqlite3_column_int64(jst, 2);
								j->received_at_block = (uint32_t)sqlite3_column_int64(jst, 3);
								if (sqlite3_column_type(jst, 4) != SQLITE_NULL)
									j->accepted_at_block = (uint32_t)sqlite3_column_int64(jst, 4);
								if (sqlite3_column_type(jst, 5) != SQLITE_NULL)
									j->decided_at_block = (uint32_t)sqlite3_column_int64(jst, 5);
								if (sqlite3_column_type(jst, 6) != SQLITE_NULL)
									j->last_seen_block = (uint32_t)sqlite3_column_int64(jst, 6);
								j->status = (factory_join_status_t)sqlite3_column_int(jst, 7);
								const unsigned char *rs = sqlite3_column_text(jst, 8);
								if (rs) {
									size_t rl = strlen((const char *)rs);
									if (rl >= sizeof(j->reason)) rl = sizeof(j->reason) - 1;
									memcpy(j->reason, rs, rl);
								}
								fi->n_join_queue++;
							}
							sqlite3_finalize(jst);
						}
						sqlite3_close(jdb);
					}
				}

				loaded++;
				plugin_log(plugin_handle, LOG_INFORM,
					   "Loaded factory %s (epoch=%u, "
					   "channels=%zu, breach_epochs=%zu, "
					   "lifecycle=%d, join_queue=%zu)",
					   id_hex, fi->epoch,
					   fi->n_channels, fi->n_breach_epochs,
					   fi->lifecycle, fi->n_join_queue);

				/* Rebuild factory_t from persisted data so
				 * rotation/force-close work after restart. */
				if (!fi->lib_factory) {
					size_t n_total;
					if (fi->n_clients > 0)
						n_total = 1 + fi->n_clients;
					else if (fi->n_tree_nodes == 2)
						n_total = 2;
					else
						n_total = 0;
					if (n_total == 0) goto skip_rebuild;
					secp256k1_pubkey *pks = calloc(
						n_total, sizeof(secp256k1_pubkey));
					bool ok = pks != NULL;
					if (ok) {
						unsigned char sk[32];
						derive_factory_seckey(sk,
							fi->instance_id,
							fi->is_lsp ? 0
							: fi->our_participant_idx);
						ok = secp256k1_ec_pubkey_create(
							global_secp_ctx,
							&pks[fi->is_lsp ? 0
							     : fi->our_participant_idx],
							sk) != 0;
					}
					if (fi->n_clients > 0) {
						for (size_t ci = 0; ci < fi->n_clients
						     && ok; ci++) {
							/* LSP-side: clients[ci] = signer at slot ci+1.
							 * Client-side: clients[ci].signer_slot
							 * carries the actual slot (0=LSP,
							 * peers at their factory-wide indices).
							 * Skip our own slot — already filled
							 * with the derived seckey above. */
							int slot = fi->is_lsp
								? (int)(ci + 1)
								: fi->clients[ci].signer_slot;
							if (!fi->is_lsp
							    && slot == fi->our_participant_idx)
								continue;
							if (slot < 0 || slot >= (int)n_total)
								continue;
							if (fi->clients[ci].has_factory_pubkey) {
								ok = secp256k1_ec_pubkey_parse(
									global_secp_ctx,
									&pks[slot],
									fi->clients[ci].factory_pubkey,
									33) != 0;
							} else {
								unsigned char psk[32];
								derive_placeholder_seckey(
									psk,
									fi->instance_id,
									slot);
								ok = secp256k1_ec_pubkey_create(
									global_secp_ctx,
									&pks[slot],
									psk) != 0;
							}
						}
					} else if (!fi->is_lsp && n_total == 2) {
						/* Client: fill LSP slot (0) from
						 * lsp_node_id or placeholder */
						if (fi->lsp_node_id[0] != 0) {
							ok = secp256k1_ec_pubkey_parse(
								global_secp_ctx,
								&pks[0],
								fi->lsp_node_id,
								33) != 0;
						} else {
							unsigned char psk[32];
							derive_placeholder_seckey(
								psk, fi->instance_id, 0);
							ok = secp256k1_ec_pubkey_create(
								global_secp_ctx,
								&pks[0], psk) != 0;
						}
					}
					if (ok) {
						factory_t *f = calloc(1,
							sizeof(factory_t));
						factory_init_from_pubkeys(f,
							global_secp_ctx,
							pks, n_total,
							DW_STEP_BLOCKS, 16);
						factory_set_arity(f,
							ss_effective_arity(fi));
						if (fi->funding_spk_len > 0) {
							factory_set_funding(f,
								fi->funding_txid,
								fi->funding_outnum,
								fi->funding_amount_sats,
								fi->funding_spk,
								fi->funding_spk_len);
						} else {
							uint8_t syn_txid[32];
							uint8_t syn_spk[34];
							for (int j=0; j<32; j++)
								syn_txid[j] = j+1;
							syn_spk[0]=0x51;
							syn_spk[1]=0x20;
							memset(syn_spk+2,0xAA,32);
							factory_set_funding(f,
								syn_txid, 0,
								fi->funding_amount_sats > 0
								? fi->funding_amount_sats
								: 500000,
								syn_spk, 34);
						}
						factory_set_lifecycle(f,
							fi->creation_block,
							4320, 432);
						if (factory_build_tree(f)) {
							apply_allocations_to_leaves(
								fi, f, n_total);
							fi->lib_factory = f;
							fi->n_tree_nodes =
								(uint32_t)f->n_nodes;
							/* Gap 9: restore persisted
							 * keyagg cache snapshots
							 * onto the rebuilt tree.
							 * No-op if the meta record
							 * predates v15 or no
							 * blob was captured. */
							ss_keyagg_snapshot_restore(fi);
							/* Load signed TXs from wallet.db */
							{
							char stx_key[160];
							snprintf(stx_key, sizeof(stx_key),
								"factory_blob:%s:signed-txs", id_hex);
							size_t stx_len = 0;
							u8 *stx_data = ss_wallet_db_load_blob_tal(
								tmpctx, stx_key, &stx_len);
							if (stx_data && stx_len > 0) {
								ss_persist_deserialize_signed_txs(
									f, stx_data, stx_len);
								plugin_log(plugin_handle, LOG_INFORM,
									"Loaded signed TXs from wallet.db (%zu bytes)",
									stx_len);
							}
							}

							/* Tier 2.6 PS leaf chain replay: Task #84
							 * follow-up — not yet migrated to wallet.db,
							 * so the loop body is disabled. On wallets
							 * that never used PS leaves this is a no-op;
							 * PS leaves rely on libsuperscalar persist_t
							 * for their own state. Re-enable once a
							 * wallet-set-setting key shape is wired for
							 * PS chain entries. */
							{
							for (int li = 0; 0 && li < f->n_leaf_nodes; li++) {
								size_t nidx = f->leaf_node_indices[li];
								if (nidx >= f->n_nodes) continue;
								if (!f->nodes[nidx].is_ps_leaf) continue;
								factory_node_t *nd = &f->nodes[nidx];
								uint8_t last_txid[32] = {0};
								uint64_t last_amt = 0;
								int loaded = 0;
								for (uint32_t cp = 0; cp < 1024; cp++) {
									/* PS-chain read disabled (Task #84). */
									u8 *pdata = NULL;
									if (!pdata) break;
									size_t plen = 0;
									if (plen == 0) break;
									uint8_t etxid[32];
									uint64_t eamt;
									uint8_t *etx = NULL;
									size_t etx_len = 0;
									if (!ss_persist_deserialize_ps_chain_entry(
										pdata, plen, etxid, &eamt,
										&etx, &etx_len))
										break;
									if (cp > 0) {
										memcpy(nd->ps_prev_txid,
										       last_txid, 32);
										nd->ps_prev_chan_amount = last_amt;
									}
									nd->ps_chain_len = (int)cp;
									if (nd->signed_tx.data)
										free(nd->signed_tx.data);
									nd->signed_tx.data = etx;
									nd->signed_tx.len = etx_len;
									nd->signed_tx.cap = etx_len;
									nd->is_signed = 1;
									memcpy(nd->txid, etxid, 32);
									if (nd->n_outputs > 0)
										nd->outputs[0].amount_sats = eamt;
									memcpy(last_txid, etxid, 32);
									last_amt = eamt;
									loaded++;
								}
								if (loaded > 0)
									plugin_log(plugin_handle, LOG_INFORM,
										"Loaded %d PS chain entries for "
										"leaf %d (node %zu), current "
										"chain_len=%d",
										loaded, li, nidx,
										nd->ps_chain_len);
							}
							}

							/* Fix early_warning_time
							 * for old factories */
							if (fi->early_warning_time == 0)
								fi->early_warning_time =
									compute_early_warning_time(
										n_total > 1
										? n_total - 1 : 1,
										ss_effective_arity(fi));
							plugin_log(plugin_handle,
								LOG_INFORM,
								"Rebuilt factory tree "
								"(%zu nodes, ewt=%u)",
								f->n_nodes,
								fi->early_warning_time);
						} else {
							free(f);
						}
					}
					free(pks);
				}
				skip_rebuild:

				/* Load signed distribution TX from wallet.db */
				{
					char dtx_key[160];
					snprintf(dtx_key, sizeof(dtx_key),
						"factory_blob:%s:dist-tx", id_hex);
					size_t dtx_len = 0;
					u8 *dtx_data = ss_wallet_db_load_blob_tal(
						tmpctx, dtx_key, &dtx_len);
					if (dtx_data) {
						if (dtx_len > 0 &&
						    ss_persist_deserialize_dist_tx(
							fi, dtx_data, dtx_len)) {
							plugin_log(plugin_handle,
								LOG_INFORM,
								"Loaded dist TX "
								"(%zu bytes)",
								fi->dist_signed_tx_len);
							/* Phase 2b: precompute
							 * txid on load so the
							 * classifier can match. */
							ss_compute_dist_signed_txid(fi);
						}
					}
				}

			}
		}
	}

	plugin_log(plugin_handle, LOG_INFORM,
		   "Loaded %zu factories from wallet.db", loaded);

	/* Reconcile factories that may have been mid-creation at shutdown.
	 * A factory is "funding-pending" if we persisted its meta (so we
	 * know the instance_id and expected funding_spk) but the
	 * funding_txid is still all-zeros — meaning the withdraw RPC hadn't
	 * returned when the plugin last exited, or the callback hadn't
	 * finished writing. Log these loudly so the operator can check
	 * on-chain whether the funding TX actually went out; if it did,
	 * the funds are recoverable because we have every non-chain piece
	 * of state (participants, iid, funding_spk). Before this PR those
	 * factories became unrecoverable: instance_id was only in memory,
	 * so the keys needed to spend the funding UTXO were lost on any
	 * crash between withdraw-broadcast and persistence. */
	for (size_t i = 0; i < ss_state.n_factories; i++) {
		factory_instance_t *fi = ss_state.factories[i];
		if (!fi || !fi->is_lsp) continue;
		bool txid_zero = true;
		for (int j = 0; j < 32 && txid_zero; j++)
			if (fi->funding_txid[j] != 0) txid_zero = false;
		if (txid_zero && fi->funding_spk_len == 34) {
			char iid_hex[65];
			for (int j = 0; j < 32; j++)
				sprintf(iid_hex + j*2, "%02x", fi->instance_id[j]);
			iid_hex[64] = '\0';
			char addr[100];
			if (segwit_addr_encode(addr, chainparams->onchain_hrp,
				1, fi->funding_spk + 2, 32)) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					"Factory %s: funding-pending at startup "
					"(no txid recorded). Expected funding "
					"address: %s. Attempting wallet "
					"reconciliation.", iid_hex, addr);
			}
			/* Gap 7: try to find the funding TX in the wallet's
			 * history and fill in the txid/outnum automatically. */
			ss_reconcile_funding_pending(cmd, fi);
		}
	}
}

/* Dispatch SuperScalar protocol submessages.
 * Data format: [32 bytes instance_id][payload] */
/* Continue ceremony after real funding TX is confirmed.
 * Rebuilds tree with real pubkeys + real funding, finalizes sessions,
 * and sends ALL_NONCES to clients. Called from withdraw callback. */
static void continue_after_funding(struct command *cmd,
				   struct funding_ctx *fctx)
{
	factory_instance_t *fi = fctx->fi;
	factory_t *f = (factory_t *)fi->lib_factory;

	plugin_log(plugin_handle, LOG_INFORM,
		   "Continuing ceremony after real funding TX created");

	/* Rebuild tree with real pubkeys (same as inline code in NONCE_BUNDLE
	 * handler) but now using real funding from fi->funding_* */
	size_t n_total = 1 + fi->n_clients;
	secp256k1_pubkey *real_pks = calloc(n_total, sizeof(secp256k1_pubkey));
	bool rebuild_ok = real_pks != NULL;
	if (rebuild_ok)
		rebuild_ok = secp256k1_ec_pubkey_create(global_secp_ctx,
			&real_pks[0], fi->our_seckey) != 0;
	for (size_t rci = 0; rci < fi->n_clients && rebuild_ok; rci++) {
		if (fi->clients[rci].has_factory_pubkey) {
			rebuild_ok = secp256k1_ec_pubkey_parse(global_secp_ctx,
				&real_pks[rci + 1],
				fi->clients[rci].factory_pubkey, 33) != 0;
		} else {
			unsigned char psk[32];
			derive_placeholder_seckey(psk, fi->instance_id,
						  (int)(rci + 1));
			rebuild_ok = secp256k1_ec_pubkey_create(global_secp_ctx,
				&real_pks[rci + 1], psk) != 0;
		}
	}

	if (rebuild_ok) {
		factory_t *new_f = calloc(1, sizeof(factory_t));
		factory_init_from_pubkeys(new_f, global_secp_ctx,
			real_pks, n_total, DW_STEP_BLOCKS, 16);
		factory_set_arity(new_f, ss_effective_arity(fi));
		/* Restore L-stock secrets BEFORE build_tree so build_l_stock_spk
		 * produces the same P2TR keys that went on-chain originally.
		 * Without this, the rebuilt tree has no taptree on L-stock
		 * outputs and every output key differs from the actual state. */
		if (ss_state.has_master_key) {
			static unsigned char rsecrets[256][32];
			derive_l_stock_secrets(rsecrets, 256, fi->instance_id);
			factory_set_flat_secrets(new_f,
				(const unsigned char (*)[32])rsecrets, 256);
		}
		/* Use REAL funding from fi */
		factory_set_funding(new_f, fi->funding_txid,
			fi->funding_outnum, fi->funding_amount_sats,
			fi->funding_spk, fi->funding_spk_len);
		factory_set_lifecycle(new_f, fi->creation_block, 4320, 432);
		factory_build_tree(new_f);

		/* Re-apply per-client allocations on the LSP's rebuilt tree.
		 * Without this, the post-funding LSP tree carries libsuperscalar
		 * default even-split amounts while the client's PROPOSE/ALL_NONCES
		 * rebuild already applied allocations — the two sides would sign
		 * different per-leaf outputs. No-op when n_allocations==0. */
		apply_allocations_to_leaves(fi, new_f, n_total);

		factory_t *old_f = f;
		if (old_f) { factory_free(old_f); free(old_f); }
		fi->lib_factory = new_f;
		f = new_f;

		/* Gap 9: snapshot the rebuilt tree's keyagg state. This is the
		 * post-real-funding tree we're about to ALL_NONCES → PSIG →
		 * sign against; persist its cache so a future reload restores
		 * the same bytes instead of trusting the recompute. The
		 * subsequent ss_save_factory call (line ~2881) picks up the
		 * fresh blob and writes it to the meta record. */
		ss_keyagg_snapshot_capture(fi);

		factory_sessions_init(f);
		nonce_entry_t *cache = (nonce_entry_t *)fi->cached_nonces;
		if (cache) {
			for (size_t ne = 0; ne < fi->n_cached_nonces; ne++) {
				secp256k1_musig_pubnonce pn;
				if (musig_pubnonce_parse(global_secp_ctx, &pn,
							 cache[ne].pubnonce))
					factory_session_set_nonce(f,
						cache[ne].node_idx,
						cache[ne].signer_slot, &pn);
			}
		}
		plugin_log(plugin_handle, LOG_INFORM,
			   "Rebuilt tree with real funding + real pubkeys "
			   "(%zu participants)", n_total);
	}
	free(real_pks);

	if (!factory_sessions_finalize(f)) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "factory_sessions_finalize failed after funding");
		ss_terminalize_failed(cmd, fi, SS_CEREMONY_ABORT_OTHER);
		return;
	}

	fi->ceremony = CEREMONY_NONCES_COLLECTED;
	fi->n_tree_nodes = (uint32_t)f->n_nodes;

	/* Build and send ALL_NONCES with real funding info */
	nonce_entry_t *anc = (nonce_entry_t *)fi->cached_nonces;
	if (anc && fi->n_cached_nonces > 0) {
		nonce_bundle_t *all_nb = calloc(1, sizeof(*all_nb));
		if (all_nb) {
			memcpy(all_nb->instance_id, fi->instance_id, 32);
			all_nb->n_participants = 1 + fi->n_clients;
			all_nb->n_nodes = f->n_nodes;
			/* Tier 2.6: propagate arity choice in ALL_NONCES as well
			 * (also delivered in FACTORY_PROPOSE; duplicated so clients
			 * that reconstruct from ALL_NONCES alone still see it). */
			all_nb->arity_mode = fi->arity_mode;

			/* Include real pubkeys */
			size_t pk_out = 33;
			secp256k1_pubkey lsp_pub;
			if (secp256k1_ec_pubkey_create(global_secp_ctx,
						       &lsp_pub, fi->our_seckey))
				secp256k1_ec_pubkey_serialize(global_secp_ctx,
					all_nb->pubkeys[0], &pk_out,
					&lsp_pub, SECP256K1_EC_COMPRESSED);
			for (size_t rci = 0; rci < fi->n_clients; rci++) {
				if (fi->clients[rci].has_factory_pubkey)
					memcpy(all_nb->pubkeys[rci + 1],
					       fi->clients[rci].factory_pubkey, 33);
			}

			/* Include real funding info */
			memcpy(all_nb->funding_txid, fi->funding_txid, 32);
			all_nb->funding_vout = fi->funding_outnum;
			all_nb->funding_amount_sats = fi->funding_amount_sats;
			memcpy(all_nb->funding_spk, fi->funding_spk,
			       fi->funding_spk_len);
			all_nb->funding_spk_len = fi->funding_spk_len;

			/* Copy nonce entries */
			size_t n = fi->n_cached_nonces;
			if (n > MAX_NONCE_ENTRIES) n = MAX_NONCE_ENTRIES;
			memcpy(all_nb->entries, anc, n * sizeof(nonce_entry_t));
			all_nb->n_entries = n;

			/* Cache for reconnect */
			uint8_t *anbuf = calloc(1, MAX_WIRE_BUF);
			size_t anlen = nonce_bundle_serialize(all_nb, anbuf,
							      MAX_WIRE_BUF);
			free(fi->cached_all_nonces_wire);
			fi->cached_all_nonces_wire = malloc(anlen);
			if (fi->cached_all_nonces_wire) {
				memcpy(fi->cached_all_nonces_wire, anbuf, anlen);
				fi->cached_all_nonces_len = anlen;
			}

			/* Send to all clients */
			for (size_t ci = 0; ci < fi->n_clients; ci++) {
				char nid[67];
				for (int j = 0; j < 33; j++)
					sprintf(nid + j*2, "%02x",
						fi->clients[ci].node_id[j]);
				nid[66] = '\0';
				send_factory_msg(cmd, nid,
					SS_SUBMSG_ALL_NONCES, anbuf, anlen);
			}
			free(anbuf);
			free(all_nb);

			plugin_log(plugin_handle, LOG_INFORM,
				   "Sent ALL_NONCES with real funding to %zu "
				   "clients (%zu entries)",
				   fi->n_clients, n);
		}
	}

	/* Free nonce cache */
	free(fi->cached_nonces);
	fi->cached_nonces = NULL;
	fi->n_cached_nonces = 0;

	ss_save_factory(cmd, fi);
}

/* ============================================================================
 * B1.3: Build the TLV-diff factory_policy blob for a single LSP-owned
 * factory, for attachment to FACTORY_INFO_RESPONSE.
 *
 * Today this only maps a handful of fields off factory_instance_t — arity,
 * lifetime, early-warning.  Most of ss_factory_policy_t stays at canonical
 * defaults.  Subsequent commits (B1.5+ / Phase D) will populate from CLI
 * options + wallet.db settings as those plumbing pieces land.
 *
 * Returns blob length, or 0 if buffer is too small / cannot encode.
 * ========================================================================= */
static size_t ss_build_factory_policy_blob(const factory_instance_t *fi,
					    uint8_t *buf, size_t cap)
{
	if (!fi || !buf) return 0;

	ss_factory_policy_t defaults;
	ss_factory_policy_init_defaults(&defaults);

	ss_factory_policy_t p;
	ss_factory_policy_init_defaults(&p);

	/* Map operator-set fields off the factory_instance_t.  factory_t
	 * arity_t values (1=ARITY_1, 2=ARITY_2, 3=ARITY_PS) align with the
	 * policy enum's ARITY_1/_2/_PS, so a direct cast is safe.  Sentinel
	 * 0 means "auto" — leave at default ARITY_PS. */
	if (fi->arity_mode != 0)
		p.arity_mode = (ss_arity_mode_t)fi->arity_mode;

	if (fi->expiry_block > fi->creation_block) {
		uint32_t lifetime = fi->expiry_block - fi->creation_block;
		p.lifetime_blocks = lifetime;
		/* re-derive lifetime-dependent default fields so the diff
		 * doesn't accidentally encode stale derived values */
		if (p.joiner_admission_window_blocks
		    == defaults.joiner_admission_window_blocks)
			p.joiner_admission_window_blocks = lifetime
				- p.dying_period_blocks;
		if (p.state_replay_defense_window_blocks
		    == defaults.state_replay_defense_window_blocks)
			p.state_replay_defense_window_blocks = lifetime;
	}

	if (fi->early_warning_time > 0)
		p.block_early_count = fi->early_warning_time;

	return ss_factory_policy_encode_diff(&p, &defaults, buf, cap);
}

/* Phase 4: passive last_seen tracking. Updates every factory's join_queue
 * entry whose client_node_id matches the BOLT-8 sender. Called from the
 * top of dispatch_superscalar_submsg so ANY wire message from a known
 * client refreshes their last_seen_block. Replaces a dedicated heartbeat
 * submsg — CLN BOLT-8 ping already covers wire-level liveness; this
 * adds factory-state-level freshness without new wire traffic. */
static void ss_update_peer_last_seen(const uint8_t peer_pk[33])
{
	for (size_t fi_idx = 0; fi_idx < ss_state.n_factories; fi_idx++) {
		factory_instance_t *fi = ss_state.factories[fi_idx];
		if (!fi || !fi->is_lsp) continue;
		for (size_t i = 0; i < fi->n_join_queue; i++) {
			if (memcmp(fi->join_queue[i].client_node_id,
				   peer_pk, 33) == 0) {
				fi->join_queue[i].last_seen_block =
					ss_state.current_blockheight;
			}
		}
	}
}

static void dispatch_superscalar_submsg(struct command *cmd,
					const char *peer_id,
					u16 submsg_id,
					const u8 *data, size_t len)
{
	factory_instance_t *fi = NULL;

	/* Phase 4: passive last_seen tracking. Update last_seen_block on every
	 * factory's join_queue entry that matches this peer. Cheap O(F*Q) scan
	 * — F factories × Q queue entries per factory. F is small (1-10 for
	 * typical LSP), Q caps at MAX_JOIN_QUEUE=256. */
	{
		uint8_t peer_pk_seen[33];
		if (strlen(peer_id) == 66) {
			bool ok = true;
			for (int k = 0; k < 33 && ok; k++) {
				unsigned int by;
				if (sscanf(peer_id + k*2, "%2x", &by) != 1)
					ok = false;
				else
					peer_pk_seen[k] = (uint8_t)by;
			}
			if (ok)
				ss_update_peer_last_seen(peer_pk_seen);
		}
	}

	/* Extract instance_id from submessage (first 32 bytes).
	 * Don't strip it — handlers that use nonce_bundle_deserialize
	 * expect the full payload including instance_id. */
	if (len >= 32 && submsg_id != SS_SUBMSG_FACTORY_PROPOSE
	    && submsg_id != SS_SUBMSG_ROTATE_PROPOSE
	    && submsg_id != SS_SUBMSG_REVOKE
	    && submsg_id != SS_SUBMSG_REVOKE_ACK
	    && submsg_id != SS_SUBMSG_CLOSE_PROPOSE
	    && submsg_id != SS_SUBMSG_FACTORY_INFO_REQUEST
	    && submsg_id != SS_SUBMSG_FACTORY_INFO_RESPONSE
	    && submsg_id != SS_SUBMSG_JOIN_REQUEST
	    && submsg_id != SS_SUBMSG_JOIN_RESPONSE
	    && submsg_id != SS_SUBMSG_JOIN_CANCEL
	    /* PR 3 ceremony submsgs (0x0145-0x014C) start with an 8-byte
	     * ceremony_id, not the 32-byte factory_instance_id. They do
	     * their own factory lookup inside the case. */
	    && submsg_id != SS_SUBMSG_CEREMONY_START
	    && submsg_id != SS_SUBMSG_CEREMONY_NONCE_REPLY
	    && submsg_id != SS_SUBMSG_CEREMONY_PARTIAL_SIG_REQ
	    && submsg_id != SS_SUBMSG_CEREMONY_PARTIAL_SIG
	    && submsg_id != SS_SUBMSG_CEREMONY_RESULT
	    && submsg_id != SS_SUBMSG_CEREMONY_ABORT
	    && submsg_id != SS_SUBMSG_CEREMONY_STATUS_QUERY
	    && submsg_id != SS_SUBMSG_CEREMONY_STATUS_REPLY
	    && submsg_id != SS_SUBMSG_SIGN_QUEUE_REQUEST
	    && submsg_id != SS_SUBMSG_SIGN_QUEUE_RESPONSE
	    && submsg_id != SS_SUBMSG_FACTORY_PROPOSE_V2) {
		fi = ss_factory_find(&ss_state, data);
		if (!fi) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "Unknown factory instance in submsg 0x%04x from %s",
				   submsg_id, peer_id);
			return;
		}
		/* data and len unchanged — handler gets full payload */
	}

	switch (submsg_id) {
	case SS_SUBMSG_FACTORY_PROPOSE_V2: {
		/* Phase C v2: strip trailing [u16 BE policy_len][policy_diff]
		 * and update the policy cache, then fall through to the V1
		 * handler with the prefix. */
		if (len < 2) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "FACTORY_PROPOSE_V2 from %s too short (%zu)",
				   peer_id, len);
			break;
		}
		size_t plen = ((size_t)data[len - 2] << 8) | data[len - 1];
		if (plen + 2 > len) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "FACTORY_PROPOSE_V2 policy_len %zu > payload %zu - 2",
				   plen, len);
			break;
		}
		const uint8_t *pol_bytes = data + (len - 2 - plen);
		size_t prefix_len = len - 2 - plen;

		/* Try to decode the policy and update cache. We need the
		 * instance_id from the bundle prefix — peek at the standard
		 * V1 trailer to find it. */
		if (plen > 0) {
			ss_factory_policy_t pol;
			ss_factory_policy_init_defaults(&pol);
			if (ss_factory_policy_decode(pol_bytes, plen, &pol)) {
				/* Need the instance_id to key the cache.
				 * The nonce bundle's first 32 bytes are
				 * the instance_id per nonce_bundle_t
				 * serialisation order. */
				if (prefix_len >= 32) {
					uint8_t lsp_pk[33];
					if (ss_decode_node_id_hex(peer_id, lsp_pk)) {
						ss_policy_cache_put(lsp_pk, data, &pol);
						plugin_log(plugin_handle, LOG_INFORM,
							   "FACTORY_PROPOSE_V2: cached policy "
							   "from %s (diff=%zu bytes)",
							   peer_id, plen);
					}
				}
			} else {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "FACTORY_PROPOSE_V2 policy decode failed");
			}
		}

		/* Dispatch the prefix as a V1 FACTORY_PROPOSE so the
		 * existing validator + auto-sign gate runs against the
		 * (now-fresh) cached policy. */
		dispatch_superscalar_submsg(cmd, peer_id,
			SS_SUBMSG_FACTORY_PROPOSE, data, prefix_len);
		break;
	}

	case SS_SUBMSG_FACTORY_PROPOSE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "FACTORY_PROPOSE from %s (len=%zu)",
			   peer_id, len);
		/* Client side: deserialize nonce bundle, init factory,
		 * generate our nonces, respond with NONCE_BUNDLE. */
		{
			/* Heap-allocate: 79KB with MAX_NONCE_ENTRIES=1024 */
			nonce_bundle_t *nb = calloc(1, sizeof(*nb));
			if (!nb) break;

			/* Payload formats (try in order):
			 *   new: bundle || famt(8) || pidx(4) || alloc[n](n*8) || n_alloc(1)
			 *   mid: bundle || famt(8) || pidx(4)
			 *   old: bundle || pidx(4)
			 * We detect "new" by reading the last byte as n_alloc and
			 * checking that the implied trailer parses cleanly. */
			/* Payload format:
			 *   bundle || famt(8) || pidx(4) || [alloc(n*8)] || n_alloc(1)
			 * n_alloc is always present (0 = no allocations).
			 * Trailer = 13 + n_alloc * 8. */
			uint8_t propose_n_alloc = 0;
			uint64_t propose_allocs[MAX_FACTORY_PARTICIPANTS] = {0};
			size_t trailer;
			bool parsed = false;

			if (len >= 13) {
				uint8_t cand = data[len - 1];
				if (cand <= MAX_FACTORY_PARTICIPANTS) {
					size_t cand_trailer = 13 + (size_t)cand * 8;
					if (len > cand_trailer
					    && nonce_bundle_deserialize(
						nb, data, len - cand_trailer)) {
						propose_n_alloc = cand;
						trailer = cand_trailer;
						parsed = true;
					}
				}
			}
			/* Fallback for old format (no n_alloc byte) */
			if (!parsed && len >= 12 && nonce_bundle_deserialize(
				nb, data, len - 12)) {
				trailer = 12;
				parsed = true;
			}
			if (!parsed) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "Bad FACTORY_PROPOSE payload");
				free(nb);
				break;
			}

			/* Read funding amount (0 if old 4-byte trailer). In the
			 * new format the famt+pidx come right after the bundle. */
			uint64_t propose_funding_sats = 0;
			size_t famt_off = len - trailer;
			if (trailer >= 12) {
				const uint8_t *ap = data + famt_off;
				propose_funding_sats =
					((uint64_t)ap[0] << 56) |
					((uint64_t)ap[1] << 48) |
					((uint64_t)ap[2] << 40) |
					((uint64_t)ap[3] << 32) |
					((uint64_t)ap[4] << 24) |
					((uint64_t)ap[5] << 16) |
					((uint64_t)ap[6] <<  8) | ap[7];
			}

			/* Participant index is always the 4 bytes after famt. */
			size_t pidx_off = (trailer >= 12) ? famt_off + 8
							  : famt_off;
			uint32_t our_pidx =
				((uint32_t)data[pidx_off]     << 24) |
				((uint32_t)data[pidx_off + 1] << 16) |
				((uint32_t)data[pidx_off + 2] << 8)  |
				 (uint32_t)data[pidx_off + 3];

			/* Read allocations if present. */
			if (propose_n_alloc > 0) {
				size_t ao = pidx_off + 4;
				for (uint8_t ai = 0; ai < propose_n_alloc; ai++) {
					const uint8_t *ap = data + ao;
					propose_allocs[ai] =
						((uint64_t)ap[0] << 56) |
						((uint64_t)ap[1] << 48) |
						((uint64_t)ap[2] << 40) |
						((uint64_t)ap[3] << 32) |
						((uint64_t)ap[4] << 24) |
						((uint64_t)ap[5] << 16) |
						((uint64_t)ap[6] <<  8) |
						 ap[7];
					ao += 8;
				}
				plugin_log(plugin_handle, LOG_INFORM,
					   "FACTORY_PROPOSE carries %u allocations",
					   propose_n_alloc);
			}

			/* B2: snapshot the parsed proposal into the pending
			 * cache BEFORE the B1.5 validator decides whether to
			 * refuse.  This way the factory-review-proposal RPC
			 * can render either an accepted-pending or refused
			 * proposal — important for letting the user see WHY
			 * a proposal was rejected, not just that it was. */
			uint8_t lsp_pk_bytes[33];
			bool lsp_pk_ok = ss_peer_id_hex_to_bytes(peer_id, lsp_pk_bytes);
			struct ss_pending_proposal_entry *pp_entry = NULL;
			if (lsp_pk_ok) {
				pp_entry = ss_pending_proposals_slot(lsp_pk_bytes,
					nb->instance_id);
				if (pp_entry) {
					pp_entry->funding_sats = propose_funding_sats;
					pp_entry->n_participants = nb->n_participants;
					pp_entry->our_pidx = our_pidx;
					pp_entry->n_allocs = propose_n_alloc;
					for (uint8_t ai = 0;
					     ai < propose_n_alloc
					     && ai < MAX_FACTORY_PARTICIPANTS;
					     ai++)
						pp_entry->allocs[ai] = propose_allocs[ai];
					pp_entry->received_at_block =
						ss_state.current_blockheight;
					pp_entry->last_validate_result =
						SS_POLICY_VALIDATE_OK;  /* will overwrite */
					pp_entry->last_validate_field_tlv = 0xFFFF;
					pp_entry->last_validate_reason[0] = '\0';
				}
			}

			/* B1.5: policy validation gate (moved here from before
			 * param parse so B2's cache write captures the proposal
			 * even on refusal).  Look up LSP's advertised policy +
			 * user's client_signing_prefs; hard-fail = refuse to
			 * sign, no nonces generated.  If no policy was cached
			 * for this (peer, instance) we still validate against
			 * canonical defaults so a permissive-by-omission LSP
			 * cannot bypass the check by simply not advertising. */
			if (lsp_pk_ok) {
				const ss_factory_policy_t *cached =
					ss_policy_cache_get(lsp_pk_bytes,
						nb->instance_id);
				ss_factory_policy_t fallback;
				ss_factory_policy_init_defaults(&fallback);
				const ss_factory_policy_t *check_policy =
					cached ? cached : &fallback;

				ss_signing_prefs_load_or_default();
				ss_policy_validation_result_t res;
				int rc = ss_validate_policy_against_prefs(
					check_policy, &g_signing_prefs, &res);
				/* Record outcome in the pending-proposal cache so
				 * the wallet UI can show it via factory-review-proposal. */
				if (pp_entry) {
					pp_entry->last_validate_result = rc;
					pp_entry->last_validate_field_tlv = res.field_tlv;
					strncpy(pp_entry->last_validate_reason,
						res.reason,
						sizeof(pp_entry->last_validate_reason) - 1);
				}
				if (rc == SS_POLICY_VALIDATE_HARD_FAIL) {
					plugin_log(plugin_handle, LOG_BROKEN,
						"REFUSING to sign FACTORY_PROPOSE from %s — "
						"policy violates client_signing_prefs: "
						"field_tlv=0x%04x reason=\"%s\"%s",
						peer_id,
						(unsigned)res.field_tlv,
						res.reason,
						cached ? "" : " (no advertised policy cached; "
							   "checked defaults)");
					ss_audit_log(LOG_BROKEN,
						"policy_violation_refused_sign",
						"{\"peer\":\"%s\",\"field_tlv\":%u,"
						"\"reason\":\"%s\",\"had_cached_policy\":%s}",
						peer_id,
						(unsigned)res.field_tlv,
						res.reason,
						cached ? "true" : "false");
					free(nb);
					break;
				}

				/* D.1 + D.6: gate auto-sign on user prefs.
				 * Bypass if the user already approved this slot
				 * via factory-approve-proposal (which sets
				 * user_approved and re-dispatches us). */
				if (!g_signing_prefs.auto_sign_on_validator_pass
				    && (!pp_entry || !pp_entry->user_approved)) {
					/* D.6: stash raw payload for later release.
					 * Free any prior held_payload first
					 * (a re-PROPOSE for the same slot overrides
					 * the previous one). */
					if (pp_entry) {
						if (pp_entry->held_payload) {
							free(pp_entry->held_payload);
							pp_entry->held_payload = NULL;
							pp_entry->held_payload_len = 0;
						}
						pp_entry->held_payload = malloc(len);
						if (pp_entry->held_payload) {
							memcpy(pp_entry->held_payload, data, len);
							pp_entry->held_payload_len = len;
						}
						pp_entry->user_approved = false;
						pp_entry->user_refused  = false;
					}
					plugin_log(plugin_handle, LOG_INFORM,
						   "auto_sign_on_validator_pass=OFF; "
						   "holding FACTORY_PROPOSE from %s "
						   "(instance_id_prefix=%02x%02x%02x%02x, "
						   "%zu bytes saved) for user decision",
						   peer_id,
						   nb->instance_id[0], nb->instance_id[1],
						   nb->instance_id[2], nb->instance_id[3],
						   len);
					ss_audit_log(LOG_INFORM,
						"propose_held_for_user_decision",
						"{\"peer\":\"%s\","
						"\"iid_prefix\":\"%02x%02x%02x%02x\","
						"\"payload_len\":%zu}",
						peer_id,
						nb->instance_id[0], nb->instance_id[1],
						nb->instance_id[2], nb->instance_id[3],
						len);
					free(nb);
					break;
				}

				/* D.6: if we're here because the user just
				 * approved a previously-held proposal, clear
				 * the held state — we're consuming it now. */
				if (pp_entry && pp_entry->user_approved) {
					if (pp_entry->held_payload) {
						free(pp_entry->held_payload);
						pp_entry->held_payload = NULL;
						pp_entry->held_payload_len = 0;
					}
					pp_entry->user_approved = false;
				}
			}

			fi = ss_factory_new(&ss_state, nb->instance_id);
			if (!fi) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "Failed to create factory");
				free(nb);
				break;
			}
			fi->is_lsp = false;
			/* Client-side semantic for fi->clients[]: one entry per
			 * OTHER signer (LSP + peer clients), in arbitrary order;
			 * each entry's signer_slot carries its factory-wide slot
			 * (0=LSP, 1..n=clients). For 2-party there is exactly one
			 * other signer (the LSP at slot 0); for 3+-party there is
			 * the LSP plus peer clients. n_clients counts other-signers,
			 * which happens to equal nb->n_participants - 1. */
			fi->n_clients = nb->n_participants > 1
				? nb->n_participants - 1 : 0;
			fi->funding_amount_sats = propose_funding_sats;
			fi->creation_block = ss_state.current_blockheight;
			fi->expiry_block = ss_state.current_blockheight + 4320 + 432;
			fi->n_tree_nodes = nb->n_nodes > 0 ? nb->n_nodes : 2;
			/* Tier 2.6: adopt LSP's arity_mode choice. 0 = auto
			 * (ss_effective_arity falls back to ss_choose_arity). */
			fi->arity_mode = nb->arity_mode;
			fi->early_warning_time = compute_early_warning_time(
				fi->n_clients, ss_effective_arity(fi));

			/* Store LSP peer_id as node_id */
			if (strlen(peer_id) == 66) {
				for (int j = 0; j < 33; j++) {
					unsigned int b;
					sscanf(peer_id + j*2, "%02x", &b);
					fi->lsp_node_id[j] = (uint8_t)b;
				}
			}

			/* Store every other-signer's factory pubkey + signer_slot
			 * so tree rebuild after restart sees correct keys at
			 * every slot (not just the LSP). For 3+-party factories
			 * the peer client's slot is also populated here — without
			 * this, ss_load_factories would leave that slot zeroed
			 * and crash inside secp256k1_musig_pubkey_agg. */
			{
				size_t ci_out = 0;
				for (uint32_t pi = 0;
				     pi < nb->n_participants
				     && ci_out < MAX_FACTORY_PARTICIPANTS;
				     pi++) {
					if ((int)pi == (int)our_pidx)
						continue;
					fi->clients[ci_out].signer_slot = (int)pi;
					if (nb->pubkeys[pi][0] != 0) {
						fi->clients[ci_out].has_factory_pubkey =
							true;
						memcpy(fi->clients[ci_out].factory_pubkey,
						       nb->pubkeys[pi], 33);
					}
					fi->clients[ci_out].pending_revoke_epoch =
						UINT32_MAX;
					fi->clients[ci_out].last_acked_epoch =
						UINT32_MAX;
					ci_out++;
				}
				/* fi->n_clients was set above to
				 * nb->n_participants - 1 which equals ci_out
				 * unless we exceeded MAX. Track the actual count
				 * so persistence/load align. */
				fi->n_clients = ci_out;
			}

			/* Use pubkeys from the bundle (same as LSP's) */
			secp256k1_context *ctx = global_secp_ctx;
			secp256k1_pubkey *pubkeys = calloc(nb->n_participants,
				sizeof(secp256k1_pubkey));

			for (uint32_t pk = 0; pk < nb->n_participants; pk++) {
				if (!secp256k1_ec_pubkey_parse(ctx,
					&pubkeys[pk],
					nb->pubkeys[pk], 33)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "Bad pubkey %u in propose", pk);
					free(pubkeys);
					free(nb);
					break;
				}
			}

			/* Derive our keypair from instance_id using our participant index. */
			unsigned char our_sec[32];
			int our_idx = (int)our_pidx;
			derive_factory_seckey(our_sec, nb->instance_id, our_idx);
			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: FACTORY_PROPOSE, our_participant_idx=%d",
				   our_idx);

			/* Init and build tree with LSP's pubkeys */
			factory_t *factory = calloc(1, sizeof(factory_t));
			factory_init_from_pubkeys(factory, ctx,
				pubkeys, nb->n_participants,
				DW_STEP_BLOCKS, 16);
			/* Phase 3c3: wire fee estimator on the client side too
			 * so client's view of tree TXs has matching anchor
			 * outputs (keeps sighashes + txids in sync with LSP). */
			ss_factory_wire_fee_estimator(fi, factory);
			factory_set_arity(factory, ss_effective_arity(fi));

			uint8_t synth_txid[32], synth_spk[34];
			for (int j = 0; j < 32; j++) synth_txid[j] = j + 1;
			synth_spk[0] = 0x51; synth_spk[1] = 0x20;
			memset(synth_spk + 2, 0xAA, 32);
			factory_set_funding(factory, synth_txid, 0,
					    propose_funding_sats > 0
						? propose_funding_sats
						: DEFAULT_FACTORY_FUNDING_SATS,
					    synth_spk, 34);
			fi->funding_amount_sats = propose_funding_sats > 0
				? propose_funding_sats
				: DEFAULT_FACTORY_FUNDING_SATS;

			factory_set_lifecycle(factory,
				ss_state.current_blockheight, 4320, 432);
			if (!factory_build_tree(factory)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Client: factory_build_tree failed");
				free(factory);
				free(pubkeys);
				free(nb);
				break;
			}

			/* Apply allocations (from FACTORY_PROPOSE payload) to
			 * leaf amounts so our MuSig2 signing uses the same
			 * message hash as the LSP. Mirrors the LSP's loop in
			 * json_factory_create. */
			if (propose_n_alloc > 0
			    && propose_funding_sats > 0
			    && factory->n_leaf_nodes > 0) {
				fi->n_allocations = propose_n_alloc;
				for (uint8_t ai = 0; ai < propose_n_alloc; ai++)
					fi->allocations[ai] = propose_allocs[ai];

				uint64_t total = propose_funding_sats;
				uint64_t lstock_total = total * 20 / 100;
				uint64_t client_total = total - lstock_total;
				uint64_t default_per =
					client_total /
					(nb->n_participants - 1);

				for (int ls = 0; ls < factory->n_leaf_nodes; ls++) {
					size_t leaf_ni =
						factory->leaf_node_indices[ls];
					factory_node_t *ln =
						&factory->nodes[leaf_ni];
					size_t nclients = 0;
					for (size_t s = 0; s < ln->n_signers; s++)
						if (ln->signer_indices[s] != 0)
							nclients++;
					size_t n_outputs = nclients + 1;
					uint64_t *amts = calloc(n_outputs,
								sizeof(uint64_t));
					if (!amts) break;
					size_t out_idx = 0;
					uint64_t csum = 0;
					for (size_t s = 0; s < ln->n_signers; s++) {
						int pidx = ln->signer_indices[s];
						if (pidx == 0) continue;
						size_t ci = (size_t)(pidx - 1);
						uint64_t a =
						  (ci < propose_n_alloc
						   && propose_allocs[ci] > 0)
						   ? propose_allocs[ci]
						   : default_per;
						amts[out_idx++] = a;
						csum += a;
					}
					uint64_t lt = ln->input_amount;
					amts[nclients] = lt > csum
						? lt - csum : 546;
					factory_set_leaf_amounts(factory, ls,
								 amts, n_outputs);
					free(amts);
				}
				plugin_log(plugin_handle, LOG_INFORM,
					   "Client: applied %u allocations to leaves",
					   propose_n_alloc);
			}

			factory_sessions_init(factory);
			fi->lib_factory = factory;

			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: tree built, %zu nodes",
				   (size_t)factory->n_nodes);

			/* Set LSP nonces on our sessions */
			for (size_t e = 0; e < nb->n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				musig_pubnonce_parse(ctx, &pn,
					nb->entries[e].pubnonce);
				factory_session_set_nonce(factory,
					nb->entries[e].node_idx,
					nb->entries[e].signer_slot,
					&pn);
			}

			/* Compute our REAL factory pubkey from HSM-derived seckey.
			 * This is sent in the NONCE_BUNDLE so the LSP can
			 * rebuild the DW tree with real pubkeys. */
			secp256k1_pubkey our_real_pub;
			if (!secp256k1_ec_pubkey_create(ctx, &our_real_pub, our_sec)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Client: ec_pubkey_create failed");
				free(pubkeys); free(nb); break;
			}

			/* Generate our nonces */
			size_t our_node_count =
				factory_count_nodes_for_participant(factory,
								   our_idx);
			/* Heap-allocate pool so secnonces survive this scope */
			musig_nonce_pool_t *pool = calloc(1, sizeof(musig_nonce_pool_t));
			musig_nonce_pool_generate(ctx, pool,
				our_node_count, our_sec,
				&our_real_pub, NULL); /* bind to real pubkey */

			/* Store pool, seckey, participant index for signing */
			fi->nonce_pool = pool;
			memcpy(fi->our_seckey, our_sec, 32);
			fi->our_participant_idx = our_idx;
			fi->n_secnonces = 0;

			/* Heap-allocate: nonce_bundle_t is ~79KB with 1024 entries */
			nonce_bundle_t *resp = calloc(1, sizeof(nonce_bundle_t));
			if (!resp) {
				free(pool);
				break;
			}
			memcpy(resp->instance_id, fi->instance_id, 32);
			resp->n_participants = nb->n_participants;
			resp->n_nodes = factory->n_nodes;
			resp->n_entries = 0;
			/* Include our real pubkey at our slot so LSP can rebuild tree */
			if (our_idx < MAX_PARTICIPANTS) {
				size_t pk_out = 33;
				secp256k1_ec_pubkey_serialize(ctx,
					resp->pubkeys[our_idx], &pk_out,
					&our_real_pub, SECP256K1_EC_COMPRESSED);
			}

			size_t pool_entry = 0;
			for (size_t ni = 0; ni < factory->n_nodes; ni++) {
				int slot = factory_find_signer_slot(
					factory, ni, our_idx);
				if (slot < 0) continue;

				if (resp->n_entries >= MAX_NONCE_ENTRIES ||
				    fi->n_secnonces >= MAX_NONCE_ENTRIES) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "Client: nonce entries exceeded"
						   " MAX_NONCE_ENTRIES at node %zu",
						   ni);
					break;
				}

				secp256k1_musig_secnonce *sec;
				secp256k1_musig_pubnonce pub;
				if (!musig_nonce_pool_next(pool, &sec, &pub))
					break;

				/* Record which pool index maps to which node */
				fi->secnonce_pool_idx[fi->n_secnonces] = pool_entry;
				fi->secnonce_node_idx[fi->n_secnonces] = ni;
				fi->n_secnonces++;
				pool_entry++;

				factory_session_set_nonce(factory, ni,
							  (size_t)slot, &pub);
				musig_pubnonce_serialize(ctx,
					resp->entries[resp->n_entries].pubnonce,
					&pub);
				resp->entries[resp->n_entries].node_idx = ni;
				resp->entries[resp->n_entries].signer_slot = slot;
				resp->n_entries++;
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: generated %zu nonce entries",
				   resp->n_entries);

			/* Serialize and send NONCE_BUNDLE back to LSP */
			uint8_t *rbuf = calloc(1, MAX_WIRE_BUF);
			size_t rlen = nonce_bundle_serialize(resp,
				rbuf, MAX_WIRE_BUF);
			free(resp);
			send_factory_msg(cmd, peer_id,
					 SS_SUBMSG_NONCE_BUNDLE,
					 rbuf, rlen);
			free(rbuf);

			/* Always wait for ALL_NONCES before signing.
			 * The LSP rebuilds the tree with real funding after
			 * collect all nonces, so signing before ALL_NONCES
			 * would produce invalid partial sigs. */
			if (false) { /* 2-party fast path disabled */
				if (!factory_sessions_finalize(factory)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "Client: factory_sessions_finalize failed");
				} else {
					plugin_log(plugin_handle, LOG_INFORM,
						   "Client: nonces finalized (2-party fast path)");

					/* Create partial sigs and send PSIG_BUNDLE */
					secp256k1_keypair kp;
					if (!secp256k1_keypair_create(ctx, &kp, our_sec)) {
						plugin_log(plugin_handle, LOG_BROKEN,
							   "Client: keypair create failed");
					} else {
						nonce_bundle_t *psig_nb = calloc(1, sizeof(*psig_nb));
						if (!psig_nb) {
							plugin_log(plugin_handle, LOG_BROKEN,
								"Client: psig_nb alloc failed");
						} else {
							memcpy(psig_nb->instance_id, fi->instance_id, 32);
							psig_nb->n_participants = nb->n_participants;
							psig_nb->n_nodes = factory->n_nodes;
							psig_nb->n_entries = 0;

							musig_nonce_pool_t *sp =
								(musig_nonce_pool_t *)fi->nonce_pool;

							for (size_t si = 0; si < fi->n_secnonces; si++) {
								uint32_t pi = fi->secnonce_pool_idx[si];
								uint32_t ni = fi->secnonce_node_idx[si];
								secp256k1_musig_secnonce *sn =
									&sp->nonces[pi].secnonce;

								int slot = factory_find_signer_slot(
									factory, ni, fi->our_participant_idx);
								if (slot < 0) continue;

								secp256k1_musig_partial_sig psig;
								if (!musig_create_partial_sig(
									ctx, &psig, sn, &kp,
									&factory->nodes[ni].signing_session))
									continue;

								musig_partial_sig_serialize(ctx,
									psig_nb->entries[psig_nb->n_entries].pubnonce,
									&psig);
								psig_nb->entries[psig_nb->n_entries].node_idx = ni;
								psig_nb->entries[psig_nb->n_entries].signer_slot = slot;
								psig_nb->n_entries++;
							}

							uint8_t pbuf[MAX_WIRE_BUF];
							size_t plen = nonce_bundle_serialize(
								psig_nb, pbuf, sizeof(pbuf));
							send_factory_msg(cmd, peer_id,
								SS_SUBMSG_PSIG_BUNDLE,
								pbuf, plen);

							plugin_log(plugin_handle, LOG_INFORM,
								   "Client: sent PSIG_BUNDLE "
								   "(%zu psigs)", psig_nb->n_entries);
							free(psig_nb);
						}
					}
				}
			} else {
				/* Multi-client: wait for ALL_NONCES to get
				 * other clients' nonces before finalizing */
				plugin_log(plugin_handle, LOG_INFORM,
					   "Client: sent NONCE_BUNDLE, waiting "
					   "for ALL_NONCES (%u participants)",
					   nb->n_participants);
			}

			fi->ceremony = CEREMONY_PROPOSED;
			/* Task #151: start the client-side self-timeout
			 * clock so a silent LSP doesn't strand us in
			 * PROPOSED forever. */
			fi->ceremony_started_block = ss_state.current_blockheight;
			free(pubkeys);
			free(nb);
			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: sent NONCE_BUNDLE (%zu bytes)",
				   4 + rlen);
		}
		break;

	case SS_SUBMSG_NONCE_BUNDLE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "NONCE_BUNDLE from %s (len=%zu)",
			   peer_id, len);
		/* LSP side: deserialize client nonces, set on sessions.
		 * When all clients responded, finalize and send ALL_NONCES. */
		plugin_log(plugin_handle, LOG_INFORM,
			   "NONCE_BUNDLE: fi=%s is_lsp=%d",
			   fi ? "found" : "NULL",
			   fi ? fi->is_lsp : -1);
		/* Audit #5 follow-up: stale-msg guard. After restart, in-memory
		 * MuSig2 sessions are gone — see lib task #80. If we receive a
		 * NONCE_BUNDLE while the ceremony isn't actively collecting
		 * nonces, send CEREMONY_ABORT(OTHER) so the sender stops
		 * retrying and skip the broken finalize path. */
		if (fi && fi->is_lsp && !ss_ceremony_expecting_nonces(fi)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "NONCE_BUNDLE from %s rejected: ceremony=%d "
				   "(stale post-restart? lib task #80)",
				   peer_id, (int)fi->ceremony);
			ss_send_factory_abort(cmd, peer_id, fi->instance_id, SS_CEREMONY_ABORT_OTHER);
			break;
		}
		if (fi && fi->is_lsp) {
			/* Heap-allocate: 79KB with MAX_NONCE_ENTRIES=1024 */
			nonce_bundle_t *cnb = calloc(1, sizeof(*cnb));
			if (!cnb) break;
			if (!nonce_bundle_deserialize(cnb, data, len)) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "Bad NONCE_BUNDLE");
				free(cnb);
				break;
			}

			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) { free(cnb); break; }

			secp256k1_context *ctx = global_secp_ctx;

			/* Set client nonces on sessions */
			size_t nonces_set = 0;
			for (size_t e = 0; e < cnb->n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				if (!musig_pubnonce_parse(ctx, &pn,
					cnb->entries[e].pubnonce)) {
					/* Dump first 8 bytes for debug */
					plugin_log(plugin_handle, LOG_BROKEN,
						   "LSP: bad pubnonce entry %zu "
						   "node=%u slot=%u "
						   "bytes=%02x%02x%02x%02x%02x%02x%02x%02x",
						   e, cnb->entries[e].node_idx,
						   cnb->entries[e].signer_slot,
						   cnb->entries[e].pubnonce[0],
						   cnb->entries[e].pubnonce[1],
						   cnb->entries[e].pubnonce[2],
						   cnb->entries[e].pubnonce[3],
						   cnb->entries[e].pubnonce[4],
						   cnb->entries[e].pubnonce[5],
						   cnb->entries[e].pubnonce[6],
						   cnb->entries[e].pubnonce[7]);
					continue;
				}
				if (!factory_session_set_nonce(f,
					cnb->entries[e].node_idx,
					cnb->entries[e].signer_slot,
					&pn)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "LSP: set_nonce failed "
						   "node=%u slot=%u",
						   cnb->entries[e].node_idx,
						   cnb->entries[e].signer_slot);
					continue;
				}
				nonces_set++;
			}

			/* Cache this client's nonce entries for ALL_NONCES */
			{
				nonce_entry_t *cache =
					(nonce_entry_t *)fi->cached_nonces;
				if (cache && fi->n_cached_nonces + cnb->n_entries
				    <= fi->cached_nonces_cap) {
					memcpy(cache + fi->n_cached_nonces,
					       cnb->entries,
					       cnb->n_entries
					       * sizeof(nonce_entry_t));
					fi->n_cached_nonces += cnb->n_entries;
				}
			}

			/* Find which client sent this */
			client_state_t *cl = NULL;
			size_t cl_ci = SIZE_MAX;
			if (strlen(peer_id) == 66) {
				uint8_t pid[33];
				for (int j = 0; j < 33; j++) {
					unsigned int b;
					sscanf(peer_id + j*2, "%02x", &b);
					pid[j] = (uint8_t)b;
				}
				for (size_t xci = 0; xci < fi->n_clients; xci++) {
					if (memcmp(fi->clients[xci].node_id, pid, 33) == 0) {
						cl = &fi->clients[xci];
						cl_ci = xci;
						break;
					}
				}
			}
			if (cl) {
				cl->nonce_received = true;
				cl->propose_retry_count = 0; /* Bug B: round complete */
				/* Extract real factory pubkey from client's bundle.
				 * Client populates pubkeys[own_slot] where slot=ci+1. */
				size_t client_slot = cl_ci + 1; /* 0=LSP, 1..n=clients */
				if (client_slot < cnb->n_participants
				    && cnb->pubkeys[client_slot][0] != 0) {
					memcpy(cl->factory_pubkey,
					       cnb->pubkeys[client_slot], 33);
					cl->has_factory_pubkey = true;
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: stored real pubkey for "
						   "client %zu", cl_ci);
				}
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: matched client, nonce_received=true");
			} else {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "LSP: could not match peer to client list");
				/* Force it for single-client demo */
				if (fi->n_clients == 1) {
					fi->clients[0].nonce_received = true;
					fi->clients[0].propose_retry_count = 0; /* Bug B */
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: forced nonce_received for solo client");
				}
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "LSP: set %zu/%zu client nonces",
				   nonces_set, cnb->n_entries);

			/* Debug: log session state before finalize */
			for (size_t di = 0; di < f->n_nodes; di++) {
				plugin_log(plugin_handle, LOG_INFORM,
					   "Node %zu: n_signers=%zu collected=%d",
					   di, (size_t)f->nodes[di].n_signers,
					   f->nodes[di].signing_session.nonces_collected);
			}

			/* Check if all clients responded */
			if (ss_factory_all_nonces_received(fi)) {
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: all nonces collected");

				/* If LSP and no real funding yet, create
				 * on-chain funding TX before continuing.
				 * Compute aggregate P2TR key from all real
				 * pubkeys and call withdraw. */
				if (fi->is_lsp && fi->funding_spk_len == 0) {
					/* Collect real pubkeys for aggregate */
					size_t nt = 1 + fi->n_clients;
					secp256k1_pubkey *apks =
						calloc(nt, sizeof(secp256k1_pubkey));
					bool agg_ok = apks != NULL;
					if (agg_ok)
						agg_ok = secp256k1_ec_pubkey_create(
							global_secp_ctx,
							&apks[0],
							fi->our_seckey) != 0;
					for (size_t ac = 0;
					     ac < fi->n_clients && agg_ok; ac++) {
						if (fi->clients[ac].has_factory_pubkey) {
							agg_ok = secp256k1_ec_pubkey_parse(
								global_secp_ctx,
								&apks[ac + 1],
								fi->clients[ac].factory_pubkey,
								33) != 0;
						} else {
							unsigned char psk[32];
							derive_placeholder_seckey(
								psk, fi->instance_id,
								(int)(ac + 1));
							agg_ok = secp256k1_ec_pubkey_create(
								global_secp_ctx,
								&apks[ac + 1],
								psk) != 0;
						}
					}

					if (agg_ok) {
						/* Build a temporary tree with placeholder
						 * funding to get the TWEAKED P2TR key
						 * for the root kickoff node. The library
						 * applies a BIP-341 taproot tweak to the
						 * aggregate key — the on-chain UTXO must
						 * be locked to this tweaked key, not the
						 * plain aggregate. */
						factory_t *tmp_f = calloc(1, sizeof(factory_t));
						factory_init_from_pubkeys(tmp_f,
							global_secp_ctx,
							apks, nt,
							DW_STEP_BLOCKS, 16);
						factory_set_arity(tmp_f, ss_effective_arity(fi));
						uint8_t ph_txid[32], ph_spk[34];
						for (int j = 0; j < 32; j++)
							ph_txid[j] = j + 1;
						ph_spk[0] = 0x51; ph_spk[1] = 0x20;
						memset(ph_spk + 2, 0xAA, 32);
						factory_set_funding(tmp_f, ph_txid, 0,
							fi->funding_amount_sats,
							ph_spk, 34);
						factory_set_lifecycle(tmp_f,
							ss_state.current_blockheight,
							4320, 432);
						/* Match the MAIN factory-create path (which
						 * sets flat_secrets before build_tree in
						 * PR #3). If the tmp tree diverges from the
						 * real tree on has_shachain, downstream
						 * sighashes / key derivations disagree. Keep
						 * both paths bit-identical. */
						if (ss_state.has_master_key) {
							static unsigned char
								tmp_secrets[256][32];
							derive_l_stock_secrets(
								tmp_secrets, 256,
								fi->instance_id);
							factory_set_flat_secrets(tmp_f,
								(const unsigned char (*)[32])
								tmp_secrets, 256);
						}
						/* factory_build_tree returns 0 on validation
						 * failure (e.g. funding below min, invalid
						 * participant count, lib version mismatch). It
						 * logs to STDERR which the plugin-manager
						 * doesn't capture — so a silent failure here
						 * leaves tmp_f->nodes[0].spending_spk_len == 0,
						 * and we copy zero bytes into fctx->funding_spk.
						 * The tal-allocated fctx then has uninitialized
						 * memory at spending_spk's slot, and
						 * segwit_addr_encode encodes that garbage into
						 * the withdraw destination — real sats out to
						 * a degenerate P2TR. Check explicitly. */
						if (!factory_build_tree(tmp_f)) {
							plugin_log(plugin_handle, LOG_BROKEN,
								"factory_build_tree(tmp_f) failed "
								"— aborting funding TX. This is "
								"usually a validation error from the "
								"library (funding below min, bad "
								"participant count, or config "
								"mismatch). stderr has details.");
							factory_free(tmp_f);
							free(tmp_f);
							free(apks);
							free(cnb);
							ss_terminalize_failed(cmd, fi, SS_CEREMONY_ABORT_OTHER);
							(void)notification_handled(cmd);
							return;
						}

						/* Extract the root node's tweaked P2TR
						 * scriptPubKey — this is what the
						 * on-chain UTXO must be locked to. */
						struct funding_ctx *fctx =
							tal(cmd, struct funding_ctx);
						fctx->fi = fi;
						memcpy(fctx->funding_spk,
						       tmp_f->nodes[0].spending_spk,
						       tmp_f->nodes[0].spending_spk_len);
						fctx->funding_spk_len =
							tmp_f->nodes[0].spending_spk_len;
						/* Defense in depth: if somehow the copy left
						 * us with a non-34-byte spk (the library
						 * always populates 34 on success, but older
						 * library versions may differ), reject before
						 * we broadcast. */
						if (fctx->funding_spk_len != 34) {
							plugin_log(plugin_handle, LOG_BROKEN,
								"tmp_f->nodes[0].spending_spk_len "
								"= %zu (expected 34) — aborting.",
								fctx->funding_spk_len);
							factory_free(tmp_f);
							free(tmp_f);
							free(apks);
							free(cnb);
							ss_terminalize_failed(cmd, fi, SS_CEREMONY_ABORT_OTHER);
							(void)notification_handled(cmd);
							return;
						}

						/* Encode bech32m address from tweaked key
						 * (skip OP_1 0x20 prefix = bytes 2-33) */
						char addr[100];
						segwit_addr_encode(addr,
							chainparams->onchain_hrp,
							1, fctx->funding_spk + 2, 32);

						factory_free(tmp_f);
						free(tmp_f);

						plugin_log(plugin_handle, LOG_INFORM,
							   "Creating funding TX: "
							   "withdraw %"PRIu64" to %s",
							   fi->funding_amount_sats,
							   addr);

						/* Persist factory state BEFORE broadcasting the
						 * funding TX. If the withdraw succeeds on-chain
						 * but the plugin crashes before the callback
						 * runs, the instance_id and participant set
						 * would otherwise be lost — the funds would be
						 * stuck at the funding address with no way to
						 * derive the keys needed to spend them.
						 *
						 * We also need funding_spk on fi at this point
						 * so startup reconciliation (checking whether a
						 * funding UTXO appeared for us) has something to
						 * match against. The funding_txid itself is
						 * filled in later by withdraw_funding_ok. */
						memcpy(fi->funding_spk,
						       fctx->funding_spk,
						       fctx->funding_spk_len);
						fi->funding_spk_len = fctx->funding_spk_len;
						ss_save_factory(cmd, fi);

						/* Call withdraw RPC */
						struct out_req *wreq =
							jsonrpc_request_start(cmd,
								"withdraw",
								withdraw_funding_ok,
								withdraw_funding_err,
								fctx);
						json_add_string(wreq->js,
							"destination", addr);
						{
							char amt_str[32];
							snprintf(amt_str, sizeof(amt_str),
								 "%"PRIu64"sat",
								 fi->funding_amount_sats);
							json_add_string(wreq->js,
								"satoshi", amt_str);
						}
						/* Phase 4 + audit #5 follow-up: always pass an explicit
						 * feerate so CLN never tries to auto-estimate (which
						 * fails on test networks where the estimator isn't
						 * primed — "Cannot estimate fees (yet)").
						 *
						 * Caller value via factory-create feerate_perkw param;
						 * otherwise fall back to 1000 perkw (~4 sat/vbyte),
						 * which is conservative for any network. signet practice
						 * runs pass 100 perkw (0.4 sat/vb). */
						{
							uint32_t fr_perkw = fi->requested_feerate_perkw > 0
								? fi->requested_feerate_perkw
								: 253; /* 1 sat/vb floor; CLN min_acceptable */
							char fr_str[32];
							snprintf(fr_str, sizeof(fr_str),
								 "%uperkw", fr_perkw);
							json_add_string(wreq->js,
								"feerate", fr_str);
							plugin_log(plugin_handle, LOG_INFORM,
								   "withdraw feerate=%uperkw "
								   "(requested=%u, fallback=%s)",
								   fr_perkw,
								   fi->requested_feerate_perkw,
								   fi->requested_feerate_perkw > 0
									? "no" : "yes");
						}
						send_outreq(wreq);

						fi->ceremony = CEREMONY_FUNDING_PENDING;
						free(apks);
						free(cnb);
						break; /* wait for callback */
					}
					free(apks);
				}

				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: finalizing nonce collection");

				/* Rebuild DW tree with real pubkeys collected
				 * from NONCE_BUNDLE responses. Uses the same
				 * tree topology (n_nodes unchanged), but correct
				 * key aggregation for MuSig2 challenge computation.
				 * LSP uses its own real key (fi->our_seckey),
				 * clients use factory_pubkey from their bundles. */
				{
					size_t n_total = 1 + fi->n_clients;
					secp256k1_pubkey *real_pks =
						calloc(n_total, sizeof(secp256k1_pubkey));
					bool rebuild_ok = false;
					if (real_pks) {
						/* LSP pubkey from our_seckey */
						rebuild_ok = secp256k1_ec_pubkey_create(
							global_secp_ctx,
							&real_pks[0],
							fi->our_seckey) != 0;
						/* Client pubkeys */
						for (size_t rci = 0;
						     rci < fi->n_clients && rebuild_ok; rci++) {
							if (!fi->clients[rci].has_factory_pubkey) {
								plugin_log(plugin_handle,
									   LOG_UNUSUAL,
									   "LSP: client %zu "
									   "has no real pubkey, "
									   "using placeholder",
									   rci);
								unsigned char psk[32];
								derive_placeholder_seckey(
									psk, fi->instance_id,
									(int)(rci + 1));
								rebuild_ok = secp256k1_ec_pubkey_create(
									global_secp_ctx,
									&real_pks[rci + 1],
									psk) != 0;
							} else {
								if (!secp256k1_ec_pubkey_parse(
									global_secp_ctx,
									&real_pks[rci + 1],
									fi->clients[rci].factory_pubkey,
									33)) {
									plugin_log(plugin_handle,
										   LOG_BROKEN,
										   "LSP: bad pubkey "
										   "for client %zu",
										   rci);
									rebuild_ok = false;
									break;
								}
							}
						}
					}

					if (rebuild_ok && real_pks) {
						/* Allocate new factory with real pubkeys */
						factory_t *new_f = calloc(1, sizeof(factory_t));
						factory_init_from_pubkeys(new_f, global_secp_ctx,
							real_pks, n_total,
							DW_STEP_BLOCKS, 16);
						factory_set_arity(new_f,
							ss_effective_arity(fi));
						/* Use real funding if available, else synthetic */
						if (fi->funding_spk_len > 0) {
							factory_set_funding(new_f,
								fi->funding_txid,
								fi->funding_outnum,
								fi->funding_amount_sats,
								fi->funding_spk,
								fi->funding_spk_len);
						} else {
							uint8_t syn_txid[32], syn_spk[34];
							for (int j = 0; j < 32; j++) syn_txid[j] = j + 1;
							syn_spk[0] = 0x51; syn_spk[1] = 0x20;
							memset(syn_spk + 2, 0xAA, 32);
							factory_set_funding(new_f, syn_txid, 0,
								fi->funding_amount_sats > 0
									? fi->funding_amount_sats
									: DEFAULT_FACTORY_FUNDING_SATS,
								syn_spk, 34);
						}
						factory_set_lifecycle(new_f,
							ss_state.current_blockheight,
							4320, 432);
						factory_build_tree(new_f);

						/* Apply allocations (if any) so leaf
						 * amounts match what we signed. */
						apply_allocations_to_leaves(fi, new_f, n_total);

						/* Free old factory, swap in new */
						factory_t *old_f = (factory_t *)fi->lib_factory;
						if (old_f) {
							factory_free(old_f);
							free(old_f);
						}
						fi->lib_factory = new_f;
						f = new_f;

						/* Gap 9: snapshot keyagg state on this
						 * client-side rebuild path (post-PROPOSE
						 * with real funding). Force a save now
						 * so the blob is durable before we begin
						 * sending PSIG — the existing PROPOSE
						 * handler doesn't otherwise persist meta
						 * here. */
						ss_keyagg_snapshot_capture(fi);
						ss_save_factory(cmd, fi);

						/* Re-init sessions then re-set all nonces
						 * from cache (LSP's + all clients') */
						factory_sessions_init(f);
						nonce_entry_t *cache2 =
							(nonce_entry_t *)fi->cached_nonces;
						if (cache2) {
							for (size_t ne = 0;
							     ne < fi->n_cached_nonces; ne++) {
								secp256k1_musig_pubnonce pn2;
								if (musig_pubnonce_parse(
									global_secp_ctx, &pn2,
									cache2[ne].pubnonce)) {
									factory_session_set_nonce(
										f,
										cache2[ne].node_idx,
										cache2[ne].signer_slot,
										&pn2);
								}
							}
						}
						plugin_log(plugin_handle, LOG_INFORM,
							   "LSP: rebuilt tree with real "
							   "pubkeys (%zu participants)",
							   n_total);
					}
					free(real_pks);
				}

				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: calling factory_sessions_finalize...");

				if (!factory_sessions_finalize(f)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "factory_sessions_finalize failed");
					free(cnb);
					break;
				}

				fi->ceremony = CEREMONY_NONCES_COLLECTED;
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: nonces finalized! ceremony=nonces_collected");

				/* For 2-party mode, the client already sent
				 * both nonces AND psigs together, skipping
				 * the ALL_NONCES round. For 3+ participants,
				 * broadcast ALL_NONCES from cache so clients
				 * can finalize and create partial sigs. */
				if (fi->n_clients > 1) {
					nonce_entry_t *cache =
						(nonce_entry_t *)fi->cached_nonces;
					if (!cache || fi->n_cached_nonces == 0) {
						plugin_log(plugin_handle, LOG_BROKEN,
							   "LSP: no cached nonces "
							   "for ALL_NONCES");
					} else {
						/* Heap-allocate: 79KB with 1024 entries */
						nonce_bundle_t *all_nb = calloc(1, sizeof(*all_nb));
						if (all_nb) {
							memcpy(all_nb->instance_id,
								fi->instance_id, 32);
							all_nb->n_participants =
								1 + fi->n_clients;
							factory_t *af =
								(factory_t *)fi->lib_factory;
							all_nb->n_nodes = af ?
								af->n_nodes : 0;

							/* Include real pubkeys so clients
							 * can rebuild tree with correct
							 * key aggregation.
							 * [0] = LSP, [1..n] = clients */
							{
								size_t pk_out = 33;
								secp256k1_pubkey lsp_pub;
								if (secp256k1_ec_pubkey_create(
									global_secp_ctx,
									&lsp_pub,
									fi->our_seckey))
									secp256k1_ec_pubkey_serialize(
										global_secp_ctx,
										all_nb->pubkeys[0],
										&pk_out, &lsp_pub,
										SECP256K1_EC_COMPRESSED);
								for (size_t rci = 0;
								     rci < fi->n_clients; rci++) {
									if (fi->clients[rci].has_factory_pubkey)
										memcpy(all_nb->pubkeys[rci + 1],
										       fi->clients[rci].factory_pubkey,
										       33);
								}
							}

							/* Copy cached entries */
							size_t n = fi->n_cached_nonces;
							if (n > MAX_NONCE_ENTRIES)
								n = MAX_NONCE_ENTRIES;
							memcpy(all_nb->entries, cache,
							       n * sizeof(nonce_entry_t));
							all_nb->n_entries = n;

							uint8_t *anbuf = calloc(1, MAX_WIRE_BUF);
							size_t anlen =
								nonce_bundle_serialize(
									all_nb, anbuf,
									MAX_WIRE_BUF);
							free(all_nb);

							/* Cache wire payload for reconnect recovery */
							free(fi->cached_all_nonces_wire);
							fi->cached_all_nonces_wire = malloc(anlen);
							if (fi->cached_all_nonces_wire) {
								memcpy(fi->cached_all_nonces_wire,
								       anbuf, anlen);
								fi->cached_all_nonces_len = anlen;
							}

							for (size_t ci = 0;
							     ci < fi->n_clients; ci++) {
								char nid[67];
								for (int j = 0; j < 33; j++)
									sprintf(nid + j*2,
										"%02x",
										fi->clients[ci].node_id[j]);
								nid[66] = '\0';
								send_factory_msg(cmd, nid,
									SS_SUBMSG_ALL_NONCES,
									anbuf, anlen);
							}
							free(anbuf);
							plugin_log(plugin_handle,
								   LOG_INFORM,
								   "LSP: sent ALL_NONCES "
								   "to %zu clients "
								   "(%zu entries)",
								   fi->n_clients, n);
						}
					}

					/* Free nonce cache */
					free(fi->cached_nonces);
					fi->cached_nonces = NULL;
					fi->n_cached_nonces = 0;
				}
			}

			free(cnb);
			/* ctx is global */
		}
		break;

	case SS_SUBMSG_ALL_NONCES:
		plugin_log(plugin_handle, LOG_INFORM,
			   "ALL_NONCES from %s (len=%zu)",
			   peer_id, len);
		/* Client: LSP sent all aggregated nonces. Rebuild tree with
		 * real pubkeys, set nonces, finalize, create partial sigs. */
		if (fi && !fi->is_lsp) {
			/* Heap-allocate both bundles: 79KB each with 1024 entries */
			nonce_bundle_t *anb = calloc(1, sizeof(*anb));
			if (!anb) break;
			if (!nonce_bundle_deserialize(anb, data, len)) {
				free(anb);
				break;
			}
			/* Tier 2.6: re-adopt LSP's arity_mode. Usually identical
			 * to what FACTORY_PROPOSE delivered, but we trust the
			 * most recent signal in case a legacy FACTORY_PROPOSE
			 * lacked the trailer. */
			if (anb->arity_mode != 0)
				fi->arity_mode = anb->arity_mode;
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) { free(anb); break; }
			secp256k1_context *ctx = global_secp_ctx;

			/* Rebuild tree with real pubkeys from ALL_NONCES bundle.
			 * ALL_NONCES carries pubkeys[0..n_participants-1]:
			 *   [0] = LSP real pubkey, [1..n] = client real pubkeys.
			 * This ensures MuSig2 challenge uses correct key aggregation. */
			if (anb->n_participants > 1
			    && anb->pubkeys[0][0] != 0) {
				secp256k1_pubkey *real_pks =
					calloc(anb->n_participants,
					       sizeof(secp256k1_pubkey));
				bool all_valid = real_pks != NULL;
				for (uint32_t rpi = 0;
				     rpi < anb->n_participants && all_valid; rpi++) {
					if (anb->pubkeys[rpi][0] == 0) {
						/* Missing pubkey — fall back to placeholder */
						unsigned char psk[32];
						derive_placeholder_seckey(
							psk, fi->instance_id,
							(int)rpi);
						if (!secp256k1_ec_pubkey_create(
							ctx, &real_pks[rpi], psk))
							all_valid = false;
					} else if (!secp256k1_ec_pubkey_parse(
						ctx, &real_pks[rpi],
						anb->pubkeys[rpi], 33)) {
						all_valid = false;
					}
				}
				if (all_valid) {
					factory_t *new_f = calloc(1, sizeof(factory_t));
					factory_init_from_pubkeys(new_f, ctx,
						real_pks, anb->n_participants,
						DW_STEP_BLOCKS, 16);
					factory_set_arity(new_f, ss_effective_arity(fi));
					/* Use real funding from ALL_NONCES if available */
					if (anb->funding_spk_len > 0) {
						factory_set_funding(new_f,
							anb->funding_txid,
							anb->funding_vout,
							anb->funding_amount_sats,
							anb->funding_spk,
							anb->funding_spk_len);
						/* Store on fi for persistence */
						memcpy(fi->funding_txid,
						       anb->funding_txid, 32);
						fi->funding_outnum = anb->funding_vout;
						fi->funding_amount_sats =
							anb->funding_amount_sats;
						memcpy(fi->funding_spk,
						       anb->funding_spk,
						       anb->funding_spk_len);
						fi->funding_spk_len =
							anb->funding_spk_len;
						plugin_log(plugin_handle, LOG_INFORM,
							   "Client: using real "
							   "funding from ALL_NONCES");
					} else {
						uint8_t syn_txid[32], syn_spk[34];
						for (int j = 0; j < 32; j++)
							syn_txid[j] = j + 1;
						syn_spk[0] = 0x51; syn_spk[1] = 0x20;
						memset(syn_spk + 2, 0xAA, 32);
						factory_set_funding(new_f, syn_txid, 0,
							fi->funding_amount_sats > 0
							? fi->funding_amount_sats
							: DEFAULT_FACTORY_FUNDING_SATS,
							syn_spk, 34);
					}
					factory_set_lifecycle(new_f,
						ss_state.current_blockheight,
						4320, 432);
					factory_build_tree(new_f);

					/* Apply allocations so our leaves match the
					 * LSP's post-rebuild state. */
					apply_allocations_to_leaves(fi, new_f,
						anb->n_participants);

					factory_t *old_f = f;
					factory_free(old_f);
					free(old_f);
					fi->lib_factory = new_f;
					f = new_f;

					/* Gap 9: snapshot keyagg state on the
					 * client-side ALL_NONCES rebuild — this
					 * is the tree we're about to PSIG with
					 * real pubkeys, so the cache here is
					 * what we need to restore on reload.
					 * Force a save so the blob is durable
					 * before PSIG. */
					ss_keyagg_snapshot_capture(fi);
					ss_save_factory(cmd, fi);

					plugin_log(plugin_handle, LOG_INFORM,
						   "Client: rebuilt tree with real "
						   "pubkeys from ALL_NONCES");
				}
				free(real_pks);
			}

			/* Re-init sessions: resets nonces_collected to 0.
			 * FACTORY_PROPOSE already set LSP+own nonces, so
			 * nonces_collected > 0. Must re-init before setting
			 * all 18 nonces from ALL_NONCES. */
			factory_sessions_init(f);

			/* Set all nonces from the bundle */
			size_t set_count = 0;
			for (size_t e = 0; e < anb->n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				if (!musig_pubnonce_parse(ctx, &pn,
					anb->entries[e].pubnonce))
					continue;
				factory_session_set_nonce(f,
					anb->entries[e].node_idx,
					anb->entries[e].signer_slot, &pn);
				set_count++;
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: set %zu/%zu nonces from ALL_NONCES",
				   set_count, anb->n_entries);

			/* Finalize all sessions */
			if (!factory_sessions_finalize(f)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Client: finalize after ALL_NONCES failed");
				free(anb);
				break;
			}

			fi->ceremony = CEREMONY_NONCES_COLLECTED;

			/* Create partial sigs and send PSIG_BUNDLE */
			unsigned char our_sec[32];
			derive_factory_seckey(our_sec, fi->instance_id,
				fi->our_participant_idx);
			secp256k1_keypair kp;
			if (!secp256k1_keypair_create(ctx, &kp, our_sec)) {
				free(anb);
				break;
			}

			nonce_bundle_t *psig_nb = calloc(1, sizeof(*psig_nb));
			if (!psig_nb) { free(anb); break; }
			memcpy(psig_nb->instance_id, fi->instance_id, 32);
			psig_nb->n_participants = anb->n_participants;
			psig_nb->n_nodes = f->n_nodes;
			psig_nb->n_entries = 0;

			musig_nonce_pool_t *sp =
				(musig_nonce_pool_t *)fi->nonce_pool;
			for (size_t si = 0; si < fi->n_secnonces; si++) {
				uint32_t pi = fi->secnonce_pool_idx[si];
				uint32_t ni = fi->secnonce_node_idx[si];
				secp256k1_musig_secnonce *sn =
					&sp->nonces[pi].secnonce;

				int slot = factory_find_signer_slot(
					f, ni, fi->our_participant_idx);
				if (slot < 0) continue;

				secp256k1_musig_partial_sig psig;
				if (!musig_create_partial_sig(
					ctx, &psig, sn, &kp,
					&f->nodes[ni].signing_session))
					continue;

				musig_partial_sig_serialize(ctx,
					psig_nb->entries[psig_nb->n_entries].pubnonce,
					&psig);
				psig_nb->entries[psig_nb->n_entries].node_idx = ni;
				psig_nb->entries[psig_nb->n_entries].signer_slot = slot;
				psig_nb->n_entries++;
			}

			uint8_t *pbuf = calloc(1, MAX_WIRE_BUF);
			size_t plen = 0;
			if (pbuf)
				plen = nonce_bundle_serialize(
					psig_nb, pbuf, MAX_WIRE_BUF);
			send_factory_msg(cmd, peer_id,
				SS_SUBMSG_PSIG_BUNDLE, pbuf, plen);

			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: sent PSIG_BUNDLE from ALL_NONCES "
				   "(%zu partial sigs, %zu bytes)",
				   psig_nb->n_entries, plen);
			free(pbuf);
			free(psig_nb);
			free(anb);
		}
		break;

	case SS_SUBMSG_PSIG_BUNDLE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "PSIG_BUNDLE from %s (len=%zu)",
			   peer_id, len);
		/* Audit #5 follow-up: stale-msg guard. See NONCE_BUNDLE case for
		 * rationale (post-restart, in-memory MuSig2 session is gone). */
		if (fi && fi->is_lsp && !ss_ceremony_expecting_psigs(fi)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "PSIG_BUNDLE from %s rejected: ceremony=%d "
				   "(stale post-restart? lib task #80)",
				   peer_id, (int)fi->ceremony);
			ss_send_factory_abort(cmd, peer_id, fi->instance_id, SS_CEREMONY_ABORT_OTHER);
			break;
		}
				if (fi && fi->is_lsp) {
			/* Heap-allocate: 79KB with MAX_NONCE_ENTRIES=1024 */
			nonce_bundle_t *pnb = calloc(1, sizeof(*pnb));
			if (!pnb) break;
			if (!nonce_bundle_deserialize(pnb, data, len)) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "Bad PSIG_BUNDLE");
				free(pnb);
				break;
			}

			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) { free(pnb); break; }

			/* Set client partial sigs */
			size_t psigs_set = 0;
			for (size_t e = 0; e < pnb->n_entries; e++) {
				secp256k1_musig_partial_sig ps;
				if (!musig_partial_sig_parse(global_secp_ctx,
					&ps, pnb->entries[e].pubnonce)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "LSP: bad psig entry %zu", e);
					continue;
				}
				if (!factory_session_set_partial_sig(f,
					pnb->entries[e].node_idx,
					pnb->entries[e].signer_slot,
					&ps)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "LSP: set_partial_sig failed %zu", e);
					continue;
				}
				psigs_set++;
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "LSP: set %zu/%zu client partial sigs",
				   psigs_set, pnb->n_entries);

			/* Track which client sent this */
			if (strlen(peer_id) == 66) {
				uint8_t pid[33];
				for (int j = 0; j < 33; j++) {
					unsigned int b;
					sscanf(peer_id + j*2, "%02x", &b);
					pid[j] = (uint8_t)b;
				}
				client_state_t *pcl =
					ss_factory_find_client(fi, pid);
				if (pcl)
					pcl->psig_received = true;
				else if (fi->n_clients == 1)
					fi->clients[0].psig_received = true;
			}

			/* Wait for ALL clients before LSP signs + completes */
			if (!ss_factory_all_psigs_received(fi)) {
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: waiting for more PSIG_BUNDLEs");
				free(pnb);
				break;
			}

			/* All clients have sent psigs — create LSP's own */
			{
				secp256k1_keypair lsp_kp;
				if (!secp256k1_keypair_create(global_secp_ctx,
					&lsp_kp, fi->our_seckey)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "LSP: keypair create failed");
					free(pnb);
					break;
				}

				musig_nonce_pool_t *lsp_pool =
					(musig_nonce_pool_t *)fi->nonce_pool;
				size_t lsp_psigs = 0;
				for (size_t si = 0; si < fi->n_secnonces; si++) {
					uint32_t pi = fi->secnonce_pool_idx[si];
					uint32_t ni = fi->secnonce_node_idx[si];
					secp256k1_musig_secnonce *sn =
						&lsp_pool->nonces[pi].secnonce;

					secp256k1_musig_partial_sig psig;
					if (!musig_create_partial_sig(
						global_secp_ctx, &psig, sn,
						&lsp_kp,
						&f->nodes[ni].signing_session)) {
						plugin_log(plugin_handle, LOG_BROKEN,
							   "LSP: partial_sig failed node %u", ni);
						continue;
					}

					int slot = factory_find_signer_slot(
						f, ni, fi->our_participant_idx);
					if (slot < 0) continue;

					if (!factory_session_set_partial_sig(
						f, ni, (size_t)slot, &psig)) {
						plugin_log(plugin_handle, LOG_BROKEN,
							   "LSP: set own psig failed node %u", ni);
						continue;
					}
					lsp_psigs++;
				}

				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: created %zu own partial sigs",
					   lsp_psigs);
			}

			/* Try to complete — all sigs should be set now */
			if (!factory_sessions_complete(f)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "LSP: factory_sessions_complete failed");
			} else {
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: FACTORY TREE SIGNED!");

				/* Tier 2.6: capture chain[0] for every PS leaf
				 * before any advance overwrites memory. */
				ss_save_all_ps_chain0(cmd, fi);

				/* Build distribution TX (nLockTime fallback).
				 * This TX lets clients recover funds if LSP
				 * vanishes — the core SuperScalar safety net. */
				tx_output_t dist_out[MAX_DIST_OUTPUTS];
				size_t n_dist = factory_compute_distribution_outputs(
					f, dist_out, MAX_DIST_OUTPUTS, 500);

				if (n_dist > 0 && factory_build_distribution_tx_unsigned(
					f, dist_out, n_dist,
					ss_state.current_blockheight + DW_STEP_BLOCKS * DIST_TX_LOCKTIME_DAYS)) {
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: distribution TX built "
						   "(%zu outputs, sighash ready)",
						   n_dist);

					/* Generate nonce for dist TX signing */
					secp256k1_context *dctx = global_secp_ctx;
					unsigned char lsp_sk[32];
					derive_factory_seckey(lsp_sk, fi->instance_id, 0);
					secp256k1_pubkey lsp_pk;
					if (!secp256k1_ec_pubkey_create(dctx, &lsp_pk, lsp_sk)) {
						free(pnb);
						break;
					}

					musig_nonce_pool_t *dpool = calloc(1,
						sizeof(musig_nonce_pool_t));
					musig_nonce_pool_generate(dctx, dpool, 1,
						lsp_sk, &lsp_pk, NULL);

					secp256k1_musig_secnonce *dsec;
					secp256k1_musig_pubnonce dpub;
					musig_nonce_pool_next(dpool, &dsec, &dpub);

					/* Init standalone MuSig2 session for dist TX
					 * using root node's key aggregation */
					musig_signing_session_t *dsess = calloc(1,
						sizeof(musig_signing_session_t));
					musig_session_init(dsess,
						&f->nodes[0].keyagg,
						f->n_participants);
					int lsp_slot = factory_find_signer_slot(
						f, 0, 0);
					if (lsp_slot >= 0)
						musig_session_set_pubnonce(dsess,
							(size_t)lsp_slot, &dpub);
					if (fi->dist_session) free(fi->dist_session);
					fi->dist_session = dsess;
					/* Follow-up #1 3B: reset collected psig
					 * state at the start of each dist ceremony
					 * (initial + each rotation). */
					memset(fi->dist_has_psig, 0,
					       sizeof(fi->dist_has_psig));
					memset(fi->dist_psigs, 0,
					       sizeof(fi->dist_psigs));

					/* For n>2 parties: cache all dist nonces
					 * (LSP's first) so we can broadcast
					 * DIST_ALL_NONCES after collecting clients'. */
					if (fi->n_clients > 1) {
						if (fi->cached_nonces)
							free(fi->cached_nonces);
						fi->cached_nonces_cap = MAX_NONCE_ENTRIES;
						fi->cached_nonces = calloc(
							fi->cached_nonces_cap,
							sizeof(nonce_entry_t));
						fi->n_cached_nonces = 0;
						if (fi->cached_nonces && lsp_slot >= 0) {
							nonce_entry_t *cache =
								(nonce_entry_t *)fi->cached_nonces;
							musig_pubnonce_serialize(dctx,
								cache[0].pubnonce, &dpub);
							cache[0].node_idx = f->n_nodes;
							cache[0].signer_slot = lsp_slot;
							fi->n_cached_nonces = 1;
						}
					}

					/* Build DIST_PROPOSE payload:
					 * instance_id(32) + dist_tx_hex_len(4)
					 * + dist_tx_hex(var) + nonce(66) */
					uint8_t dpayload[MAX_WIRE_BUF];
					uint8_t *dp = dpayload;
					memcpy(dp, fi->instance_id, 32); dp += 32;
					/* TX length */
					uint32_t txlen = f->dist_unsigned_tx.len;
					dp[0] = (txlen >> 24) & 0xFF;
					dp[1] = (txlen >> 16) & 0xFF;
					dp[2] = (txlen >> 8) & 0xFF;
					dp[3] = txlen & 0xFF;
					dp += 4;
					/* TX data */
					memcpy(dp, f->dist_unsigned_tx.data, txlen);
					dp += txlen;
					/* LSP nonce */
					musig_pubnonce_serialize(dctx, dp, &dpub);
					dp += 66;

					size_t dplen = (size_t)(dp - dpayload);

					/* Store dist nonce pool for later signing */
					/* Reuse nonce_pool — tree signing is done */
					if (fi->nonce_pool) free(fi->nonce_pool);
					fi->nonce_pool = dpool;
					fi->n_secnonces = 1;
					fi->secnonce_pool_idx[0] = 0;
					fi->secnonce_node_idx[0] = f->n_nodes;

					/* Send DIST_PROPOSE to all clients */
					for (size_t ci = 0; ci < fi->n_clients; ci++) {
						char nid[67];
						for (int j = 0; j < 33; j++)
							sprintf(nid + j*2, "%02x",
								fi->clients[ci].node_id[j]);
						nid[66] = '\0';
						send_factory_msg(cmd, nid,
							SS_SUBMSG_DIST_PROPOSE,
							dpayload, dplen);
					}

					/* Reset ceremony tracking for dist round */
					ss_factory_reset_ceremony(fi);
					fi->ceremony = CEREMONY_PSIGS_COLLECTED;
					/* No longer need all_nonces cache */
					free(fi->cached_all_nonces_wire);
					fi->cached_all_nonces_wire = NULL;
					fi->cached_all_nonces_len = 0;

					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: sent DIST_PROPOSE to %zu "
						   "clients (%zu bytes)",
						   fi->n_clients, dplen);
				} else {
					/* Distribution TX build failed — proceed
					 * without it (degraded safety) */
					plugin_log(plugin_handle, LOG_UNUSUAL,
						   "LSP: distribution TX build "
						   "failed, proceeding without");
					fi->ceremony = CEREMONY_COMPLETE;
					free(fi->cached_all_nonces_wire);
					fi->cached_all_nonces_wire = NULL;
					fi->cached_all_nonces_len = 0;

					/* Bug C: promote all ACCEPTED join_queue entries to
					 * SIGNED so factory-list stops reporting stale
					 * "join_queue=N" on completed factories and Bug B's
					 * retry path stops re-PROPOSing them. ss_save_factory
					 * below persists the new statuses. */
					for (size_t jqi = 0; jqi < fi->n_join_queue; jqi++) {
						if (fi->join_queue[jqi].status ==
						    JOIN_STATUS_ACCEPTED) {
							fi->join_queue[jqi].status =
								JOIN_STATUS_SIGNED;
							fi->join_queue[jqi].decided_at_block =
								ss_state.current_blockheight;
						}
					}

					size_t ready_bytes = 0;
					for (size_t ci = 0; ci < fi->n_clients; ci++) {
						char nid[67];
						for (int j = 0; j < 33; j++)
							sprintf(nid + j*2, "%02x",
								fi->clients[ci].node_id[j]);
						nid[66] = '\0';
						ready_bytes = ss_send_factory_ready(
							cmd, fi, nid);
					}
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: sent FACTORY_READY (no dist TX, "
						   "%zu bytes incl signed-tree trailer)",
						   ready_bytes);
					ss_save_factory(cmd, fi);
				}
			}
			free(pnb);
		}
		break;

	case SS_SUBMSG_FACTORY_READY:
		plugin_log(plugin_handle, LOG_INFORM,
			   "FACTORY_READY from %s (len=%zu)",
			   peer_id, len);
		/* Client side: factory tree is fully signed.
		 * The LSP will call fundchannel_start which sends us an
		 * open_channel with channel_in_factory TLV.
		 * Our openchannel hook (handle_openchannel) maps it. */
		if (fi) {
			/* Follow-up #1 / sub-PR 3A: if the payload carries a
			 * signed-tree trailer past the 32-byte instance_id, apply
			 * it to our local factory_t so we have signed TXs for
			 * trustless unilateral exit. Legacy LSPs omit the
			 * trailer (len == 32), in which case the client keeps
			 * the historical no-local-sigs behavior. */
			if (len > 32 && fi->lib_factory) {
				if (ss_persist_deserialize_signed_txs(
					fi->lib_factory, data + 32, len - 32)) {
					plugin_log(plugin_handle, LOG_INFORM,
						   "Client: applied %zu bytes of "
						   "signed tree TXs from "
						   "FACTORY_READY trailer",
						   len - 32);
				} else {
					plugin_log(plugin_handle, LOG_UNUSUAL,
						   "Client: failed to parse "
						   "FACTORY_READY signed-tree "
						   "trailer (%zu bytes)",
						   len - 32);
				}
			} else if (len == 32) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "Client: FACTORY_READY has no "
					   "signed-tree trailer — LSP is "
					   "pre-Follow-up-#1; no trustless "
					   "client-side exit available");
			}

			fi->ceremony = CEREMONY_COMPLETE;
			/* Task #151: clear self-timeout clock now that the
			 * ceremony completed cleanly. */
			fi->ceremony_started_block = 0;

			/* Task #92: client-side ceremony complete — promote
			 * lifecycle to SIGNED so factory-list reports the same
			 * state on LSP and client. Deferred clients arrive
			 * here from CEREMONY_RUNNING; legacy clients arrive
			 * from INIT. Either becomes SIGNED. The openchannel
			 * hook (which is the next step) doesn't gate on
			 * lifecycle — it just looks up by instance_id. */
			if (fi->lifecycle == FACTORY_LIFECYCLE_CEREMONY_RUNNING
			    || fi->lifecycle == FACTORY_LIFECYCLE_INIT)
				fi->lifecycle = FACTORY_LIFECYCLE_SIGNED;

			/* With signed TXs now on the client side, chain[0] of
			 * every PS leaf has is_signed=1. Persist them. */
			ss_save_all_ps_chain0(cmd, fi);

			/* Save factory (includes signed_txs via ss_save_factory's
			 * own call to ss_persist_serialize_signed_txs). */
			ss_save_factory(cmd, fi);
		}
		break;

	case SS_SUBMSG_DIST_PROPOSE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "DIST_PROPOSE from %s (len=%zu)",
			   peer_id, len);
		/* Client: LSP sent unsigned distribution TX + nonce.
		 * Parse TX, generate nonce, create partial sig, respond. */
		if (fi && len > 36) {
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) break;
			secp256k1_context *ctx = global_secp_ctx;
			const uint8_t *dp = data + 32; /* skip instance_id */
			size_t rem = len - 32;

			/* Parse TX length + data */
			if (rem < 4) break;
			uint32_t txlen = ((uint32_t)dp[0] << 24) |
				((uint32_t)dp[1] << 16) |
				((uint32_t)dp[2] << 8) | dp[3];
			dp += 4; rem -= 4;
			if (rem < txlen + 66) break;

			/* Store unsigned dist TX in factory */
			tx_buf_init(&f->dist_unsigned_tx, txlen);
			memcpy(f->dist_unsigned_tx.data, dp, txlen);
			f->dist_unsigned_tx.len = txlen;
			f->dist_tx_ready = 1;
			dp += txlen; rem -= txlen;

			/* Parse LSP nonce */
			secp256k1_musig_pubnonce lsp_nonce;
			musig_pubnonce_parse(ctx, &lsp_nonce, dp);

			/* Generate our nonce for dist TX */
			int our_idx = fi->our_participant_idx;
			unsigned char our_sec[32];
			derive_factory_seckey(our_sec, fi->instance_id, our_idx);
			secp256k1_pubkey our_pub;
			if (!secp256k1_ec_pubkey_create(ctx, &our_pub, our_sec))
				break;

			if (fi->nonce_pool) free(fi->nonce_pool);
			musig_nonce_pool_t *pool = calloc(1,
				sizeof(musig_nonce_pool_t));
			musig_nonce_pool_generate(ctx, pool, 1,
				our_sec, &our_pub, NULL);
			fi->nonce_pool = pool;
			fi->n_secnonces = 0;

			secp256k1_musig_secnonce *sec;
			secp256k1_musig_pubnonce pub;
			musig_nonce_pool_next(pool, &sec, &pub);
			fi->secnonce_pool_idx[0] = 0;
			fi->secnonce_node_idx[0] = f->n_nodes;
			fi->n_secnonces = 1;

			/* Init standalone signing session for dist TX
			 * using root node's key aggregation */
			uint32_t dist_idx = f->n_nodes;
			musig_signing_session_t *dsess = calloc(1,
				sizeof(musig_signing_session_t));
			musig_session_init(dsess, &f->nodes[0].keyagg,
				f->n_participants);

			/* Set both nonces on standalone session */
			int lsp_slot = factory_find_signer_slot(f, 0, 0);
			if (lsp_slot >= 0)
				musig_session_set_pubnonce(dsess,
					(size_t)lsp_slot, &lsp_nonce);
			musig_session_set_pubnonce(dsess, our_idx, &pub);

			if (fi->dist_session) free(fi->dist_session);
			fi->dist_session = dsess;

			/* Send DIST_NONCE (heap alloc: 79KB struct) */
			uint32_t saved_n_participants;
			{
				nonce_bundle_t *nresp = calloc(1, sizeof(*nresp));
				if (!nresp) break;
				memcpy(nresp->instance_id, fi->instance_id, 32);
				nresp->n_participants = 1 + fi->n_clients;
				nresp->n_nodes = 1;
				nresp->n_entries = 1;
				nresp->entries[0].node_idx = dist_idx;
				nresp->entries[0].signer_slot = our_idx;
				musig_pubnonce_serialize(ctx,
					nresp->entries[0].pubnonce, &pub);

				uint8_t nbuf[MAX_WIRE_BUF];
				size_t nlen = nonce_bundle_serialize(nresp,
					nbuf, sizeof(nbuf));
				send_factory_msg(cmd, peer_id,
					SS_SUBMSG_DIST_NONCE, nbuf, nlen);
				saved_n_participants = nresp->n_participants;
				free(nresp);
			}

			/* Finalize standalone session with dist sighash */
			if (musig_session_finalize_nonces(ctx, dsess,
				f->dist_sighash, NULL, NULL)) {
				secp256k1_keypair kp;
				if (!secp256k1_keypair_create(ctx, &kp, our_sec))
					break;
				secp256k1_musig_partial_sig psig;
				if (musig_create_partial_sig(ctx, &psig, sec,
					&kp, dsess)) {

					nonce_bundle_t *presp = calloc(1, sizeof(*presp));
					if (presp) {
						memcpy(presp->instance_id, fi->instance_id, 32);
						presp->n_participants = saved_n_participants;
						presp->n_nodes = 1;
						presp->n_entries = 1;
						presp->entries[0].node_idx = dist_idx;
						presp->entries[0].signer_slot = our_idx;
						musig_partial_sig_serialize(ctx,
							presp->entries[0].pubnonce, &psig);

						uint8_t pbuf[MAX_WIRE_BUF];
						size_t plen = nonce_bundle_serialize(
							presp, pbuf, sizeof(pbuf));
						send_factory_msg(cmd, peer_id,
							SS_SUBMSG_DIST_PSIG, pbuf, plen);
						free(presp);

						plugin_log(plugin_handle, LOG_INFORM,
							   "Client: sent DIST_NONCE + DIST_PSIG");
					}
				}
			} else {
				/* n>2: can't finalize yet (missing other clients'
				 * nonces). LSP will broadcast DIST_ALL_NONCES. */
				plugin_log(plugin_handle, LOG_INFORM,
					   "Client: waiting for DIST_ALL_NONCES");
			}
		}
		break;

	case SS_SUBMSG_DIST_NONCE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "DIST_NONCE from %s (len=%zu)", peer_id, len);
		/* LSP: client sent dist nonce — set on session, track reception */
		if (fi && fi->is_lsp) {
			nonce_bundle_t *cnb = calloc(1, sizeof(*cnb));
			if (!cnb) break;
			if (!nonce_bundle_deserialize(cnb, data, len)) {
				free(cnb); break;
			}
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) { free(cnb); break; }
			musig_signing_session_t *dsess =
				(musig_signing_session_t *)fi->dist_session;
			if (!dsess) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "LSP: no dist session");
				free(cnb); break;
			}

			/* Set nonces on session and cache for DIST_ALL_NONCES */
			for (size_t e = 0; e < cnb->n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				if (!musig_pubnonce_parse(global_secp_ctx, &pn,
					cnb->entries[e].pubnonce))
					continue;
				musig_session_set_pubnonce(dsess,
					cnb->entries[e].signer_slot, &pn);
				/* Cache for DIST_ALL_NONCES broadcast */
				if (fi->n_clients > 1 && fi->cached_nonces) {
					nonce_entry_t *cache =
						(nonce_entry_t *)fi->cached_nonces;
					if (fi->n_cached_nonces <
					    fi->cached_nonces_cap) {
						cache[fi->n_cached_nonces] =
							cnb->entries[e];
						fi->n_cached_nonces++;
					}
				}
			}

			/* Mark client as responded */
			if (strlen(peer_id) == 66) {
				uint8_t pid[33];
				for (int j = 0; j < 33; j++) {
					unsigned int b;
					sscanf(peer_id + j*2, "%02x", &b);
					pid[j] = (uint8_t)b;
				}
				client_state_t *cl =
					ss_factory_find_client(fi, pid);
				if (cl) cl->nonce_received = true;
				if (cl) cl->propose_retry_count = 0; /* Bug B: round complete */
				else if (fi->n_clients == 1)
					fi->clients[0].nonce_received = true;
					fi->clients[0].propose_retry_count = 0; /* Bug B */
			}

			/* When all clients responded, finalize and
			 * broadcast DIST_ALL_NONCES (n>2) or wait
			 * for DIST_PSIG (n=2, client sends both together) */
			if (ss_factory_all_nonces_received(fi)) {
				if (!musig_session_finalize_nonces(
					global_secp_ctx, dsess,
					f->dist_sighash, NULL, NULL)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "LSP: dist session finalize "
						   "failed after all nonces");
					free(cnb); break;
				}
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: dist session finalized");
				if (fi->n_clients > 1) {
					/* Broadcast all dist nonces to clients */
					nonce_bundle_t *all_nb =
						calloc(1, sizeof(*all_nb));
					if (all_nb) {
						memcpy(all_nb->instance_id,
							fi->instance_id, 32);
						all_nb->n_participants =
							1 + fi->n_clients;
						all_nb->n_nodes = 1;
						nonce_entry_t *cache =
							(nonce_entry_t *)fi->cached_nonces;
						size_t nc = fi->n_cached_nonces;
						if (nc > MAX_NONCE_ENTRIES)
							nc = MAX_NONCE_ENTRIES;
						memcpy(all_nb->entries, cache,
							nc * sizeof(nonce_entry_t));
						all_nb->n_entries = nc;
						uint8_t *anbuf =
							calloc(1, MAX_WIRE_BUF);
						if (anbuf) {
							size_t anlen =
								nonce_bundle_serialize(
									all_nb, anbuf,
									MAX_WIRE_BUF);
							for (size_t ci = 0;
							     ci < fi->n_clients;
							     ci++) {
								char nid[67];
								for (int j = 0;
								     j < 33; j++)
									sprintf(
										nid+j*2,
										"%02x",
										fi->clients[ci].node_id[j]);
								nid[66] = '\0';
								send_factory_msg(
									cmd, nid,
									SS_SUBMSG_DIST_ALL_NONCES,
									anbuf, anlen);
							}
							plugin_log(plugin_handle,
								LOG_INFORM,
								"LSP: sent DIST_ALL_NONCES "
								"to %zu clients (%zu entries)",
								fi->n_clients, nc);
							free(anbuf);
						}
						free(all_nb);
					}
					free(fi->cached_nonces);
					fi->cached_nonces = NULL;
					fi->n_cached_nonces = 0;
				}
			} else {
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: dist nonce cached, waiting for more");
			}
			free(cnb);
		}
		break;

	case SS_SUBMSG_DIST_ALL_NONCES:
		plugin_log(plugin_handle, LOG_INFORM,
			   "DIST_ALL_NONCES from %s (len=%zu)", peer_id, len);
		/* Client: LSP broadcast all dist nonces. Finalize and send PSIG. */
		if (fi && !fi->is_lsp) {
			nonce_bundle_t *anb = calloc(1, sizeof(*anb));
			if (!anb) break;
			if (!nonce_bundle_deserialize(anb, data, len)) {
				free(anb); break;
			}
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) { free(anb); break; }
			musig_signing_session_t *dsess =
				(musig_signing_session_t *)fi->dist_session;
			if (!dsess) { free(anb); break; }

			/* Re-init to reset nonces_collected (same fix as ALL_NONCES) */
			musig_session_init(dsess, &f->nodes[0].keyagg,
				f->n_participants);

			/* Set all nonces from bundle */
			for (size_t e = 0; e < anb->n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				if (!musig_pubnonce_parse(global_secp_ctx, &pn,
					anb->entries[e].pubnonce))
					continue;
				musig_session_set_pubnonce(dsess,
					anb->entries[e].signer_slot, &pn);
			}

			if (!musig_session_finalize_nonces(global_secp_ctx,
				dsess, f->dist_sighash, NULL, NULL)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Client: dist finalize after ALL failed");
				free(anb); break;
			}

			/* Create partial sig and send DIST_PSIG */
			int our_idx = fi->our_participant_idx;
			unsigned char our_sec[32];
			derive_factory_seckey(our_sec, fi->instance_id, our_idx);
			secp256k1_keypair kp;
			if (!secp256k1_keypair_create(global_secp_ctx, &kp, our_sec)) {
				free(anb); break;
			}
			musig_nonce_pool_t *pool =
				(musig_nonce_pool_t *)fi->nonce_pool;
			if (!pool || fi->n_secnonces == 0) {
				free(anb); break;
			}
			secp256k1_musig_secnonce *sec =
				&pool->nonces[fi->secnonce_pool_idx[0]].secnonce;

			secp256k1_musig_partial_sig psig;
			if (!musig_create_partial_sig(global_secp_ctx, &psig,
				sec, &kp, dsess)) {
				free(anb); break;
			}

			nonce_bundle_t *presp = calloc(1, sizeof(*presp));
			if (!presp) { free(anb); break; }
			memcpy(presp->instance_id, fi->instance_id, 32);
			presp->n_participants = anb->n_participants;
			presp->n_nodes = 1;
			presp->n_entries = 1;
			presp->entries[0].node_idx = f->n_nodes;
			presp->entries[0].signer_slot = our_idx;
			musig_partial_sig_serialize(global_secp_ctx,
				presp->entries[0].pubnonce, &psig);

			uint8_t *pbuf = calloc(1, MAX_WIRE_BUF);
			if (pbuf) {
				size_t plen = nonce_bundle_serialize(presp, pbuf,
					MAX_WIRE_BUF);
				send_factory_msg(cmd, peer_id,
					SS_SUBMSG_DIST_PSIG, pbuf, plen);
				plugin_log(plugin_handle, LOG_INFORM,
					   "Client: sent DIST_PSIG after ALL");
				free(pbuf);
			}
			free(presp);
			free(anb);
		}
		break;

	case SS_SUBMSG_DIST_PSIG:
		plugin_log(plugin_handle, LOG_INFORM,
			   "DIST_PSIG from %s (len=%zu)", peer_id, len);
		/* LSP: client sent dist partial sig.
		 * Track with psig_received. Fire FACTORY_READY once all respond. */
		if (fi && fi->is_lsp) {
			nonce_bundle_t *pnb = calloc(1, sizeof(*pnb));
			if (!pnb) break;
			if (!nonce_bundle_deserialize(pnb, data, len)) {
				free(pnb); break;
			}
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) { free(pnb); break; }

			musig_signing_session_t *dsess =
				(musig_signing_session_t *)fi->dist_session;
			if (!dsess) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "LSP: no dist session for PSIG");
				free(pnb); break;
			}

			/* Follow-up #1 sub-PR 3B: stash this client's partial sig
			 * so we can aggregate once all are in. Client side
			 * serializes the 32-byte psig into the `pubnonce` field
			 * of entry[0] (66-byte buffer; first 32 bytes are the
			 * psig). signer_slot identifies which participant. */
			if (pnb->n_entries > 0 &&
			    pnb->entries[0].signer_slot < MAX_FACTORY_PARTICIPANTS) {
				uint32_t pslot = pnb->entries[0].signer_slot;
				memcpy(fi->dist_psigs[pslot],
				       pnb->entries[0].pubnonce, 32);
				fi->dist_has_psig[pslot] = 1;
			}

			/* Mark this client as responded */
			if (strlen(peer_id) == 66) {
				uint8_t pid[33];
				for (int j = 0; j < 33; j++) {
					unsigned int b;
					sscanf(peer_id + j*2, "%02x", &b);
					pid[j] = (uint8_t)b;
				}
				client_state_t *cl =
					ss_factory_find_client(fi, pid);
				if (cl) cl->psig_received = true;
				else if (fi->n_clients == 1)
					fi->clients[0].psig_received = true;
			}

			if (!ss_factory_all_psigs_received(fi)) {
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: waiting for more DIST_PSIGs");
				free(pnb); break;
			}

			/* All client PSIGs received. Create LSP's own and
			 * stash it into fi->dist_psigs[0] so we can aggregate
			 * all sigs into a single 64-byte Schnorr witness. */
			bool lsp_signed = false;
			secp256k1_musig_partial_sig lsp_psig;
			musig_nonce_pool_t *dpool =
				(musig_nonce_pool_t *)fi->nonce_pool;
			if (dpool && fi->n_secnonces > 0) {
				secp256k1_keypair lsp_kp;
				if (!secp256k1_keypair_create(global_secp_ctx,
					&lsp_kp, fi->our_seckey)) {
					free(pnb); break;
				}
				secp256k1_musig_secnonce *sn =
					&dpool->nonces[0].secnonce;
				if (musig_create_partial_sig(global_secp_ctx,
					&lsp_psig, sn, &lsp_kp, dsess)) {
					lsp_signed = true;
					musig_partial_sig_serialize(
						global_secp_ctx,
						fi->dist_psigs[0], &lsp_psig);
					fi->dist_has_psig[0] = 1;
				} else {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "LSP: dist partial_sig failed");
				}
			}

			if (lsp_signed) {
				f->dist_tx_ready = 2; /* signed */
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: DISTRIBUTION TX SIGNED! "
					   "(%zu clients + LSP)", fi->n_clients);

				/* Follow-up #1 sub-PR 3B: aggregate partial
				 * sigs into the final 64-byte Schnorr witness
				 * and apply via finalize_signed_tx.  Pre-3B
				 * this block just memcpy'd the UNSIGNED bytes
				 * into fi->dist_signed_tx — bitcoind would
				 * reject on expiry auto-broadcast. */
				size_t n_sigs = 1 + fi->n_clients; /* LSP + clients */
				secp256k1_musig_partial_sig *sigs =
					calloc(n_sigs, sizeof(*sigs));
				bool all_parsed = sigs != NULL;
				for (size_t s = 0; s < n_sigs && all_parsed; s++) {
					if (!fi->dist_has_psig[s]) {
						all_parsed = false;
						break;
					}
					if (!musig_partial_sig_parse(
						global_secp_ctx, &sigs[s],
						fi->dist_psigs[s])) {
						all_parsed = false;
					}
				}

				if (all_parsed && f->dist_unsigned_tx.data &&
				    f->dist_unsigned_tx.len > 0) {
					unsigned char schnorr_sig[64];
					if (musig_aggregate_partial_sigs(
						global_secp_ctx, schnorr_sig,
						dsess, sigs, n_sigs)) {
						tx_buf_t out;
						tx_buf_init(&out, f->dist_unsigned_tx.len + 80);
						if (finalize_signed_tx(&out,
							f->dist_unsigned_tx.data,
							f->dist_unsigned_tx.len,
							schnorr_sig) &&
						    out.data && out.len > 0) {
							free(fi->dist_signed_tx);
							fi->dist_signed_tx =
								malloc(out.len);
							if (fi->dist_signed_tx) {
								memcpy(fi->dist_signed_tx,
								       out.data, out.len);
								fi->dist_signed_tx_len =
									out.len;
								ss_compute_dist_signed_txid(fi);
								plugin_log(plugin_handle,
									LOG_INFORM,
									"LSP: dist TX aggregated "
									"+ witness applied "
									"(%zu bytes)",
									out.len);
							}
						} else {
							plugin_log(plugin_handle,
								LOG_BROKEN,
								"LSP: finalize_signed_tx "
								"failed on dist TX");
						}
						tx_buf_free(&out);
					} else {
						plugin_log(plugin_handle, LOG_BROKEN,
							"LSP: musig_aggregate_partial_sigs "
							"failed for dist TX");
					}
				} else {
					plugin_log(plugin_handle, LOG_BROKEN,
						"LSP: missing dist psigs — can't "
						"aggregate (all_parsed=%d, "
						"unsigned=%p, unsigned_len=%zu)",
						all_parsed,
						f->dist_unsigned_tx.data,
						f->dist_unsigned_tx.len);
				}
				free(sigs);

				/* Broadcast real signed dist TX to every client
				 * via DIST_READY so both sides end up with the
				 * same bitcoind-acceptable bytes. */
				if (fi->dist_signed_tx &&
				    fi->dist_signed_tx_len > 0) {
					size_t dr_len = 32 + 4 +
						fi->dist_signed_tx_len;
					uint8_t *dr = malloc(dr_len);
					if (dr) {
						memcpy(dr, fi->instance_id, 32);
						uint32_t tl =
							(uint32_t)fi->dist_signed_tx_len;
						dr[32] = (tl >> 24) & 0xFF;
						dr[33] = (tl >> 16) & 0xFF;
						dr[34] = (tl >>  8) & 0xFF;
						dr[35] = tl & 0xFF;
						memcpy(dr + 36,
						       fi->dist_signed_tx,
						       fi->dist_signed_tx_len);
						for (size_t ci = 0;
						     ci < fi->n_clients; ci++) {
							char nid[67];
							for (int j = 0; j < 33; j++)
								sprintf(nid + j*2, "%02x",
									fi->clients[ci].node_id[j]);
							nid[66] = '\0';
							send_factory_msg(cmd, nid,
								SS_SUBMSG_DIST_READY,
								dr, dr_len);
						}
						free(dr);
						plugin_log(plugin_handle, LOG_INFORM,
							"LSP: sent DIST_READY to %zu "
							"clients (%zu-byte signed dist TX)",
							fi->n_clients,
							fi->dist_signed_tx_len);
					}
				}
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "DIST complete: rotation_in_progress=%d "
				   "n_channels=%zu",
				   fi->rotation_in_progress,
				   fi->n_channels);
			if (fi->rotation_in_progress) {
				rotate_finish_and_notify(cmd, fi);
			} else {
				fi->ceremony = CEREMONY_COMPLETE;

				/* Bug C: promote all ACCEPTED join_queue entries to
				 * SIGNED so factory-list stops reporting stale
				 * "join_queue=N" on completed factories and Bug B's
				 * retry path stops re-PROPOSing them. ss_save_factory
				 * below persists the new statuses. */
				for (size_t jqi = 0; jqi < fi->n_join_queue; jqi++) {
					if (fi->join_queue[jqi].status ==
					    JOIN_STATUS_ACCEPTED) {
						fi->join_queue[jqi].status =
							JOIN_STATUS_SIGNED;
						fi->join_queue[jqi].decided_at_block =
							ss_state.current_blockheight;
					}
				}
				size_t ready_bytes = 0;
				for (size_t ci = 0; ci < fi->n_clients; ci++) {
					char nid[67];
					for (int j = 0; j < 33; j++)
						sprintf(nid + j*2, "%02x",
							fi->clients[ci].node_id[j]);
					nid[66] = '\0';
					ready_bytes = ss_send_factory_ready(
						cmd, fi, nid);
				}
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: sent FACTORY_READY to %zu "
					   "clients (%zu bytes incl signed-tree) "
					   "— call factory-open-channels",
					   fi->n_clients, ready_bytes);
				ss_save_factory(cmd, fi);
			}

			/* Clean up dist session */
			if (fi->dist_session) {
				free(fi->dist_session);
				fi->dist_session = NULL;
			}
			free(pnb);
		}
		break;

	case SS_SUBMSG_ROTATE_PROPOSE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "ROTATE_PROPOSE from %s (len=%zu)",
			   peer_id, len);
		/* Client side: LSP wants to advance DW epoch.
		 * Payload: old_epoch(4) + new_epoch(4) + nonce_bundle */
		if (len < 8) break;
		{
			uint32_t old_epoch = ((uint32_t)data[0] << 24) |
				((uint32_t)data[1] << 16) |
				((uint32_t)data[2] << 8) | data[3];
			uint32_t new_epoch = ((uint32_t)data[4] << 24) |
				((uint32_t)data[5] << 16) |
				((uint32_t)data[6] << 8) | data[7];

			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: rotation epoch %u → %u",
				   old_epoch, new_epoch);

			/* Three nonce_bundle_t — heap alloc, 79KB each (~237KB
			 * total stack avoided). */
			nonce_bundle_t *nb = calloc(1, sizeof(*nb));
			if (!nb) break;
			if (!nonce_bundle_deserialize(nb, data + 8, len - 8)) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "Bad ROTATE_PROPOSE nonce bundle");
				free(nb); break;
			}

			if (!fi) {
				fi = ss_factory_find(&ss_state, nb->instance_id);
			}
			if (!fi || !fi->lib_factory) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "No factory for rotation");
				free(nb); break;
			}

			factory_t *factory = (factory_t *)fi->lib_factory;
			secp256k1_context *ctx = global_secp_ctx;

			ss_snapshot_current_epoch_kickoff_sig(fi);

			dw_counter_advance(&factory->counter);
			fi->epoch = new_epoch;

			for (size_t ni = 0; ni < factory->n_nodes; ni++)
				factory_rebuild_node_tx(factory, ni);

			factory_sessions_init(factory);

			for (size_t e = 0; e < nb->n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				musig_pubnonce_parse(ctx, &pn,
					nb->entries[e].pubnonce);
				factory_session_set_nonce(factory,
					nb->entries[e].node_idx,
					nb->entries[e].signer_slot, &pn);
			}

			int our_idx = fi->our_participant_idx;
			unsigned char our_sec[32];
			derive_factory_seckey(our_sec, fi->instance_id, our_idx);

			size_t our_count = factory_count_nodes_for_participant(
				factory, our_idx);

			secp256k1_pubkey our_pub;
			if (!secp256k1_ec_pubkey_create(ctx, &our_pub, our_sec)) {
				free(nb); break;
			}

			if (fi->nonce_pool) {
				free(fi->nonce_pool);
				fi->nonce_pool = NULL;
			}
			musig_nonce_pool_t *pool = calloc(1,
				sizeof(musig_nonce_pool_t));
			musig_nonce_pool_generate(ctx, pool, our_count,
				our_sec, &our_pub, NULL);
			fi->nonce_pool = pool;
			memcpy(fi->our_seckey, our_sec, 32);
			fi->n_secnonces = 0;

			nonce_bundle_t *resp = calloc(1, sizeof(*resp));
			if (!resp) { free(nb); break; }
			memcpy(resp->instance_id, fi->instance_id, 32);
			resp->n_participants = nb->n_participants;
			resp->n_nodes = factory->n_nodes;
			resp->n_entries = 0;

			size_t pool_entry = 0;
			for (size_t ni = 0; ni < factory->n_nodes; ni++) {
				int slot = factory_find_signer_slot(
					factory, ni, our_idx);
				if (slot < 0) continue;

				secp256k1_musig_secnonce *sec;
				secp256k1_musig_pubnonce pub;
				if (!musig_nonce_pool_next(pool, &sec, &pub))
					break;

				fi->secnonce_pool_idx[fi->n_secnonces] = pool_entry;
				fi->secnonce_node_idx[fi->n_secnonces] = ni;
				fi->n_secnonces++;
				pool_entry++;

				factory_session_set_nonce(factory, ni,
					(size_t)slot, &pub);
				musig_pubnonce_serialize(ctx,
					resp->entries[resp->n_entries].pubnonce,
					&pub);
				resp->entries[resp->n_entries].node_idx = ni;
				resp->entries[resp->n_entries].signer_slot = slot;
				resp->n_entries++;
			}

			uint8_t rbuf[MAX_WIRE_BUF];
			size_t rlen = nonce_bundle_serialize(resp,
				rbuf, sizeof(rbuf));
			send_factory_msg(cmd, peer_id,
					 SS_SUBMSG_ROTATE_NONCE,
					 rbuf, rlen);
			free(resp);

			if (!factory_sessions_finalize(factory)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Client: rotate finalize failed");
				free(nb); break;
			}

			secp256k1_keypair kp;
			if (!secp256k1_keypair_create(ctx, &kp, our_sec)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Client: rotate keypair failed");
				free(nb); break;
			}

			nonce_bundle_t *psig_nb = calloc(1, sizeof(*psig_nb));
			if (!psig_nb) { free(nb); break; }
			memcpy(psig_nb->instance_id, fi->instance_id, 32);
			psig_nb->n_participants = nb->n_participants;
			psig_nb->n_nodes = factory->n_nodes;
			psig_nb->n_entries = 0;

			musig_nonce_pool_t *sp =
				(musig_nonce_pool_t *)fi->nonce_pool;
			for (size_t si = 0; si < fi->n_secnonces; si++) {
				uint32_t pi = fi->secnonce_pool_idx[si];
				uint32_t ni = fi->secnonce_node_idx[si];
				secp256k1_musig_secnonce *sn =
					&sp->nonces[pi].secnonce;

				int slot = factory_find_signer_slot(
					factory, ni, our_idx);
				if (slot < 0) continue;

				secp256k1_musig_partial_sig psig;
				if (!musig_create_partial_sig(
					ctx, &psig, sn, &kp,
					&factory->nodes[ni].signing_session)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "Client: rotate psig failed node %u", ni);
					continue;
				}

				musig_partial_sig_serialize(ctx,
					psig_nb->entries[psig_nb->n_entries].pubnonce,
					&psig);
				psig_nb->entries[psig_nb->n_entries].node_idx = ni;
				psig_nb->entries[psig_nb->n_entries].signer_slot = slot;
				psig_nb->n_entries++;
			}

			uint8_t pbuf[MAX_WIRE_BUF];
			size_t plen = nonce_bundle_serialize(psig_nb,
				pbuf, sizeof(pbuf));
			send_factory_msg(cmd, peer_id,
					 SS_SUBMSG_ROTATE_PSIG,
					 pbuf, plen);

			fi->ceremony = CEREMONY_ROTATING;
			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: sent ROTATE_NONCE + ROTATE_PSIG "
				   "(%zu psigs)", psig_nb->n_entries);
			free(psig_nb);
			free(nb);
		}
		break;

	case SS_SUBMSG_ROTATE_NONCE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "ROTATE_NONCE from %s (len=%zu)",
			   peer_id, len);
		/* LSP side: client sent rotation nonces */
		if (fi && fi->is_lsp) {
			nonce_bundle_t *cnb = calloc(1, sizeof(*cnb));
			if (!cnb) break;
			if (!nonce_bundle_deserialize(cnb, data, len)) {
				free(cnb); break;
			}
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) { free(cnb); break; }
			secp256k1_context *ctx = global_secp_ctx;

			size_t nonces_set = 0;
			for (size_t e = 0; e < cnb->n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				if (!musig_pubnonce_parse(ctx, &pn,
					cnb->entries[e].pubnonce))
					continue;
				if (!factory_session_set_nonce(f,
					cnb->entries[e].node_idx,
					cnb->entries[e].signer_slot, &pn))
					continue;
				nonces_set++;
			}

			/* Mark client nonce received — identify by peer_id */
			if (strlen(peer_id) == 66) {
				uint8_t pid[33];
				for (int j = 0; j < 33; j++) {
					unsigned int b;
					sscanf(peer_id + j*2, "%02x", &b);
					pid[j] = (uint8_t)b;
				}
				for (size_t xci = 0; xci < fi->n_clients; xci++) {
					if (memcmp(fi->clients[xci].node_id,
						   pid, 33) == 0) {
						fi->clients[xci].nonce_received = true;
						fi->clients[xci].propose_retry_count = 0; /* Bug B */
						break;
					}
				}
			}

			/* Cache client nonces for ALL_NONCES round */
			if (fi->cached_nonces && fi->n_cached_nonces + cnb->n_entries
			    <= fi->cached_nonces_cap) {
				nonce_entry_t *cache =
					(nonce_entry_t *)fi->cached_nonces;
				memcpy(cache + fi->n_cached_nonces,
				       cnb->entries,
				       cnb->n_entries * sizeof(nonce_entry_t));
				fi->n_cached_nonces += cnb->n_entries;
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "LSP: rotate nonces set %zu/%zu "
				   "(cached: %zu total)",
				   nonces_set, cnb->n_entries,
				   fi->n_cached_nonces);

			if (ss_factory_all_nonces_received(fi)) {
				if (!factory_sessions_finalize(f)) {
					plugin_log(plugin_handle, LOG_BROKEN,
						   "LSP: rotate finalize failed");
				} else {
					/* Mark rotation in progress BEFORE
					 * sending ALL_NONCES. The subsequent
					 * PSIG_BUNDLE (via initial ceremony
					 * path) will check this flag. */
					fi->rotation_in_progress = true;
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: rotate nonces finalized");

					/* For 3+ party: broadcast aggregated
					 * rotation nonces so clients can
					 * finalize and create partial sigs. */
					if (fi->n_clients > 1) {
						nonce_entry_t *rnc =
							(nonce_entry_t *)fi->cached_nonces;
						if (rnc && fi->n_cached_nonces > 0) {
							nonce_bundle_t *anb = calloc(1,
								sizeof(*anb));
							if (anb) {
								memcpy(anb->instance_id,
									fi->instance_id, 32);
								anb->n_participants =
									1 + fi->n_clients;
								anb->n_nodes = f->n_nodes;
								size_t n = fi->n_cached_nonces;
								if (n > MAX_NONCE_ENTRIES)
									n = MAX_NONCE_ENTRIES;
								memcpy(anb->entries, rnc,
									n * sizeof(nonce_entry_t));
								anb->n_entries = n;
								uint8_t *abuf = calloc(1,
									MAX_WIRE_BUF);
								size_t alen =
									nonce_bundle_serialize(
										anb, abuf,
										MAX_WIRE_BUF);
								free(anb);
								for (size_t ci = 0;
								     ci < fi->n_clients;
								     ci++) {
									char nid[67];
									for (int j = 0; j < 33; j++)
										sprintf(nid+j*2, "%02x",
											fi->clients[ci].node_id[j]);
									nid[66] = '\0';
									send_factory_msg(cmd, nid,
										SS_SUBMSG_ALL_NONCES,
										abuf, alen);
								}
								free(abuf);
								plugin_log(plugin_handle,
									LOG_INFORM,
									"LSP: sent rotation "
									"ALL_NONCES to %zu clients",
									fi->n_clients);
							}
						}
					}
					/* Reset nonce tracking for PSIG round.
					 * ss_factory_reset_ceremony also sets
					 * ceremony=IDLE; restore CEREMONY_ROTATING
					 * immediately so factory-list / ps-advance
					 * see the correct rotation-in-progress
					 * state during the gap before DIST psigs
					 * finish. Otherwise factory-ps-advance
					 * fails with "factory not in signed state
					 * (ceremony=0)" on PS factories whose dist
					 * TX re-sign hasn't completed yet. */
					ss_factory_reset_ceremony(fi);
					fi->ceremony = CEREMONY_ROTATING;
				}
			}
			free(cnb);
		}
		break;

	case SS_SUBMSG_ROTATE_PSIG:
		plugin_log(plugin_handle, LOG_INFORM,
			   "ROTATE_PSIG from %s (len=%zu)",
			   peer_id, len);
		/* LSP side: client sent rotation partial sigs */
		if (fi && fi->is_lsp) {
			nonce_bundle_t *pnb = calloc(1, sizeof(*pnb));
			if (!pnb) break;
			if (!nonce_bundle_deserialize(pnb, data, len)) {
				free(pnb); break;
			}
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) { free(pnb); break; }

			/* Set client psigs */
			size_t psigs_set = 0;
			for (size_t e = 0; e < pnb->n_entries; e++) {
				secp256k1_musig_partial_sig ps;
				if (!musig_partial_sig_parse(global_secp_ctx,
					&ps, pnb->entries[e].pubnonce))
					continue;
				if (!factory_session_set_partial_sig(f,
					pnb->entries[e].node_idx,
					pnb->entries[e].signer_slot, &ps))
					continue;
				psigs_set++;
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "LSP: rotate client psigs set %zu/%zu",
				   psigs_set, pnb->n_entries);

			/* Create LSP's own psigs */
			secp256k1_keypair lsp_kp;
			if (!secp256k1_keypair_create(global_secp_ctx,
				&lsp_kp, fi->our_seckey)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "LSP: rotate keypair failed");
				free(pnb); break;
			}

			musig_nonce_pool_t *lsp_pool =
				(musig_nonce_pool_t *)fi->nonce_pool;
			size_t lsp_psigs = 0;
			for (size_t si = 0; si < fi->n_secnonces; si++) {
				uint32_t pi = fi->secnonce_pool_idx[si];
				uint32_t ni = fi->secnonce_node_idx[si];
				secp256k1_musig_secnonce *sn =
					&lsp_pool->nonces[pi].secnonce;

				secp256k1_musig_partial_sig psig;
				if (!musig_create_partial_sig(
					global_secp_ctx, &psig, sn, &lsp_kp,
					&f->nodes[ni].signing_session))
					continue;

				int slot = factory_find_signer_slot(
					f, ni, fi->our_participant_idx);
				if (slot < 0) continue;

				factory_session_set_partial_sig(
					f, ni, (size_t)slot, &psig);
				lsp_psigs++;
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "LSP: created %zu own rotate psigs",
				   lsp_psigs);

			/* Try to complete */
			if (!factory_sessions_complete(f)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "LSP: rotate sessions_complete failed");
			} else {
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: ROTATION TREE SIGNED! epoch=%u",
					   fi->epoch);

				/* Tier 2.6: rotation rebuilds the tree, so PS
				 * leaves' chain state resets.  Capture the new
				 * chain[0] for each PS leaf. */
				ss_save_all_ps_chain0(cmd, fi);

				/* Build new distribution TX for rotated tree */
				fi->rotation_in_progress = true;
				tx_output_t rot_dist_out[MAX_DIST_OUTPUTS];
				size_t n_rdist = factory_compute_distribution_outputs(
					f, rot_dist_out, MAX_DIST_OUTPUTS, 500);

				if (n_rdist > 0 && factory_build_distribution_tx_unsigned(
					f, rot_dist_out, n_rdist,
					ss_state.current_blockheight + DW_STEP_BLOCKS * DIST_TX_LOCKTIME_DAYS)) {
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: rotate dist TX built "
						   "(%zu outputs)", n_rdist);

					/* Generate nonce for dist TX */
					secp256k1_context *rdctx = global_secp_ctx;
					unsigned char rlsp_sk[32];
					derive_factory_seckey(rlsp_sk, fi->instance_id, 0);
					secp256k1_pubkey rlsp_pk;
					if (!secp256k1_ec_pubkey_create(rdctx,
						&rlsp_pk, rlsp_sk)) {
						free(pnb); break;
					}

					musig_nonce_pool_t *rdpool = calloc(1,
						sizeof(musig_nonce_pool_t));
					musig_nonce_pool_generate(rdctx, rdpool, 1,
						rlsp_sk, &rlsp_pk, NULL);

					secp256k1_musig_secnonce *rdsec;
					secp256k1_musig_pubnonce rdpub;
					musig_nonce_pool_next(rdpool, &rdsec, &rdpub);

					/* Init standalone session for rotation dist TX */
					musig_signing_session_t *rdsess = calloc(1,
						sizeof(musig_signing_session_t));
					musig_session_init(rdsess,
						&f->nodes[0].keyagg,
						f->n_participants);
					int rlsp_slot = factory_find_signer_slot(
						f, 0, 0);
					if (rlsp_slot >= 0)
						musig_session_set_pubnonce(rdsess,
							(size_t)rlsp_slot, &rdpub);
					if (fi->dist_session) free(fi->dist_session);
					fi->dist_session = rdsess;

					/* Build DIST_PROPOSE payload */
					uint8_t rdpayload[MAX_WIRE_BUF];
					uint8_t *rdp = rdpayload;
					memcpy(rdp, fi->instance_id, 32); rdp += 32;
					uint32_t rtxlen = f->dist_unsigned_tx.len;
					rdp[0] = (rtxlen >> 24) & 0xFF;
					rdp[1] = (rtxlen >> 16) & 0xFF;
					rdp[2] = (rtxlen >> 8) & 0xFF;
					rdp[3] = rtxlen & 0xFF;
					rdp += 4;
					memcpy(rdp, f->dist_unsigned_tx.data, rtxlen);
					rdp += rtxlen;
					musig_pubnonce_serialize(rdctx,
						rdp, &rdpub);
					rdp += 66;
					size_t rdplen = (size_t)(rdp - rdpayload);

					/* Store nonce pool for dist signing */
					if (fi->nonce_pool) free(fi->nonce_pool);
					fi->nonce_pool = rdpool;
					fi->n_secnonces = 1;
					fi->secnonce_pool_idx[0] = 0;
					fi->secnonce_node_idx[0] = f->n_nodes;

					/* Send DIST_PROPOSE to clients */
					for (size_t ci = 0; ci < fi->n_clients; ci++) {
						char nid[67];
						for (int j = 0; j < 33; j++)
							sprintf(nid + j*2, "%02x",
								fi->clients[ci].node_id[j]);
						nid[66] = '\0';
						send_factory_msg(cmd, nid,
							SS_SUBMSG_DIST_PROPOSE,
							rdpayload, rdplen);
					}

					ss_factory_reset_ceremony(fi);
					fi->ceremony = CEREMONY_PSIGS_COLLECTED;
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: sent rotate DIST_PROPOSE "
						   "to %zu clients (%zu bytes)",
						   fi->n_clients, rdplen);
				} else {
					/* Dist TX failed — proceed without */
					plugin_log(plugin_handle, LOG_UNUSUAL,
						   "LSP: rotate dist TX failed, "
						   "completing without");
					rotate_finish_and_notify(cmd, fi);
				}
			}
			free(pnb);
		}
		break;

	case SS_SUBMSG_ROTATE_COMPLETE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "ROTATE_COMPLETE from %s (len=%zu)",
			   peer_id, len);
		if (fi) {
			/* Follow-up #1 sub-PR 3C: if the LSP sent a signed-tree
			 * trailer past the 32-byte instance_id, apply it so the
			 * client has the rotated epoch's signed TXs for
			 * trustless force-close. Mirrors FACTORY_READY's 3A
			 * behavior for the rotation ceremony. */
			if (len > 32 && fi->lib_factory) {
				if (ss_persist_deserialize_signed_txs(
					fi->lib_factory, data + 32, len - 32)) {
					plugin_log(plugin_handle, LOG_INFORM,
						"Client: applied %zu bytes of "
						"signed tree TXs from "
						"ROTATE_COMPLETE trailer",
						len - 32);
				} else {
					plugin_log(plugin_handle, LOG_UNUSUAL,
						"Client: failed to parse "
						"ROTATE_COMPLETE signed-tree "
						"trailer (%zu bytes)",
						len - 32);
				}
			} else if (len == 32) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					"Client: ROTATE_COMPLETE has no "
					"signed-tree trailer — legacy LSP, "
					"no trustless client-side exit for "
					"rotated epoch");
			}

			fi->ceremony = CEREMONY_ROTATE_COMPLETE;

			/* Rotation rebuilt the tree, so PS leaves' chain state
			 * was reset. Capture the new chain[0] for each PS leaf
			 * now that they're signed client-side. */
			ss_save_all_ps_chain0(cmd, fi);

			ss_save_factory(cmd, fi);

			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: rotation complete, epoch=%u",
				   fi->epoch);
		}
		break;

	case SS_SUBMSG_REVOKE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "REVOKE from %s (len=%zu)", peer_id, len);
		/* Client: store revocation secret for breach detection.
		 * fi is NULL here (payload starts with epoch, not instance_id).
		 * Find factory by scanning for one with this peer as LSP. */
		if (!fi) {
			for (size_t i = 0; i < ss_state.n_factories; i++) {
				if (!ss_state.factories[i]->is_lsp) {
					fi = ss_state.factories[i];
					break;
				}
			}
		}
		if (fi && len >= 36) {
			uint32_t rev_epoch = ((uint32_t)data[0] << 24) |
				((uint32_t)data[1] << 16) |
				((uint32_t)data[2] << 8) | data[3];
			const uint8_t *rev_secret = data + 4;

			ss_factory_add_breach_data(fi, rev_epoch,
						   rev_secret, NULL, 0);

			fi->ceremony = CEREMONY_REVOKED;
			ss_save_factory(cmd, fi);
			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: stored revocation for epoch %u, "
				   "n_breach=%zu",
				   rev_epoch, fi->n_breach_epochs);

			/* Ack only AFTER ss_save_factory returns — if the
			 * datastore write fails, we don't want to mislead
			 * the LSP into advancing. The payload is just the
			 * epoch we're acking; the LSP matches it against
			 * its pending_revoke_epoch for this client. */
			uint8_t ack_payload[4];
			ack_payload[0] = (rev_epoch >> 24) & 0xFF;
			ack_payload[1] = (rev_epoch >> 16) & 0xFF;
			ack_payload[2] = (rev_epoch >> 8) & 0xFF;
			ack_payload[3] = rev_epoch & 0xFF;
			send_factory_msg(cmd, peer_id,
				SS_SUBMSG_REVOKE_ACK, ack_payload, 4);
			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: sent REVOKE_ACK for epoch %u",
				   rev_epoch);
		}
		break;

	case SS_SUBMSG_REVOKE_ACK:
		plugin_log(plugin_handle, LOG_INFORM,
			   "REVOKE_ACK from %s (len=%zu)", peer_id, len);
		/* LSP-side: find the factory where this peer is a client
		 * and clear the pending_revoke_epoch marker. Ignores acks
		 * for factories we're not the LSP of, or for epochs that
		 * don't match the currently-pending value (stale retry). */
		if (len >= 4) {
			uint32_t ack_epoch = ((uint32_t)data[0] << 24) |
				((uint32_t)data[1] << 16) |
				((uint32_t)data[2] << 8) | data[3];
			/* Parse peer_id back to bytes for comparison */
			uint8_t peer_bytes[33];
			bool parsed = false;
			if (strlen(peer_id) == 66) {
				parsed = true;
				for (int j = 0; j < 33; j++) {
					unsigned int b;
					if (sscanf(peer_id + j*2, "%02x",
						   &b) != 1) {
						parsed = false; break;
					}
					peer_bytes[j] = (uint8_t)b;
				}
			}
			if (parsed) {
				bool any = false;
				for (size_t i = 0;
				     i < ss_state.n_factories; i++) {
					factory_instance_t *lsp_fi =
						ss_state.factories[i];
					if (!lsp_fi->is_lsp) continue;
					for (size_t ci = 0;
					     ci < lsp_fi->n_clients; ci++) {
						if (memcmp(lsp_fi->clients[ci]
							   .node_id,
							   peer_bytes, 33) != 0)
							continue;
						if (lsp_fi->clients[ci]
							.pending_revoke_epoch
						    != ack_epoch)
							continue;
						lsp_fi->clients[ci]
							.pending_revoke_epoch =
							UINT32_MAX;
						if (lsp_fi->clients[ci]
							.last_acked_epoch
						    == UINT32_MAX ||
						    lsp_fi->clients[ci]
							.last_acked_epoch
						    < ack_epoch) {
							lsp_fi->clients[ci]
							  .last_acked_epoch =
							  ack_epoch;
						}
						ss_save_factory(cmd, lsp_fi);
						any = true;
						plugin_log(plugin_handle,
							LOG_INFORM,
							"LSP: cleared pending "
							"REVOKE for client %zu "
							"epoch %u",
							ci, ack_epoch);
					}
				}
				if (!any) {
					plugin_log(plugin_handle, LOG_DBG,
						"REVOKE_ACK: no matching "
						"pending entry (epoch %u)",
						ack_epoch);
				}
			}
		}
		break;

	case SS_SUBMSG_CLOSE_PROPOSE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "CLOSE_PROPOSE from %s (len=%zu)",
			   peer_id, len);
		if (len >= 4) {
			secp256k1_context *ctx = global_secp_ctx;

			/* Parse output distribution */
			const uint8_t *p = data;
			uint32_t n_outputs = ((uint32_t)p[0] << 24) |
				((uint32_t)p[1] << 16) |
				((uint32_t)p[2] << 8) | p[3];
			p += 4;

			if (n_outputs > 8) break;
			tx_output_t outputs[8];
			for (uint32_t oi = 0; oi < n_outputs; oi++) {
				if (p + 10 > data + len) break;
				outputs[oi].amount_sats =
					((uint64_t)p[0] << 56) |
					((uint64_t)p[1] << 48) |
					((uint64_t)p[2] << 40) |
					((uint64_t)p[3] << 32) |
					((uint64_t)p[4] << 24) |
					((uint64_t)p[5] << 16) |
					((uint64_t)p[6] << 8) | p[7];
				p += 8;
				uint16_t spk_len = ((uint16_t)p[0] << 8) | p[1];
				p += 2;
				if (spk_len > 34 || p + spk_len > data + len) break;
				memcpy(outputs[oi].script_pubkey, p, spk_len);
				outputs[oi].script_pubkey_len = spk_len;
				p += spk_len;
			}

			/* Lookup factory by instance_id from nonce_bundle.
			 * The bundle starts at p; its first 32 bytes are the
			 * instance_id. Old logic picked the first non-LSP
			 * factory which fails when the client knows more than
			 * one factory. */
			if (p + 32 > data + len) break;
			fi = ss_factory_find(&ss_state, p);
			if (!fi || fi->is_lsp) {
				plugin_log(plugin_handle, LOG_BROKEN,
					"Client: CLOSE_PROPOSE for unknown factory (fi=%p is_lsp=%d)",
					(void *)fi, fi ? fi->is_lsp : -1);
				break;
			}
			factory_t *factory = (factory_t *)fi->lib_factory;
			if (!factory) break;

			/* Build unsigned close tx to get sighash */
			tx_buf_t close_tx;
			unsigned char sighash[32];
			tx_buf_init(&close_tx, 512);

			if (!factory_build_cooperative_close_unsigned(
				factory, &close_tx, sighash,
				outputs, n_outputs,
				ss_state.current_blockheight)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Client: close tx build failed");
				tx_buf_free(&close_tx);
				break;
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: close tx built (%zu bytes)",
				   close_tx.len);

			/* Parse LSP nonces from remainder (heap alloc: 79KB struct) */
			size_t hdr_consumed = (size_t)(p - data);
			if (hdr_consumed < len) {
				nonce_bundle_t *cnb = calloc(1, sizeof(*cnb));
				if (!cnb) break;
				if (nonce_bundle_deserialize(cnb,
					p, len - hdr_consumed)) {
					factory_session_init_node(factory, 0);

					for (size_t e = 0; e < cnb->n_entries; e++) {
						secp256k1_musig_pubnonce pn;
						musig_pubnonce_parse(ctx, &pn,
							cnb->entries[e].pubnonce);
						factory_session_set_nonce(factory,
							cnb->entries[e].node_idx,
							cnb->entries[e].signer_slot,
							&pn);
					}
				}
				free(cnb);
			}

			/* Generate our nonces */
			int our_idx = fi->our_participant_idx;
			unsigned char our_sec[32];
			derive_factory_seckey(our_sec, fi->instance_id, our_idx);

			secp256k1_pubkey our_pub;
			if (!secp256k1_ec_pubkey_create(ctx, &our_pub, our_sec))
				break;

			if (fi->nonce_pool) free(fi->nonce_pool);
			musig_nonce_pool_t *pool = calloc(1,
				sizeof(musig_nonce_pool_t));
			/* Close uses 1 signing session (kickoff root) */
			musig_nonce_pool_generate(ctx, pool, 1,
				our_sec, &our_pub, NULL);
			fi->nonce_pool = pool;
			fi->n_secnonces = 0;

			secp256k1_musig_secnonce *sec;
			secp256k1_musig_pubnonce pub;
			musig_nonce_pool_next(pool, &sec, &pub);
			fi->secnonce_pool_idx[0] = 0;
			fi->secnonce_node_idx[0] = 0;
			fi->n_secnonces = 1;
			factory_session_set_nonce(factory, 0, our_idx, &pub);

			/* Send CLOSE_NONCE (heap alloc: 79KB struct) */
			{
				nonce_bundle_t *nresp = calloc(1, sizeof(*nresp));
				if (!nresp) break;
				memcpy(nresp->instance_id, fi->instance_id, 32);
				nresp->n_participants = 2;
				nresp->n_nodes = 1;
				nresp->n_entries = 1;
				nresp->entries[0].node_idx = 0;
				nresp->entries[0].signer_slot = our_idx;
				musig_pubnonce_serialize(ctx,
					nresp->entries[0].pubnonce, &pub);

				uint8_t nbuf[MAX_WIRE_BUF];
				size_t nlen = nonce_bundle_serialize(nresp,
					nbuf, sizeof(nbuf));
				send_factory_msg(cmd, peer_id,
						 SS_SUBMSG_CLOSE_NONCE,
						 nbuf, nlen);
				free(nresp);
			}

			/* Finalize node 0 and create partial sig */
			factory_session_finalize_node(factory, 0);

			secp256k1_keypair kp;
			if (!secp256k1_keypair_create(ctx, &kp, our_sec))
				break;

			musig_nonce_pool_t *sp =
				(musig_nonce_pool_t *)fi->nonce_pool;
			secp256k1_musig_secnonce *sn =
				&sp->nonces[0].secnonce;

			secp256k1_musig_partial_sig psig;
			if (musig_create_partial_sig(ctx, &psig, sn, &kp,
				&factory->nodes[0].signing_session)) {

				nonce_bundle_t *presp = calloc(1, sizeof(*presp));
				if (presp) {
					memcpy(presp->instance_id, fi->instance_id, 32);
					presp->n_participants = 2;
					presp->n_nodes = 1;
					presp->n_entries = 1;
					presp->entries[0].node_idx = 0;
					presp->entries[0].signer_slot = our_idx;
					musig_partial_sig_serialize(ctx,
						presp->entries[0].pubnonce, &psig);

					uint8_t pbuf[MAX_WIRE_BUF];
					size_t plen = nonce_bundle_serialize(presp,
						pbuf, sizeof(pbuf));
					send_factory_msg(cmd, peer_id,
						SS_SUBMSG_CLOSE_PSIG,
						pbuf, plen);
					free(presp);

					plugin_log(plugin_handle, LOG_INFORM,
						   "Client: sent CLOSE_NONCE + CLOSE_PSIG");
				}
			}

			tx_buf_free(&close_tx);
			fi->lifecycle = FACTORY_LIFECYCLE_DYING;
		}
		break;

	case SS_SUBMSG_CLOSE_NONCE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "CLOSE_NONCE from %s (len=%zu)",
			   peer_id, len);
		if (fi && fi->is_lsp) {
			nonce_bundle_t *cnb = calloc(1, sizeof(*cnb));
			if (!cnb) break;
			if (!nonce_bundle_deserialize(cnb, data, len)) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "CLOSE_NONCE: deserialize failed");
				free(cnb);
				break;
			}
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) {
				free(cnb);
				break;
			}

			for (size_t e = 0; e < cnb->n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				if (!musig_pubnonce_parse(global_secp_ctx, &pn,
					cnb->entries[e].pubnonce))
					continue;
				factory_session_set_nonce(f,
					cnb->entries[e].node_idx,
					cnb->entries[e].signer_slot, &pn);
			}
			free(cnb);

			if (!factory_session_finalize_node(f, 0))
				plugin_log(plugin_handle, LOG_BROKEN,
					   "LSP: close finalize failed");
			else
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: close nonces finalized");
		}
		break;

	case SS_SUBMSG_CLOSE_ALL_NONCES:
		plugin_log(plugin_handle, LOG_INFORM,
			   "CLOSE_ALL_NONCES from %s", peer_id);
		break;

	case SS_SUBMSG_CLOSE_PSIG:
		plugin_log(plugin_handle, LOG_INFORM,
			   "CLOSE_PSIG from %s (len=%zu)",
			   peer_id, len);
		/* LSP side: client sent close partial sig.
		 * Task #95: same heap-vs-stack fix as CLOSE_NONCE — the
		 * 79KB nonce_bundle_t blows libplugin's stack. */
		if (fi && fi->is_lsp) {
			nonce_bundle_t *pnb = calloc(1, sizeof(*pnb));
			if (!pnb) break;
			if (!nonce_bundle_deserialize(pnb, data, len)) {
				free(pnb);
				break;
			}
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) { free(pnb); break; }

			for (size_t e = 0; e < pnb->n_entries; e++) {
				secp256k1_musig_partial_sig ps;
				if (!musig_partial_sig_parse(global_secp_ctx,
					&ps, pnb->entries[e].pubnonce))
					continue;
				factory_session_set_partial_sig(f,
					pnb->entries[e].node_idx,
					pnb->entries[e].signer_slot, &ps);
			}
			free(pnb);

			/* Create LSP's own partial sig */
			secp256k1_keypair lsp_kp;
			if (!secp256k1_keypair_create(global_secp_ctx,
				&lsp_kp, fi->our_seckey))
				break;

			musig_nonce_pool_t *lsp_pool =
				(musig_nonce_pool_t *)fi->nonce_pool;
			/* Guard: secp256k1_musig_partial_sign aborts the
			 * process if secnonce was wiped (single-use safety)
			 * or session was never properly finalized. Refuse
			 * partial_sign unless finalize ran cleanly — the
			 * indicator is nonces_collected == n_signers AND
			 * the session reached agg state (msg32 non-zero). */
			int finalize_ran = 0;
			for (int z = 0; z < 32; z++) {
				if (f->nodes[0].signing_session.msg32[z]) {
					finalize_ran = 1;
					break;
				}
			}
			if (lsp_pool && fi->n_secnonces > 0
			    && finalize_ran
			    && (size_t)f->nodes[0].signing_session.nonces_collected
				   == f->nodes[0].n_signers) {
				uint32_t pi = fi->secnonce_pool_idx[0];
				secp256k1_musig_secnonce *sn =
					&lsp_pool->nonces[pi].secnonce;

				secp256k1_musig_partial_sig psig;
				if (musig_create_partial_sig(
					global_secp_ctx, &psig, sn, &lsp_kp,
					&f->nodes[0].signing_session)) {
					factory_session_set_partial_sig(
						f, 0, fi->our_participant_idx,
						&psig);
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: created own close psig");
				}
			} else {
				plugin_log(plugin_handle, LOG_BROKEN,
					"LSP: skipping partial_sign — session not finalized "
					"(finalize_ran=%d collected=%d n_signers=%zu pool=%p n_sec=%u)",
					finalize_ran,
					f->nodes[0].signing_session.nonces_collected,
					f->nodes[0].n_signers,
					(void *)lsp_pool, fi->n_secnonces);
			}

			/* Try to complete just node 0 (close tx) */
			if (factory_session_complete_node(f, 0)) {
				fi->lifecycle = FACTORY_LIFECYCLE_EXPIRED;
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: COOPERATIVE CLOSE SIGNED!");

				/* Broadcast the close TX (node 0) */
				if (f->n_nodes > 0
				    && f->nodes[0].signed_tx.data
				    && f->nodes[0].signed_tx.len > 0) {
					tx_buf_t *ctx_buf = &f->nodes[0].signed_tx;
					char *ctx_hex = tal_arr(cmd, char,
						ctx_buf->len * 2 + 1);
					for (size_t h = 0; h < ctx_buf->len; h++)
						sprintf(ctx_hex + h*2, "%02x",
							ctx_buf->data[h]);
					ss_broadcast_factory_tx(cmd, fi, ctx_hex,
								FACTORY_TX_DIST);
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: broadcast cooperative close TX");
				}

				/* Send CLOSE_DONE */
				for (size_t ci = 0; ci < fi->n_clients; ci++) {
					char nid[67];
					for (int j = 0; j < 33; j++)
						sprintf(nid + j*2, "%02x",
							fi->clients[ci].node_id[j]);
					nid[66] = '\0';
					send_factory_msg(cmd, nid,
						SS_SUBMSG_CLOSE_DONE,
						fi->instance_id, 32);
				}

				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: sent CLOSE_DONE to %zu clients",
					   fi->n_clients);
				ss_save_factory(cmd, fi);

				/* Forget factory channels (no commitment broadcast —
				 * factory protocol resolved the funds) */
				for (size_t ch = 0; ch < fi->n_channels; ch++) {
					char cid_hex[65];
					for (int j = 0; j < 32; j++)
						sprintf(cid_hex + j*2, "%02x",
							fi->channels[ch].channel_id[j]);
					size_t ci = 0;
					for (; ci < fi->n_clients; ci++)
						if (fi->channels[ch].leaf_index >= 0)
							break;
					char peer_nid[67];
					for (int j = 0; j < 33; j++)
						sprintf(peer_nid + j*2, "%02x",
							fi->clients[ci < fi->n_clients ? ci : 0].node_id[j]);
					peer_nid[66] = '\0';
					struct out_req *creq = jsonrpc_request_start(
						cmd, "dev-forget-channel",
						rpc_done, rpc_err, fi);
					json_add_string(creq->js, "id", peer_nid);
					json_add_string(creq->js, "channel_id", cid_hex);
					send_outreq(creq);
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: forgetting factory channel %zu", ch);
				}
			} else {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "LSP: close sessions_complete failed");
			}
		}
		break;

	case SS_SUBMSG_CLOSE_DONE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "CLOSE_DONE from %s (len=%zu)",
			   peer_id, len);
		if (fi) {
			fi->lifecycle = FACTORY_LIFECYCLE_EXPIRED;
			ss_save_factory(cmd, fi);
			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: factory closed cooperatively");

			/* Forget factory channels (no commitment broadcast —
			 * factory protocol resolved the funds) */
			for (size_t ch = 0; ch < fi->n_channels; ch++) {
				char cid_hex[65];
				for (int j = 0; j < 32; j++)
					sprintf(cid_hex + j*2, "%02x",
						fi->channels[ch].channel_id[j]);
				char lsp_hex[67];
				for (int j = 0; j < 33; j++)
					sprintf(lsp_hex + j*2, "%02x",
						fi->lsp_node_id[j]);
				lsp_hex[66] = '\0';
				struct out_req *creq = jsonrpc_request_start(
					cmd, "dev-forget-channel",
					rpc_done, rpc_err, fi);
				json_add_string(creq->js, "id", lsp_hex);
				json_add_string(creq->js, "channel_id", cid_hex);
				send_outreq(creq);
				plugin_log(plugin_handle, LOG_INFORM,
					   "Client: forgetting factory channel %zu", ch);
			}
		}
		break;

	/* Key turnover: LSP requests client to hand over factory key */
	case SS_SUBMSG_TURNOVER_REQUEST:
		plugin_log(plugin_handle, LOG_INFORM,
			   "TURNOVER_REQUEST from %s (len=%zu)",
			   peer_id, len);
		/* Client side: LSP is asking us to depart this factory.
		 * Send our factory secret key back. */
		if (fi && !fi->is_lsp) {
			unsigned char our_sk[32];
			derive_factory_seckey(our_sk, fi->instance_id,
					      fi->our_participant_idx);

			/* Send TURNOVER_KEY: instance_id(32) + seckey(32) */
			uint8_t tkbuf[64];
			memcpy(tkbuf, fi->instance_id, 32);
			memcpy(tkbuf + 32, our_sk, 32);
			send_factory_msg(cmd, peer_id,
					 SS_SUBMSG_TURNOVER_KEY,
					 tkbuf, 64);
			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: sent TURNOVER_KEY to LSP "
				   "(departing factory)");
			memset(our_sk, 0, 32); /* wipe */
		}
		break;

	/* Key turnover: client sends their factory secret key */
	case SS_SUBMSG_TURNOVER_KEY:
		plugin_log(plugin_handle, LOG_INFORM,
			   "TURNOVER_KEY from %s (len=%zu)",
			   peer_id, len);
		if (fi && fi->is_lsp && len >= 64) {
			const uint8_t *key_data = data + 32; /* skip instance_id */

			/* Find client index */
			uint8_t pid[33];
			if (strlen(peer_id) == 66) {
				for (int j = 0; j < 33; j++) {
					unsigned int b;
					sscanf(peer_id + j*2, "%02x", &b);
					pid[j] = (uint8_t)b;
				}
			}

			for (size_t ci = 0; ci < fi->n_clients; ci++) {
				if (memcmp(fi->clients[ci].node_id, pid, 33) != 0)
					continue;

				/* Verify the key matches the client's pubkey */
				secp256k1_pubkey verify_pub;
				if (secp256k1_ec_pubkey_create(global_secp_ctx,
							       &verify_pub,
							       key_data)) {
					uint8_t vp[33];
					size_t vplen = 33;
					secp256k1_ec_pubkey_serialize(
						global_secp_ctx, vp, &vplen,
						&verify_pub,
						SECP256K1_EC_COMPRESSED);

					bool key_ok = fi->clients[ci].has_factory_pubkey
						&& memcmp(vp, fi->clients[ci].factory_pubkey, 33) == 0;

					if (key_ok) {
						memcpy(fi->extracted_keys[ci],
						       key_data, 32);
						fi->client_departed[ci] = true;
						fi->n_departed++;

						/* Record in ladder if active */
						if (ss_ladder) {
							/* Find ladder factory by matching instance_id */
							for (size_t li = 0;
							     li < ss_ladder->n_factories;
							     li++) {
								ladder_record_key_turnover(
									ss_ladder,
									ss_ladder->factories[li].factory_id,
									(uint32_t)(ci + 1),
									key_data);
							}
						}

						/* Send ACK */
						send_factory_msg(cmd, peer_id,
							SS_SUBMSG_TURNOVER_ACK,
							fi->instance_id, 32);

						plugin_log(plugin_handle, LOG_INFORM,
							   "LSP: client %zu departed "
							   "(key verified, n_departed=%zu)",
							   ci, fi->n_departed);
						ss_save_factory(cmd, fi);
					} else {
						plugin_log(plugin_handle, LOG_UNUSUAL,
							   "LSP: TURNOVER_KEY from "
							   "client %zu: key mismatch!",
							   ci);
					}
				}
				break;
			}
		}
		break;

	/* Follow-up #1 sub-PR 3B: client-side DIST_READY — LSP shipped
	 * the aggregated signed distribution TX after the DIST_PSIG ceremony
	 * completed. Store locally so expiry auto-broadcast has valid bytes
	 * (prior to this, clients had no signed dist TX at all — same gap
	 * that FACTORY_READY's tree trailer closes for the tree). */
	case SS_SUBMSG_DIST_READY:
		plugin_log(plugin_handle, LOG_INFORM,
			   "DIST_READY from %s (len=%zu)", peer_id, len);
		if (fi && !fi->is_lsp && len >= 36) {
			uint32_t tx_len =
				((uint32_t)data[32] << 24) |
				((uint32_t)data[33] << 16) |
				((uint32_t)data[34] <<  8) |
				 (uint32_t)data[35];
			if (tx_len == 0 || 36 + tx_len > len) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					"Bad DIST_READY: tx_len=%u, payload=%zu",
					tx_len, len);
				break;
			}
			free(fi->dist_signed_tx);
			fi->dist_signed_tx = malloc(tx_len);
			if (fi->dist_signed_tx) {
				memcpy(fi->dist_signed_tx, data + 36, tx_len);
				fi->dist_signed_tx_len = tx_len;
				ss_compute_dist_signed_txid(fi);
				plugin_log(plugin_handle, LOG_INFORM,
					"Client: applied signed dist TX (%u bytes) "
					"from DIST_READY — trustless expiry "
					"auto-broadcast now works", tx_len);
				ss_save_factory(cmd, fi);
			}
		}
		break;

	/* Key turnover: LSP acknowledges departure */
	case SS_SUBMSG_TURNOVER_ACK:
		plugin_log(plugin_handle, LOG_INFORM,
			   "TURNOVER_ACK from %s — departure confirmed",
			   peer_id);
		break;

	/* --- Tier 2.6: per-leaf advance ceremony (ARITY_PS chain append) --- */

	case SS_SUBMSG_LEAF_ADVANCE_PROPOSE: {
		/* Client side: LSP asks us to advance leaf N. Parse, advance
		 * our own factory_t mirror, generate our nonce + partial sig,
		 * reply with PSIG. */
		uint8_t iid[32], lsp_pn[66];
		uint32_t leaf_side;
		if (!ss_leaf_advance_propose_parse(data, len, iid, &leaf_side,
						   lsp_pn)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"Bad LEAF_ADVANCE_PROPOSE from %s (len=%zu)",
				peer_id, len);
			break;
		}
		factory_instance_t *fp = ss_factory_find(&ss_state, iid);
		if (!fp || fp->is_lsp) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"LEAF_ADVANCE_PROPOSE for unknown/LSP factory");
			break;
		}
		if (fp->ps_pending_leaf != -1) {
			/* Duplicate PROPOSE for the same leaf is treated as
			 * an LSP-side reconnect resend: re-emit the cached
			 * PSIG instead of re-signing. BIP-327 forbids fresh-
			 * nonce re-signing the same MuSig session (it would
			 * leak our seckey).
			 *
			 * If pending is for a DIFFERENT leaf, or if we have
			 * no cached PSIG (PROPOSE was processed but PSIG
			 * couldn't be built — partial fail), drop. */
			if (fp->ps_pending_leaf == (int32_t)leaf_side &&
			    fp->cached_ps_psig_wire &&
			    fp->cached_ps_psig_len > 0) {
				send_factory_msg(cmd, peer_id,
					SS_SUBMSG_LEAF_ADVANCE_PSIG,
					fp->cached_ps_psig_wire,
					fp->cached_ps_psig_len);
				plugin_log(plugin_handle, LOG_INFORM,
					"Reconnect recovery: re-sent cached "
					"LEAF_ADVANCE_PSIG for leaf %u "
					"(LSP resent PROPOSE)",
					leaf_side);
				break;
			}
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"LEAF_ADVANCE_PROPOSE while another advance "
				"pending on leaf %d — dropping",
				fp->ps_pending_leaf);
			break;
		}
		factory_t *cf = (factory_t *)fp->lib_factory;
		if (!cf) break;
		if ((int)leaf_side < 0 || (int)leaf_side >= cf->n_leaf_nodes) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"LEAF_ADVANCE_PROPOSE: leaf_side %u out of "
				"range", leaf_side);
			break;
		}
		size_t nidx = cf->leaf_node_indices[leaf_side];
		factory_node_t *nd = &cf->nodes[nidx];
		if (!nd->is_ps_leaf) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"LEAF_ADVANCE_PROPOSE: leaf %u not PS",
				leaf_side);
			break;
		}
		int rc = factory_advance_leaf_unsigned(cf, (int)leaf_side);
		if (rc <= 0) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"Client advance_leaf_unsigned rc=%d on leaf %u",
				rc, leaf_side);
			break;
		}

		/* Tier B: PS double-spend defense (mirrors upstream
		 * client.c:2620-2638 / client_ps_signed_inputs schema v20).
		 * After advance, nd->ps_prev_txid holds the parent UTXO txid
		 * the new chain element will spend. If we've previously
		 * co-signed a TX spending that same (parent_txid, 0) — whether
		 * a network retry or a genuine double-spend attack — refuse:
		 * MuSig2 nonce reuse risk makes replay-based idempotency
		 * unsafe. DW leaves are protected by decrementing nSequence
		 * and don't need this check; we only run it for PS leaves
		 * with chain_len > 0 (chain[0] has no prior parent to defend
		 * against). */
		if (nd->is_ps_leaf && nd->ps_chain_len > 0) {
			/* Task #84: PS double-spend defense was previously
			 * gated by a datastore lookup. The key isn't migrated
			 * to wallet.db yet — disabling the check here would
			 * regress safety, so we conservatively REFUSE to
			 * co-sign any PS-chain advance after a restart until
			 * the PS-leaf state migration lands. Non-PS factories
			 * are unaffected. */
			char hex[65];
			for (int i = 0; i < 32; i++)
				sprintf(hex + 2*i, "%02x",
					nd->ps_prev_txid[i]);
			plugin_log(plugin_handle, LOG_BROKEN,
				"PS double-spend defense unavailable (Task #84 "
				"PS-leaf migration pending) — refusing leaf %u "
				"advance after (%s:0). Restart loses PS state "
				"until wallet.db schema covers PS chain entries.",
				leaf_side, hex);
			break;
		}

		if (!factory_session_init_node(cf, nidx)) break;
		int my_slot = factory_find_signer_slot(cf, nidx,
			(uint32_t)fp->our_participant_idx);
		int lsp_slot = factory_find_signer_slot(cf, nidx, 0);
		if (my_slot < 0 || lsp_slot < 0) break;

		/* Parse LSP's pubnonce and set it on the session */
		secp256k1_musig_pubnonce lsp_pubnonce_obj;
		if (!musig_pubnonce_parse(global_secp_ctx, &lsp_pubnonce_obj,
					  lsp_pn))
			break;
		if (!factory_session_set_nonce(cf, nidx, (size_t)lsp_slot,
					       &lsp_pubnonce_obj))
			break;

		/* Generate our own secnonce + pubnonce */
		secp256k1_musig_secnonce *my_sn =
			calloc(1, sizeof(secp256k1_musig_secnonce));
		if (!my_sn) break;
		secp256k1_musig_pubnonce my_pn;
		secp256k1_pubkey my_pub;
		if (!secp256k1_ec_pubkey_create(global_secp_ctx, &my_pub,
						fp->our_seckey)) {
			free(my_sn);
			break;
		}
		if (!musig_generate_nonce(global_secp_ctx, my_sn, &my_pn,
					  fp->our_seckey, &my_pub,
					  &nd->keyagg.cache)) {
			free(my_sn);
			break;
		}
		if (!factory_session_set_nonce(cf, nidx, (size_t)my_slot,
					       &my_pn)) {
			free(my_sn);
			break;
		}
		if (!factory_session_finalize_node(cf, nidx)) {
			free(my_sn);
			break;
		}

		/* Create our partial sig (consumes secnonce) */
		secp256k1_keypair my_kp;
		if (!secp256k1_keypair_create(global_secp_ctx, &my_kp,
					      fp->our_seckey)) {
			free(my_sn);
			break;
		}
		secp256k1_musig_partial_sig my_psig;
		if (!musig_create_partial_sig(global_secp_ctx, &my_psig,
					      my_sn, &my_kp,
					      &nd->signing_session)) {
			free(my_sn);
			break;
		}
		free(my_sn); /* secnonce consumed */
		if (!factory_session_set_partial_sig(cf, nidx,
						     (size_t)my_slot, &my_psig))
			break;

		/* Stash pending state — we need to remember we're awaiting
		 * DONE with LSP's psig so we can complete locally. */
		fp->ps_pending_leaf = (int32_t)leaf_side;
		fp->ps_pending_node_idx = (uint32_t)nidx;
		fp->ps_pending_secnonce = NULL; /* already consumed */
		fp->ps_pending_start_block = ss_state.current_blockheight;

		/* Serialize + send PSIG */
		uint8_t my_pn_ser[66];
		musig_pubnonce_serialize(global_secp_ctx, my_pn_ser, &my_pn);
		uint8_t my_psig_ser[32];
		musig_partial_sig_serialize(global_secp_ctx,
						      my_psig_ser, &my_psig);

		/* Tier B: persist the PS signed-input row BEFORE wire send.
		 * A crash between persist and send is safe — restart will see
		 * the row and refuse to sign anew, leaving the LSP to retry
		 * with the existing psig from a future reply. Persisting AFTER
		 * the send risks a window where we've sent a psig that no
		 * longer matches our local state machine. */
		if (nd->is_ps_leaf && nd->ps_chain_len > 0) {
			uint8_t sighash[32];
			if (compute_taproot_sighash(sighash,
					nd->unsigned_tx.data,
					nd->unsigned_tx.len,
					0,
					nd->spending_spk,
					nd->spending_spk_len,
					nd->ps_prev_chan_amount,
					nd->nsequence)) {
				char psinp_key[256];
				ss_persist_key_ps_signed_input(fp,
					nd->ps_prev_txid,
					psinp_key, sizeof(psinp_key));
				uint8_t *psinp_buf = NULL;
				size_t psinp_len =
					ss_persist_serialize_ps_signed_input(
						0, sighash, &psinp_buf);
				if (psinp_len > 0 && psinp_buf) {
					free(psinp_buf);
				}
			}
		}

		uint8_t payload[134];
		size_t plen = ss_leaf_advance_psig_build(payload,
			sizeof(payload), fp->instance_id, leaf_side,
			my_pn_ser, my_psig_ser);
		if (plen > 0) {
			/* Cache the PSIG payload before sending so a duplicate
			 * PROPOSE (from an LSP-side reconnect resend) can
			 * re-emit the SAME bytes instead of re-signing. BIP-327
			 * forbids fresh-nonce re-signing of the same message
			 * (would leak our seckey). Freed in
			 * ss_clear_ps_pending. */
			if (fp->cached_ps_psig_wire)
				free(fp->cached_ps_psig_wire);
			fp->cached_ps_psig_wire = malloc(plen);
			if (fp->cached_ps_psig_wire) {
				memcpy(fp->cached_ps_psig_wire, payload, plen);
				fp->cached_ps_psig_len = plen;
			}

			send_factory_msg(cmd, peer_id,
				SS_SUBMSG_LEAF_ADVANCE_PSIG, payload, plen);
			plugin_log(plugin_handle, LOG_INFORM,
				"SS_METRIC event=ps_advance_psig_sent "
				"leaf=%u chain_pos=%d",
				leaf_side, nd->ps_chain_len);
		}
		break;
	}

	case SS_SUBMSG_LEAF_ADVANCE_PSIG: {
		/* LSP side: client replied with their pubnonce + partial sig.
		 * Set on session, finalize, create LSP psig, complete, then
		 * send DONE carrying LSP's partial sig so client can complete
		 * locally. */
		uint8_t iid[32], cli_pn[66], cli_psig_ser[32];
		uint32_t leaf_side;
		if (!ss_leaf_advance_psig_parse(data, len, iid, &leaf_side,
						cli_pn, cli_psig_ser)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"Bad LEAF_ADVANCE_PSIG (len=%zu)", len);
			break;
		}
		factory_instance_t *fp = ss_factory_find(&ss_state, iid);
		if (!fp || !fp->is_lsp) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"LEAF_ADVANCE_PSIG for unknown/client factory");
			break;
		}
		if (fp->ps_pending_leaf != (int32_t)leaf_side) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"LEAF_ADVANCE_PSIG leaf_side mismatch "
				"(pending=%d got=%u)",
				fp->ps_pending_leaf, leaf_side);
			break;
		}
		factory_t *lf = (factory_t *)fp->lib_factory;
		if (!lf || !fp->ps_pending_secnonce) {
			ss_clear_ps_pending(fp);
			break;
		}
		size_t nidx = fp->ps_pending_node_idx;
		factory_node_t *nd = &lf->nodes[nidx];

		int my_slot = factory_find_signer_slot(lf, nidx, 0); /* LSP=0 */
		int cli_slot = factory_find_signer_slot(lf, nidx,
			(uint32_t)(leaf_side + 1));
		if (my_slot < 0 || cli_slot < 0) {
			ss_clear_ps_pending(fp);
			break;
		}

		/* Parse client inputs */
		secp256k1_musig_pubnonce cli_pn_obj;
		secp256k1_musig_partial_sig cli_psig_obj;
		if (!musig_pubnonce_parse(global_secp_ctx, &cli_pn_obj,
					  cli_pn)) {
			ss_clear_ps_pending(fp);
			break;
		}
		if (!musig_partial_sig_parse(global_secp_ctx,
			&cli_psig_obj, cli_psig_ser)) {
			ss_clear_ps_pending(fp);
			break;
		}
		if (!factory_session_set_nonce(lf, nidx, (size_t)cli_slot,
					       &cli_pn_obj)) {
			ss_clear_ps_pending(fp);
			break;
		}
		if (!factory_session_finalize_node(lf, nidx)) {
			ss_clear_ps_pending(fp);
			break;
		}

		/* Create LSP's own partial sig, consuming the stashed
		 * secnonce. */
		secp256k1_keypair lsp_kp;
		if (!secp256k1_keypair_create(global_secp_ctx, &lsp_kp,
					      fp->our_seckey)) {
			ss_clear_ps_pending(fp);
			break;
		}
		secp256k1_musig_partial_sig lsp_psig;
		if (!musig_create_partial_sig(global_secp_ctx, &lsp_psig,
			(secp256k1_musig_secnonce *)fp->ps_pending_secnonce,
			&lsp_kp, &nd->signing_session)) {
			ss_clear_ps_pending(fp);
			break;
		}
		free(fp->ps_pending_secnonce);
		fp->ps_pending_secnonce = NULL;

		if (!factory_session_set_partial_sig(lf, nidx,
			(size_t)my_slot, &lsp_psig)) {
			ss_clear_ps_pending(fp);
			break;
		}
		if (!factory_session_set_partial_sig(lf, nidx,
			(size_t)cli_slot, &cli_psig_obj)) {
			ss_clear_ps_pending(fp);
			break;
		}
		if (!factory_session_complete_node(lf, nidx)) {
			ss_clear_ps_pending(fp);
			break;
		}

		/* Chain[N] signed. Persist this chain entry before anything
		 * else — once ps_chain_len advances, this signed_tx is gone
		 * from factory_t memory. */
		ss_save_ps_chain_entry(cmd, fp, (uint32_t)nidx);

		/* Clear pending, send DONE to all clients carrying our partial
		 * sig so the involved client can finish their local copy.
		 * Others ignore the psig. */
		int32_t done_leaf = fp->ps_pending_leaf;
		ss_clear_ps_pending(fp);

		uint8_t lsp_psig_ser[32];
		musig_partial_sig_serialize(global_secp_ctx,
						      lsp_psig_ser, &lsp_psig);
		uint8_t payload[68];
		size_t plen = ss_leaf_advance_done_build(payload,
			sizeof(payload), fp->instance_id,
			(uint32_t)done_leaf, lsp_psig_ser);
		if (plen > 0) {
			for (size_t ci = 0; ci < fp->n_clients; ci++) {
				char ch[67];
				for (int j = 0; j < 33; j++)
					sprintf(ch + j*2, "%02x",
						fp->clients[ci].node_id[j]);
				ch[66] = '\0';
				send_factory_msg(cmd, ch,
					SS_SUBMSG_LEAF_ADVANCE_DONE,
					payload, plen);
			}
		}

		char iid_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(iid_hex + j*2, "%02x", fp->instance_id[j]);
		iid_hex[64] = '\0';
		plugin_log(plugin_handle, LOG_INFORM,
			"SS_METRIC event=ps_advance iid=%s leaf=%d "
			"chain_pos=%d",
			iid_hex, done_leaf, nd->ps_chain_len);
		break;
	}

	case SS_SUBMSG_LEAF_ADVANCE_DONE: {
		/* Client side: receive LSP's partial sig. If this is the leaf
		 * whose ceremony we started, apply LSP's psig, complete node,
		 * clear pending. Other clients just ignore — they don't have a
		 * signing session for this leaf. */
		uint8_t iid[32], lsp_psig_ser[32];
		uint32_t leaf_side;
		if (!ss_leaf_advance_done_parse(data, len, iid, &leaf_side,
						lsp_psig_ser)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"Bad LEAF_ADVANCE_DONE (len=%zu)", len);
			break;
		}
		factory_instance_t *fp = ss_factory_find(&ss_state, iid);
		if (!fp || fp->is_lsp) break;
		if (fp->ps_pending_leaf != (int32_t)leaf_side) {
			/* Not our involved leaf — informational only. */
			plugin_log(plugin_handle, LOG_DBG,
				"LEAF_ADVANCE_DONE leaf=%u notification "
				"(we weren't signer)", leaf_side);
			break;
		}
		factory_t *cf = (factory_t *)fp->lib_factory;
		if (!cf) { ss_clear_ps_pending(fp); break; }
		size_t nidx = fp->ps_pending_node_idx;
		int lsp_slot = factory_find_signer_slot(cf, nidx, 0);
		if (lsp_slot < 0) { ss_clear_ps_pending(fp); break; }

		secp256k1_musig_partial_sig lsp_psig_obj;
		if (!musig_partial_sig_parse(global_secp_ctx,
			&lsp_psig_obj, lsp_psig_ser)) {
			ss_clear_ps_pending(fp);
			break;
		}
		if (!factory_session_set_partial_sig(cf, nidx,
			(size_t)lsp_slot, &lsp_psig_obj)) {
			ss_clear_ps_pending(fp);
			break;
		}
		if (!factory_session_complete_node(cf, nidx)) {
			ss_clear_ps_pending(fp);
			break;
		}
		/* Client persists their copy of chain[N] for unilateral exit
		 * from cold storage without relying on the LSP's retention. */
		ss_save_ps_chain_entry(cmd, fp, (uint32_t)nidx);
		ss_clear_ps_pending(fp);
		plugin_log(plugin_handle, LOG_INFORM,
			"SS_METRIC event=ps_advance_client_done leaf=%u "
			"chain_pos=%d",
			leaf_side, cf->nodes[nidx].ps_chain_len);
		break;
	}

	/* --- Follow-up #4 impl: LEAF_REALLOC handlers (value transfer) --- */

	case SS_SUBMSG_LEAF_REALLOC_PROPOSE: {
		/* Client side: LSP proposed new output amounts on a leaf.
		 * Apply factory_set_leaf_amounts locally so our unsigned TX
		 * matches, then do the 2-of-2 signing half (no advance). */
		uint8_t iid[32], lsp_pn[66];
		uint32_t leaf_side;
		uint64_t new_amts[SS_LEAF_REALLOC_PROPOSE_MAX_OUTPUTS];
		size_t n_amts = 0;
		if (!ss_leaf_realloc_propose_parse(data, len, iid, &leaf_side,
			new_amts, &n_amts,
			SS_LEAF_REALLOC_PROPOSE_MAX_OUTPUTS, lsp_pn)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"Bad LEAF_REALLOC_PROPOSE from %s (len=%zu)",
				peer_id, len);
			break;
		}
		factory_instance_t *fp = ss_factory_find(&ss_state, iid);
		if (!fp || fp->is_lsp) break;
		if (fp->ps_pending_leaf != -1) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"LEAF_REALLOC_PROPOSE while another ceremony "
				"pending on leaf %d — dropping",
				fp->ps_pending_leaf);
			break;
		}
		factory_t *cf = (factory_t *)fp->lib_factory;
		if (!cf) break;
		if ((int)leaf_side < 0 || (int)leaf_side >= cf->n_leaf_nodes) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"LEAF_REALLOC_PROPOSE: leaf_side %u out of range",
				leaf_side);
			break;
		}

		/* Mirror the LSP's DW state advance. The LSP called
		 * factory_advance_leaf_unsigned in json_factory_buy_liquidity
		 * before set_leaf_amounts; we have to do the same so both
		 * sides' leaf nodes are at the same per-leaf DW counter and
		 * therefore produce identical unsigned TX bytes (same
		 * nSequence) — without this, the sighashes would diverge and
		 * MuSig2 finalize would reject the LSP's nonce contribution.
		 *
		 * If the advance returns -1 (root layer also advanced), the
		 * LSP's view requires a full factory re-sign — we can't
		 * piggyback that on a leaf-realloc ceremony, so abort. */
		{
			int adv_rc = factory_advance_leaf_unsigned(
				cf, (int)leaf_side);
			if (adv_rc <= 0) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					"LEAF_REALLOC_PROPOSE: client "
					"advance_leaf_unsigned rc=%d on leaf "
					"%u — aborting realloc",
					adv_rc, leaf_side);
				break;
			}
		}

		/* Mirror the LSP's amount change on our local factory_t.
		 * set_leaf_amounts enforces sum-conservation and rebuilds
		 * the unsigned TX. */
		if (!factory_set_leaf_amounts(cf, (int)leaf_side,
					      new_amts, n_amts)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"LEAF_REALLOC_PROPOSE: factory_set_leaf_amounts "
				"rejected (mismatched sum or dust?)");
			break;
		}

		size_t nidx = cf->leaf_node_indices[leaf_side];
		factory_node_t *nd = &cf->nodes[nidx];
		if (!factory_session_init_node(cf, nidx)) break;
		int my_slot = factory_find_signer_slot(cf, nidx,
			(uint32_t)fp->our_participant_idx);
		int lsp_slot = factory_find_signer_slot(cf, nidx, 0);
		if (my_slot < 0 || lsp_slot < 0) break;

		secp256k1_musig_pubnonce lsp_pn_obj;
		if (!musig_pubnonce_parse(global_secp_ctx, &lsp_pn_obj, lsp_pn))
			break;
		if (!factory_session_set_nonce(cf, nidx, (size_t)lsp_slot,
					       &lsp_pn_obj))
			break;

		/* Generate our own secnonce + pubnonce. The secnonce path
		 * differs between 2-of-2 and 3-of-3:
		 *   - 2-of-2: consume immediately (finalize+create_psig+free)
		 *   - 3-of-3: stash on fp->ps_pending_secnonce, defer until
		 *             ALL_NONCES arrives carrying the OTHER client's
		 *             nonce (MuSig2 needs all pubnonces set before
		 *             session_finalize_nonces). */
		secp256k1_musig_secnonce *my_sn =
			calloc(1, sizeof(secp256k1_musig_secnonce));
		if (!my_sn) break;
		secp256k1_musig_pubnonce my_pn;
		secp256k1_pubkey my_pub;
		if (!secp256k1_ec_pubkey_create(global_secp_ctx, &my_pub,
						fp->our_seckey)) {
			free(my_sn); break;
		}
		if (!musig_generate_nonce(global_secp_ctx, my_sn, &my_pn,
					  fp->our_seckey, &my_pub,
					  &nd->keyagg.cache)) {
			free(my_sn); break;
		}
		if (!factory_session_set_nonce(cf, nidx, (size_t)my_slot,
					       &my_pn)) {
			free(my_sn); break;
		}

		/* Task #93 fork: 2-of-2 vs 3-of-3 */
		if (nd->n_signers == 3) {
			/* 3-of-3: don't try to finalize yet — we're missing
			 * the other client's pubnonce. Stash own secnonce +
			 * pubnonce, send REALLOC_NONCE to LSP, await
			 * ALL_NONCES. */
			fp->ps_pending_leaf = (int32_t)leaf_side;
			fp->ps_pending_node_idx = (uint32_t)nidx;
			fp->ps_pending_secnonce = my_sn; /* keep alive */
			fp->ps_pending_start_block =
				ss_state.current_blockheight;
			fp->ps_pending_is_realloc = 1;
			/* Stash own pubnonce for later when the LSP's
			 * REALLOC_ALL_NONCES arrives — we'll need it to
			 * verify our own nonce wasn't garbled in transit. */
			musig_pubnonce_serialize(global_secp_ctx,
				fp->realloc_pubnonces[my_slot], &my_pn);
			fp->realloc_has_pubnonce[my_slot] = 1;
			/* lsp_pn is already serialized 66 bytes — memcpy, not
			 * musig_pubnonce_serialize (which would reinterpret
			 * the buffer as a parsed-pubnonce struct pointer and
			 * crash inside secp256k1). */
			memcpy(fp->realloc_pubnonces[lsp_slot], lsp_pn, 66);
			fp->realloc_has_pubnonce[lsp_slot] = 1;

			/* Send REALLOC_NONCE (own pubnonce) to LSP. */
			uint8_t my_pn_ser[66];
			musig_pubnonce_serialize(global_secp_ctx, my_pn_ser, &my_pn);
			uint8_t payload[102];
			size_t plen = ss_leaf_realloc_nonce_build(
				payload, sizeof(payload),
				fp->instance_id, leaf_side, my_pn_ser);
			if (plen > 0) {
				send_factory_msg(cmd, peer_id,
					SS_SUBMSG_LEAF_REALLOC_NONCE,
					payload, plen);
				plugin_log(plugin_handle, LOG_INFORM,
					"SS_METRIC event=realloc_nonce_sent leaf=%u "
					"slot=%d",
					leaf_side, my_slot);
			}
			break;
		}

		/* 2-of-2 path (ARITY_PS chain[0] / ARITY_1): finalize + create
		 * psig + send PSIG back. */
		if (!factory_session_finalize_node(cf, nidx)) {
			free(my_sn); break;
		}
		secp256k1_keypair my_kp;
		if (!secp256k1_keypair_create(global_secp_ctx, &my_kp,
					      fp->our_seckey)) {
			free(my_sn); break;
		}
		secp256k1_musig_partial_sig my_psig;
		if (!musig_create_partial_sig(global_secp_ctx, &my_psig,
					      my_sn, &my_kp,
					      &nd->signing_session)) {
			free(my_sn); break;
		}
		free(my_sn);
		if (!factory_session_set_partial_sig(cf, nidx,
						     (size_t)my_slot, &my_psig))
			break;

		/* Stash pending state — we need to remember we're awaiting
		 * DONE with LSP's psig so we can complete locally. Mark
		 * is_realloc so we know not to save as a new chain entry. */
		fp->ps_pending_leaf = (int32_t)leaf_side;
		fp->ps_pending_node_idx = (uint32_t)nidx;
		fp->ps_pending_secnonce = NULL; /* already consumed */
		fp->ps_pending_start_block = ss_state.current_blockheight;
		fp->ps_pending_is_realloc = 1;

		/* Send PSIG back (same wire shape as LEAF_ADVANCE_PSIG; the
		 * distinct submsg ID is what routes to the realloc handler). */
		uint8_t my_pn_ser[66];
		musig_pubnonce_serialize(global_secp_ctx, my_pn_ser, &my_pn);
		uint8_t my_psig_ser[32];
		musig_partial_sig_serialize(global_secp_ctx,
					    my_psig_ser, &my_psig);
		uint8_t payload[134];
		size_t plen = ss_leaf_advance_psig_build(payload, sizeof(payload),
			fp->instance_id, leaf_side, my_pn_ser, my_psig_ser);
		if (plen > 0) {
			send_factory_msg(cmd, peer_id,
				SS_SUBMSG_LEAF_REALLOC_PSIG, payload, plen);
			plugin_log(plugin_handle, LOG_INFORM,
				"SS_METRIC event=realloc_psig_sent leaf=%u",
				leaf_side);
		}
		break;
	}

	case SS_SUBMSG_LEAF_REALLOC_PSIG: {
		/* LSP side: client replied with pubnonce + psig. Complete the
		 * signing session and send REALLOC_DONE. Logic is identical
		 * to LEAF_ADVANCE_PSIG minus the chain-advance bookkeeping
		 * (no ps_prev_* updates). */
		uint8_t iid[32], cli_pn[66], cli_psig_ser[32];
		uint32_t leaf_side;
		if (!ss_leaf_advance_psig_parse(data, len, iid, &leaf_side,
						cli_pn, cli_psig_ser)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"Bad LEAF_REALLOC_PSIG (len=%zu)", len);
			break;
		}
		factory_instance_t *fp = ss_factory_find(&ss_state, iid);
		if (!fp || !fp->is_lsp) break;
		if (!fp->ps_pending_is_realloc ||
		    fp->ps_pending_leaf != (int32_t)leaf_side) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"LEAF_REALLOC_PSIG mismatch (pending leaf=%d "
				"is_realloc=%u got=%u)",
				fp->ps_pending_leaf, fp->ps_pending_is_realloc,
				leaf_side);
			break;
		}
		factory_t *lf = (factory_t *)fp->lib_factory;
		if (!lf || !fp->ps_pending_secnonce) {
			ss_clear_ps_pending(fp);
			break;
		}
		size_t nidx = fp->ps_pending_node_idx;
		factory_node_t *nd = &lf->nodes[nidx];
		int my_slot = factory_find_signer_slot(lf, nidx, 0);
		int cli_slot = factory_find_signer_slot(lf, nidx,
			(uint32_t)(leaf_side + 1));
		if (my_slot < 0 || cli_slot < 0) {
			ss_clear_ps_pending(fp); break;
		}
		secp256k1_musig_pubnonce cli_pn_obj;
		secp256k1_musig_partial_sig cli_psig_obj;
		if (!musig_pubnonce_parse(global_secp_ctx, &cli_pn_obj, cli_pn)
		    || !musig_partial_sig_parse(global_secp_ctx, &cli_psig_obj,
					        cli_psig_ser)) {
			ss_clear_ps_pending(fp); break;
		}
		if (!factory_session_set_nonce(lf, nidx, (size_t)cli_slot,
					       &cli_pn_obj)
		    || !factory_session_finalize_node(lf, nidx)) {
			ss_clear_ps_pending(fp); break;
		}
		secp256k1_keypair lsp_kp;
		if (!secp256k1_keypair_create(global_secp_ctx, &lsp_kp,
					      fp->our_seckey)) {
			ss_clear_ps_pending(fp); break;
		}
		secp256k1_musig_partial_sig lsp_psig;
		if (!musig_create_partial_sig(global_secp_ctx, &lsp_psig,
			(secp256k1_musig_secnonce *)fp->ps_pending_secnonce,
			&lsp_kp, &nd->signing_session)) {
			ss_clear_ps_pending(fp); break;
		}
		free(fp->ps_pending_secnonce);
		fp->ps_pending_secnonce = NULL;

		if (!factory_session_set_partial_sig(lf, nidx,
			(size_t)my_slot, &lsp_psig)
		    || !factory_session_set_partial_sig(lf, nidx,
			(size_t)cli_slot, &cli_psig_obj)
		    || !factory_session_complete_node(lf, nidx)) {
			ss_clear_ps_pending(fp); break;
		}

		/* For PS chain[0] reallocs, the stored chain[0] entry's
		 * signed_tx has changed; refresh the datastore entry. */
		if (nd->is_ps_leaf)
			ss_save_ps_chain_entry(cmd, fp, (uint32_t)nidx);
		/* Also refresh the full signed_txs blob so a legacy replay
		 * picks up the new amounts on this leaf. */
		ss_save_factory(cmd, fp);

		int32_t done_leaf = fp->ps_pending_leaf;
		ss_clear_ps_pending(fp);

		/* Send REALLOC_DONE to all clients (same wire shape as
		 * LEAF_ADVANCE_DONE). */
		uint8_t lsp_psig_ser[32];
		musig_partial_sig_serialize(global_secp_ctx,
					    lsp_psig_ser, &lsp_psig);
		uint8_t payload[68];
		size_t plen = ss_leaf_advance_done_build(payload,
			sizeof(payload), fp->instance_id,
			(uint32_t)done_leaf, lsp_psig_ser);
		if (plen > 0) {
			for (size_t ci = 0; ci < fp->n_clients; ci++) {
				char ch[67];
				for (int j = 0; j < 33; j++)
					sprintf(ch + j*2, "%02x",
						fp->clients[ci].node_id[j]);
				ch[66] = '\0';
				send_factory_msg(cmd, ch,
					SS_SUBMSG_LEAF_REALLOC_DONE,
					payload, plen);
			}
		}

		char iid_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(iid_hex + j*2, "%02x", fp->instance_id[j]);
		iid_hex[64] = '\0';
		plugin_log(plugin_handle, LOG_INFORM,
			"SS_METRIC event=realloc_complete iid=%s leaf=%d",
			iid_hex, done_leaf);
		break;
	}

	case SS_SUBMSG_LEAF_REALLOC_DONE: {
		/* Client side: LSP's partial sig arrived; complete our copy
		 * so we have the re-signed leaf TX locally. */
		uint8_t iid[32], lsp_psig_ser[32];
		uint32_t leaf_side;
		if (!ss_leaf_advance_done_parse(data, len, iid, &leaf_side,
						lsp_psig_ser)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"Bad LEAF_REALLOC_DONE (len=%zu)", len);
			break;
		}
		factory_instance_t *fp = ss_factory_find(&ss_state, iid);
		if (!fp || fp->is_lsp) break;
		if (!fp->ps_pending_is_realloc ||
		    fp->ps_pending_leaf != (int32_t)leaf_side) {
			plugin_log(plugin_handle, LOG_DBG,
				"LEAF_REALLOC_DONE leaf=%u notification "
				"(we weren't the signer)", leaf_side);
			break;
		}
		factory_t *cf = (factory_t *)fp->lib_factory;
		if (!cf) { ss_clear_ps_pending(fp); break; }
		size_t nidx = fp->ps_pending_node_idx;
		int lsp_slot = factory_find_signer_slot(cf, nidx, 0);
		if (lsp_slot < 0) { ss_clear_ps_pending(fp); break; }

		secp256k1_musig_partial_sig lsp_psig_obj;
		if (!musig_partial_sig_parse(global_secp_ctx, &lsp_psig_obj,
					     lsp_psig_ser)) {
			ss_clear_ps_pending(fp); break;
		}
		if (!factory_session_set_partial_sig(cf, nidx,
			(size_t)lsp_slot, &lsp_psig_obj)
		    || !factory_session_complete_node(cf, nidx)) {
			ss_clear_ps_pending(fp); break;
		}

		/* Persist the re-signed leaf on the client too. */
		if (cf->nodes[nidx].is_ps_leaf)
			ss_save_ps_chain_entry(cmd, fp, (uint32_t)nidx);
		ss_save_factory(cmd, fp);

		ss_clear_ps_pending(fp);
		plugin_log(plugin_handle, LOG_INFORM,
			"SS_METRIC event=realloc_client_done leaf=%u",
			leaf_side);
		break;
	}

	/* --- Task #93: ARITY_2 3-of-3 LEAF_REALLOC handlers --- */

	case SS_SUBMSG_LEAF_REALLOC_NONCE: {
		/* LSP side: a client replied with their pubnonce. Stash it,
		 * and once both clients have responded build REALLOC_ALL_NONCES
		 * and broadcast to both. */
		uint8_t iid[32], pn[66];
		uint32_t leaf_side;
		if (!ss_leaf_realloc_nonce_parse(data, len, iid, &leaf_side, pn)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"Bad LEAF_REALLOC_NONCE (len=%zu)", len);
			break;
		}
		factory_instance_t *fp = ss_factory_find(&ss_state, iid);
		if (!fp || !fp->is_lsp || !fp->ps_pending_is_realloc ||
		    fp->ps_pending_leaf != (int32_t)leaf_side)
			break;
		factory_t *lf = (factory_t *)fp->lib_factory;
		if (!lf) break;
		size_t nidx = fp->ps_pending_node_idx;
		factory_node_t *nd = &lf->nodes[nidx];
		if (nd->n_signers != 3) break;

		/* Identify which client replied via peer_id → participant_idx. */
		if (strlen(peer_id) != 66) break;
		uint8_t pid[33];
		for (int j = 0; j < 33; j++) {
			unsigned int b;
			sscanf(peer_id + j*2, "%02x", &b);
			pid[j] = (uint8_t)b;
		}
		client_state_t *cl = ss_factory_find_client(fp, pid);
		if (!cl) break;
		uint32_t their_pidx = (uint32_t)cl->signer_slot;
		int their_slot = factory_find_signer_slot(lf, nidx, their_pidx);
		if (their_slot < 0) break;

		secp256k1_musig_pubnonce pn_obj;
		if (!musig_pubnonce_parse(global_secp_ctx, &pn_obj, pn))
			break;
		if (!factory_session_set_nonce(lf, nidx, (size_t)their_slot,
					       &pn_obj))
			break;

		/* Stash for ALL_NONCES rebroadcast. */
		memcpy(fp->realloc_pubnonces[their_slot], pn, 66);
		fp->realloc_has_pubnonce[their_slot] = 1;

		/* Wait for both clients (slots 1 and 2; LSP is slot 0). */
		int got = (fp->realloc_has_pubnonce[1] ? 1 : 0)
			+ (fp->realloc_has_pubnonce[2] ? 1 : 0);
		plugin_log(plugin_handle, LOG_INFORM,
			"SS_METRIC event=realloc_nonce_recv leaf=%u slot=%d "
			"got=%d/2",
			leaf_side, their_slot, got);
		if (got < 2) break;

		/* All client nonces in. Build REALLOC_ALL_NONCES with the 3
		 * pubnonces in slot order and broadcast to both clients. */
		uint8_t all[3][66];
		memcpy(all[0], fp->realloc_pubnonces[0], 66);
		memcpy(all[1], fp->realloc_pubnonces[1], 66);
		memcpy(all[2], fp->realloc_pubnonces[2], 66);
		uint8_t payload[234];
		size_t plen = ss_leaf_realloc_all_nonces_build(
			payload, sizeof(payload),
			fp->instance_id, leaf_side, all);
		if (plen == 0) {
			ss_clear_ps_pending(fp); break;
		}
		for (int i = 0; i < 2; i++) {
			uint32_t pi = fp->realloc_subtree_clients[i];
			if (pi == 0 || pi - 1 >= fp->n_clients) continue;
			char ch[67];
			for (int j = 0; j < 33; j++)
				sprintf(ch + j*2, "%02x",
					fp->clients[pi - 1].node_id[j]);
			ch[66] = '\0';
			send_factory_msg(cmd, ch,
				SS_SUBMSG_LEAF_REALLOC_ALL_NONCES,
				payload, plen);
		}
		plugin_log(plugin_handle, LOG_INFORM,
			"SS_METRIC event=realloc_all_nonces_sent leaf=%u",
			leaf_side);

		/* Finalize the LSP's session now that all 3 pubnonces are
		 * pushed. factory_session_set_partial_sig (called in PSIG_3)
		 * verifies psigs against the agg-nonce computed by finalize,
		 * and musig_create_partial_sig (called when both client psigs
		 * are in) reads the same finalized state. Without this call
		 * both operations silently fail. The 2-of-2 path finalizes
		 * inline in PSIG; we have to do it earlier here because
		 * PSIG_3 is per-client and either client's psig may arrive
		 * first. */
		if (!factory_session_finalize_node(lf, nidx)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_NONCE: LSP finalize_node failed "
				"(nidx=%zu) — clearing pending",
				nidx);
			ss_clear_ps_pending(fp);
		}
		break;
	}

	case SS_SUBMSG_LEAF_REALLOC_ALL_NONCES: {
		/* Client side: LSP relayed all 3 pubnonces. Set them on the
		 * session, finalize, create our partial sig, send PSIG_3. */
		uint8_t iid[32];
		uint8_t nonces[3][66];
		uint32_t leaf_side;
		if (!ss_leaf_realloc_all_nonces_parse(data, len, iid,
						      &leaf_side, nonces)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"Bad LEAF_REALLOC_ALL_NONCES (len=%zu)", len);
			break;
		}
		factory_instance_t *fp = ss_factory_find(&ss_state, iid);
		if (!fp) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_ALL_NONCES: factory not found");
			break;
		}
		if (fp->is_lsp) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_ALL_NONCES: dropped — we're the LSP");
			break;
		}
		if (!fp->ps_pending_is_realloc) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_ALL_NONCES: ps_pending_is_realloc=0 "
				"(no PROPOSE was processed for this leaf)");
			break;
		}
		if (fp->ps_pending_leaf != (int32_t)leaf_side) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_ALL_NONCES: leaf mismatch — "
				"pending=%d incoming=%u",
				fp->ps_pending_leaf, leaf_side);
			break;
		}
		if (!fp->ps_pending_secnonce) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_ALL_NONCES: secnonce missing — "
				"PROPOSE didn't stash one");
			break;
		}
		factory_t *cf = (factory_t *)fp->lib_factory;
		if (!cf) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_ALL_NONCES: lib_factory NULL");
			break;
		}
		size_t nidx = fp->ps_pending_node_idx;
		factory_node_t *nd = &cf->nodes[nidx];
		if (nd->n_signers != 3) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_ALL_NONCES: node %zu has n_signers=%zu, "
				"expected 3",
				nidx, nd->n_signers);
			break;
		}

		int my_slot = factory_find_signer_slot(cf, nidx,
			(uint32_t)fp->our_participant_idx);
		if (my_slot < 0) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_ALL_NONCES: our pidx=%d not in node %zu's "
				"signer set",
				fp->our_participant_idx, nidx);
			break;
		}

		plugin_log(plugin_handle, LOG_INFORM,
			"SS_METRIC event=realloc_all_nonces_recv leaf=%u "
			"my_slot=%d",
			leaf_side, my_slot);

		/* PROPOSE already pushed two nonces (LSP's + ours), so the
		 * session's nonces_collected counter is at 2. set_pubnonce
		 * unconditionally increments that counter, so re-setting all
		 * 3 slots here would bring it to 5 and trip the strict
		 * equality check inside musig_session_finalize_nonces.
		 * factory_session_init_node memsets the session, restoring
		 * nonces_collected=0; we then set all 3 to reach exactly 3.
		 * Our stashed secnonce lives on fp->ps_pending_secnonce, not
		 * on the session struct, so the re-init is safe. */
		if (!factory_session_init_node(cf, nidx)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_ALL_NONCES: factory_session_init_node "
				"failed (nidx=%zu)",
				nidx);
			ss_clear_ps_pending(fp); break;
		}
		for (size_t s = 0; s < 3; s++) {
			secp256k1_musig_pubnonce pn_obj;
			if (!musig_pubnonce_parse(global_secp_ctx, &pn_obj,
						  nonces[s])) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					"REALLOC_ALL_NONCES: pubnonce[%zu] "
					"failed to parse",
					s);
				ss_clear_ps_pending(fp); goto realloc_all_nonces_done;
			}
			if (!factory_session_set_nonce(cf, nidx, s, &pn_obj)) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					"REALLOC_ALL_NONCES: set_nonce slot=%zu "
					"rejected",
					s);
				ss_clear_ps_pending(fp);
				goto realloc_all_nonces_done;
			}
		}

		if (!factory_session_finalize_node(cf, nidx)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_ALL_NONCES: factory_session_finalize_node "
				"failed (nidx=%zu)",
				nidx);
			ss_clear_ps_pending(fp); break;
		}

		/* Create our partial sig (consumes the stashed secnonce). */
		secp256k1_keypair my_kp;
		if (!secp256k1_keypair_create(global_secp_ctx, &my_kp,
					      fp->our_seckey)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_ALL_NONCES: keypair_create failed");
			ss_clear_ps_pending(fp); break;
		}
		secp256k1_musig_partial_sig my_psig;
		if (!musig_create_partial_sig(global_secp_ctx, &my_psig,
			(secp256k1_musig_secnonce *)fp->ps_pending_secnonce,
			&my_kp, &nd->signing_session)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_ALL_NONCES: musig_create_partial_sig "
				"failed");
			ss_clear_ps_pending(fp); break;
		}
		free(fp->ps_pending_secnonce);
		fp->ps_pending_secnonce = NULL;
		if (!factory_session_set_partial_sig(cf, nidx,
			(size_t)my_slot, &my_psig)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_ALL_NONCES: set_partial_sig slot=%d "
				"rejected",
				my_slot);
			ss_clear_ps_pending(fp); break;
		}

		/* Stash own psig for the DONE_3 round (we'll need to combine
		 * with peer's psig from DONE_3 to complete locally). */
		musig_partial_sig_serialize(global_secp_ctx,
			fp->realloc_psigs[my_slot], &my_psig);
		fp->realloc_has_psig[my_slot] = 1;

		/* Send PSIG_3 to LSP. fp->realloc_pubnonces[my_slot] already
		 * holds our serialized pubnonce (stashed by the PROPOSE
		 * handler), so just memcpy — calling musig_pubnonce_serialize
		 * with a zeroed compound literal would crash inside
		 * secp256k1_musig_pubnonce_load (no magic prefix). */
		uint8_t my_pn_ser[66];
		memcpy(my_pn_ser, fp->realloc_pubnonces[my_slot], 66);
		uint8_t payload[134];
		size_t plen = ss_leaf_realloc_psig3_build(
			payload, sizeof(payload),
			fp->instance_id, leaf_side, my_pn_ser,
			fp->realloc_psigs[my_slot]);
		if (plen > 0) {
			send_factory_msg(cmd, peer_id,
				SS_SUBMSG_LEAF_REALLOC_PSIG_3, payload, plen);
			plugin_log(plugin_handle, LOG_INFORM,
				"SS_METRIC event=realloc_psig3_sent leaf=%u "
				"slot=%d",
				leaf_side, my_slot);
		}
realloc_all_nonces_done:
		break;
	}

	case SS_SUBMSG_LEAF_REALLOC_PSIG_3: {
		/* LSP side: a client replied with their partial sig. Stash,
		 * and once both clients have responded create LSP psig,
		 * complete_node, broadcast REALLOC_DONE_3 with all 3 psigs. */
		uint8_t iid[32], cli_pn[66], cli_psig_ser[32];
		uint32_t leaf_side;
		if (!ss_leaf_realloc_psig3_parse(data, len, iid, &leaf_side,
						 cli_pn, cli_psig_ser)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"Bad LEAF_REALLOC_PSIG_3 (len=%zu)", len);
			break;
		}
		factory_instance_t *fp = ss_factory_find(&ss_state, iid);
		if (!fp || !fp->is_lsp || !fp->ps_pending_is_realloc ||
		    fp->ps_pending_leaf != (int32_t)leaf_side)
			break;
		factory_t *lf = (factory_t *)fp->lib_factory;
		if (!lf) break;
		size_t nidx = fp->ps_pending_node_idx;
		factory_node_t *nd = &lf->nodes[nidx];
		if (nd->n_signers != 3) break;

		if (strlen(peer_id) != 66) break;
		uint8_t pid[33];
		for (int j = 0; j < 33; j++) {
			unsigned int b;
			sscanf(peer_id + j*2, "%02x", &b);
			pid[j] = (uint8_t)b;
		}
		client_state_t *cl = ss_factory_find_client(fp, pid);
		if (!cl) break;
		int their_slot = factory_find_signer_slot(lf, nidx,
			(uint32_t)cl->signer_slot);
		if (their_slot < 0) break;

		secp256k1_musig_partial_sig their_psig_obj;
		if (!musig_partial_sig_parse(global_secp_ctx, &their_psig_obj,
					     cli_psig_ser)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_PSIG_3: psig from slot=%d failed to parse",
				their_slot);
			break;
		}
		if (!factory_session_set_partial_sig(lf, nidx,
			(size_t)their_slot, &their_psig_obj)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_PSIG_3: set_partial_sig slot=%d rejected "
				"(usually means session not finalized or psig "
				"verify failed)",
				their_slot);
			break;
		}
		memcpy(fp->realloc_psigs[their_slot], cli_psig_ser, 32);
		fp->realloc_has_psig[their_slot] = 1;

		int got = (fp->realloc_has_psig[1] ? 1 : 0)
			+ (fp->realloc_has_psig[2] ? 1 : 0);
		plugin_log(plugin_handle, LOG_INFORM,
			"SS_METRIC event=realloc_psig3_recv leaf=%u slot=%d "
			"got=%d/2",
			leaf_side, their_slot, got);
		if (got < 2) break;

		/* Both client psigs received. Create LSP own psig, set on
		 * session, complete the node. */
		if (!fp->ps_pending_secnonce) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_PSIG_3: LSP secnonce missing");
			ss_clear_ps_pending(fp); break;
		}
		secp256k1_keypair lsp_kp;
		if (!secp256k1_keypair_create(global_secp_ctx, &lsp_kp,
					      fp->our_seckey)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_PSIG_3: keypair_create failed");
			ss_clear_ps_pending(fp); break;
		}
		secp256k1_musig_partial_sig lsp_psig;
		if (!musig_create_partial_sig(global_secp_ctx, &lsp_psig,
			(secp256k1_musig_secnonce *)fp->ps_pending_secnonce,
			&lsp_kp, &nd->signing_session)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_PSIG_3: LSP create_partial_sig failed");
			ss_clear_ps_pending(fp); break;
		}
		free(fp->ps_pending_secnonce);
		fp->ps_pending_secnonce = NULL;
		musig_partial_sig_serialize(global_secp_ctx,
			fp->realloc_psigs[0], &lsp_psig);
		fp->realloc_has_psig[0] = 1;
		if (!factory_session_set_partial_sig(lf, nidx, 0, &lsp_psig)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_PSIG_3: LSP set_partial_sig slot=0 rejected");
			ss_clear_ps_pending(fp); break;
		}
		if (!factory_session_complete_node(lf, nidx)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"REALLOC_PSIG_3: complete_node failed (nidx=%zu)",
				nidx);
			ss_clear_ps_pending(fp); break;
		}

		/* Persist re-signed leaf. */
		ss_save_factory(cmd, fp);

		/* Build REALLOC_DONE_3 carrying all 3 psigs. Broadcast to
		 * both clients. */
		uint8_t payload[132];
		size_t plen = ss_leaf_realloc_done3_build(
			payload, sizeof(payload),
			fp->instance_id, leaf_side,
			fp->realloc_psigs[0],
			fp->realloc_psigs[1],
			fp->realloc_psigs[2]);
		if (plen > 0) {
			for (int i = 0; i < 2; i++) {
				uint32_t pi = fp->realloc_subtree_clients[i];
				if (pi == 0 || pi - 1 >= fp->n_clients) continue;
				char ch[67];
				for (int j = 0; j < 33; j++)
					sprintf(ch + j*2, "%02x",
						fp->clients[pi - 1].node_id[j]);
				ch[66] = '\0';
				send_factory_msg(cmd, ch,
					SS_SUBMSG_LEAF_REALLOC_DONE_3,
					payload, plen);
			}
		}

		char iid_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(iid_hex + j*2, "%02x", fp->instance_id[j]);
		iid_hex[64] = '\0';
		plugin_log(plugin_handle, LOG_INFORM,
			"SS_METRIC event=realloc_complete iid=%s leaf=%u "
			"arity=2",
			iid_hex, leaf_side);
		ss_clear_ps_pending(fp);
		break;
	}

	case SS_SUBMSG_LEAF_REALLOC_DONE_3: {
		/* Client side: LSP shipped all 3 psigs. Complete locally. */
		uint8_t iid[32], lsp_psig[32], a_psig[32], b_psig[32];
		uint32_t leaf_side;
		if (!ss_leaf_realloc_done3_parse(data, len, iid, &leaf_side,
						 lsp_psig, a_psig, b_psig)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"Bad LEAF_REALLOC_DONE_3 (len=%zu)", len);
			break;
		}
		factory_instance_t *fp = ss_factory_find(&ss_state, iid);
		if (!fp || fp->is_lsp || !fp->ps_pending_is_realloc ||
		    fp->ps_pending_leaf != (int32_t)leaf_side)
			break;
		factory_t *cf = (factory_t *)fp->lib_factory;
		if (!cf) break;
		size_t nidx = fp->ps_pending_node_idx;
		factory_node_t *nd = &cf->nodes[nidx];
		if (nd->n_signers != 3) break;

		/* Set LSP slot (always 0) + set the OTHER client's slot.
		 * Our own is already set from the ALL_NONCES handler. */
		secp256k1_musig_partial_sig lsp_psig_obj;
		if (!musig_partial_sig_parse(global_secp_ctx, &lsp_psig_obj,
					     lsp_psig)) {
			ss_clear_ps_pending(fp); break;
		}
		if (!factory_session_set_partial_sig(cf, nidx, 0,
						     &lsp_psig_obj)) {
			ss_clear_ps_pending(fp); break;
		}

		/* Determine our own slot and pick the other client psig. */
		int my_slot = factory_find_signer_slot(cf, nidx,
			(uint32_t)fp->our_participant_idx);
		if (my_slot < 0) {
			ss_clear_ps_pending(fp); break;
		}
		const uint8_t *peer_psig = (my_slot == 1) ? b_psig : a_psig;
		int peer_slot = (my_slot == 1) ? 2 : 1;
		secp256k1_musig_partial_sig peer_psig_obj;
		if (!musig_partial_sig_parse(global_secp_ctx, &peer_psig_obj,
					     peer_psig)) {
			ss_clear_ps_pending(fp); break;
		}
		if (!factory_session_set_partial_sig(cf, nidx,
			(size_t)peer_slot, &peer_psig_obj)) {
			ss_clear_ps_pending(fp); break;
		}

		if (!factory_session_complete_node(cf, nidx)) {
			ss_clear_ps_pending(fp); break;
		}

		ss_save_factory(cmd, fp);
		ss_clear_ps_pending(fp);
		plugin_log(plugin_handle, LOG_INFORM,
			"SS_METRIC event=realloc_client_done leaf=%u arity=2",
			leaf_side);
		break;
	}

	case SS_SUBMSG_FACTORY_INFO_REQUEST: {
		if (len < 12) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "FACTORY_INFO_REQUEST from %s too short (%zu bytes)",
				   peer_id, len);
			break;
		}
		uint64_t req_id = 0;
		for (int i = 0; i < 8; i++) req_id = (req_id << 8) | data[i];
		uint32_t since_block = 0;
		for (int i = 0; i < 4; i++) since_block = (since_block << 8) | data[8+i];

		plugin_log(plugin_handle, LOG_INFORM,
			   "FACTORY_INFO_REQUEST from %s (req_id=%llu since_block=%u)",
			   peer_id, (unsigned long long)req_id, since_block);

		size_t n_facts = ss_state.n_factories;
		if (n_facts > 32) n_facts = 32;
		/* B1.3: payload layout is now
		 *   [8 req_id][4 snap_block][1 n_facts][47 × n_facts]
		 *   [for each emitted factory: [2 BE policy_blob_len][blob]]
		 * The trailer is backward-compatible — older clients consume
		 * exactly 13 + n_facts*47 bytes and ignore the rest. */
		#define SS_POLICY_BLOB_MAX 256
		size_t cap = 13 + n_facts * 47 + n_facts * (2 + SS_POLICY_BLOB_MAX);
		size_t total = cap;  /* will be tightened below */
		uint8_t *resp = tal_arr(cmd, uint8_t, cap);
		uint8_t *p = resp;
		for (int i = 7; i >= 0; i--) *p++ = (uint8_t)(req_id >> (i*8));
		uint32_t snap = ss_state.current_blockheight;
		for (int i = 3; i >= 0; i--) *p++ = (uint8_t)(snap >> (i*8));
		uint8_t *n_facts_field = p;
		*p++ = (uint8_t)n_facts;
		/* Track which factories we emitted (and in what slot) so the
		 * trailer policy blobs come out in the same order. */
		factory_instance_t *emitted_facts[32] = {0};
		size_t emitted = 0;
		for (size_t fi_i = 0; fi_i < ss_state.n_factories && emitted < n_facts; fi_i++) {
			factory_instance_t *xfi = ss_state.factories[fi_i];
			if (!xfi) continue;
			if (since_block && xfi->creation_block < since_block) continue;
			memcpy(p, xfi->instance_id, 32); p += 32;
			*p++ = (uint8_t)xfi->lifecycle;
			for (int j = 3; j >= 0; j--) *p++ = (uint8_t)(xfi->creation_block >> (j*8));
			for (int j = 3; j >= 0; j--) *p++ = (uint8_t)(xfi->expiry_block >> (j*8));
			*p++ = (uint8_t)xfi->n_clients;
			*p++ = (uint8_t)xfi->n_channels;
			*p++ = xfi->is_lsp ? 1 : 0;
			bool accepting = xfi->is_lsp && xfi->lifecycle == FACTORY_LIFECYCLE_INIT;
			*p++ = accepting ? 1 : 0;
			*p++ = 0; *p++ = 0;
			emitted_facts[emitted] = xfi;
			emitted++;
		}
		if (emitted != n_facts) {
			*n_facts_field = (uint8_t)emitted;
		}

		/* B1.3: append per-factory policy blob trailer in emission
		 * order.  One [u16 BE length][length bytes] per factory.
		 * Length=0 is valid (means "all defaults"). */
		for (size_t e = 0; e < emitted; e++) {
			uint8_t pbuf[SS_POLICY_BLOB_MAX];
			size_t plen = ss_build_factory_policy_blob(
				emitted_facts[e], pbuf, sizeof(pbuf));
			if (plen > SS_POLICY_BLOB_MAX) plen = 0;  /* defensive */
			p[0] = (uint8_t)(plen >> 8);
			p[1] = (uint8_t)plen;
			p += 2;
			if (plen > 0) {
				memcpy(p, pbuf, plen);
				p += plen;
			}
		}
		total = (size_t)(p - resp);
		#undef SS_POLICY_BLOB_MAX

		send_factory_msg(cmd, peer_id, SS_SUBMSG_FACTORY_INFO_RESPONSE,
				 resp, total);
		plugin_log(plugin_handle, LOG_INFORM,
			   "Sent FACTORY_INFO_RESPONSE to %s (req_id=%llu, %zu bytes, %zu factories, +policy)",
			   peer_id, (unsigned long long)req_id, total, emitted);
		tal_free(resp);
		break;
	}

	case SS_SUBMSG_FACTORY_INFO_RESPONSE: {
		/* Bug-1 hardening: if we can read req_id (>=8 bytes), free the
		 * slot and command_fail. Otherwise we have nothing to attribute
		 * the malformed message to — just log and drop. */
		if (len < 8) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "FACTORY_INFO_RESPONSE from %s too short to "
				   "read req_id (%zu bytes) — dropped",
				   peer_id, len);
			break;
		}
		uint64_t req_id = 0;
		for (int i = 0; i < 8; i++) req_id = (req_id << 8) | data[i];

		int slot = ss_browse_find_slot(req_id);
		if (slot < 0) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "FACTORY_INFO_RESPONSE for unknown req_id=%llu from %s (already timed out?)",
				   (unsigned long long)req_id, peer_id);
			break;
		}
		struct command *orig_cmd = ss_browse_pending[slot].cmd;
		if (!orig_cmd) {
			ss_browse_pending[slot].request_id = 0;
			break;
		}

		/* Helper to free the slot + command_fail with a reason.
		 * Used for every malformed-response path so the RPC fails
		 * in <1ms instead of waiting 30s for the reaper. */
		#define BROWSE_FAIL_MALFORMED(fmt, ...) do {			\
			ss_browse_pending[slot].request_id = 0;		\
			ss_browse_pending[slot].cmd = NULL;		\
			ss_browse_pending[slot].deadline = 0;		\
			plugin_log(plugin_handle, LOG_UNUSUAL,		\
				   "browse: malformed response from %s "	\
				   "(req_id=%llu): " fmt,			\
				   peer_id,					\
				   (unsigned long long)req_id,		\
				   ##__VA_ARGS__);				\
			struct command_result *_bf = command_fail(	\
				orig_cmd, LIGHTNINGD,			\
				"factory-browse-host: malformed "	\
				"response from peer: " fmt,		\
				##__VA_ARGS__);				\
			(void)_bf;					\
		} while (0)

		if (len < 13) {
			BROWSE_FAIL_MALFORMED(
				"header truncated (%zu bytes, need 13)",
				len);
			break;
		}

		uint32_t snap = 0;
		for (int i = 0; i < 4; i++) snap = (snap << 8) | data[8+i];
		uint8_t n_factories = data[12];

		/* Bug-2 hardening: pre-validate the wire body fits. For v1 each
		 * factory entry is 47 bytes (trailing_tlv_len=0). If a peer
		 * starts sending non-zero trailing TLVs we need to honor them,
		 * but they must still fit within len. We do a strict cumulative
		 * walk below and fail if any boundary is overrun. */

		struct json_stream *js = jsonrpc_stream_success(orig_cmd);
		json_add_string(js, "host_node_id", peer_id);
		json_add_string(js, "factory_protocol_id", "SuperScalar/v1");
		json_add_u32(js, "snapshot_block", snap);
		json_array_start(js, "factories");

		size_t offset = 13;
		bool malformed = false;
		for (uint8_t i = 0; i < n_factories; i++) {
			/* Each fixed-section entry is 47 bytes. Bounds check
			 * BEFORE reading any of it. */
			if (offset + 47 > len) {
				malformed = true;
				break;
			}
			json_object_start(js, NULL);
			char iid_hex[65];
			for (int j = 0; j < 32; j++) sprintf(iid_hex + j*2, "%02x", data[offset + j]);
			iid_hex[64] = 0;
			json_add_string(js, "instance_id", iid_hex);
			offset += 32;

			uint8_t lc = data[offset++];
			const char *lc_name;
			switch (lc) {
			case FACTORY_LIFECYCLE_INIT:               lc_name = "init"; break;
			case FACTORY_LIFECYCLE_ACTIVE:             lc_name = "active"; break;
			case FACTORY_LIFECYCLE_DYING:              lc_name = "dying"; break;
			case FACTORY_LIFECYCLE_EXPIRED:            lc_name = "expired"; break;
			case FACTORY_LIFECYCLE_CLOSED_EXTERNALLY:  lc_name = "closed_externally"; break;
			case FACTORY_LIFECYCLE_CLOSED_COOPERATIVE: lc_name = "closed_cooperative"; break;
			case FACTORY_LIFECYCLE_CLOSED_UNILATERAL:  lc_name = "closed_unilateral"; break;
			case FACTORY_LIFECYCLE_CLOSED_BREACHED:    lc_name = "closed_breached"; break;
			case FACTORY_LIFECYCLE_ABORTED:            lc_name = "aborted"; break;
			case FACTORY_LIFECYCLE_FAILED:             lc_name = "failed"; break;
			case FACTORY_LIFECYCLE_AWAITING_JOINS:     lc_name = "awaiting_joins"; break;
			case FACTORY_LIFECYCLE_READY_TO_TRIGGER:   lc_name = "ready_to_trigger"; break;
			case FACTORY_LIFECYCLE_CEREMONY_RUNNING:   lc_name = "ceremony_running"; break;
			case FACTORY_LIFECYCLE_SIGNED:             lc_name = "signed"; break;
			default: lc_name = "unknown"; break;
			}
			json_add_string(js, "lifecycle", lc_name);

			uint32_t cb = 0;
			for (int j = 0; j < 4; j++) cb = (cb << 8) | data[offset + j];
			json_add_u32(js, "created_block", cb);
			offset += 4;
			uint32_t eb = 0;
			for (int j = 0; j < 4; j++) eb = (eb << 8) | data[offset + j];
			json_add_u32(js, "expiry_block", eb);
			offset += 4;
			json_add_u32(js, "n_clients", data[offset++]);
			json_add_u32(js, "n_channels", data[offset++]);
			json_add_bool(js, "is_lsp", data[offset++] != 0);
			json_add_bool(js, "accepting_joins", data[offset++] != 0);

			/* Bug-2 hardening: read trailing_tlv_len and honor it
			 * (advance past any trailing TLV bytes). v1 spec says
			 * trailing_tlv_len = 0; future versions may use it for
			 * per-entry feature TLVs. Refuse if declared length
			 * runs past the message buffer. */
			uint16_t trailing_tlv_len =
				((uint16_t)data[offset]) << 8 |
				(uint16_t)data[offset + 1];
			offset += 2;
			if (offset + trailing_tlv_len > len) {
				/* JSON object is mid-build — close it before
				 * we bail so the JSON stream stays well-formed
				 * for the BROWSE_FAIL_MALFORMED path. */
				json_object_end(js);
				malformed = true;
				break;
			}
			offset += trailing_tlv_len;
			json_object_end(js);
		}
		json_array_end(js);

		if (malformed) {
			/* Tear down the half-built JSON stream by closing it
			 * (the success-stream is owned by lightningd's RPC
			 * subsystem and gets discarded when command_fail
			 * replaces the success path). */
			BROWSE_FAIL_MALFORMED(
				"truncated body — declared %u factories but "
				"only %zu of %zu bytes consumed",
				(unsigned)n_factories, offset, len);
			break;
		}

		/* B1.4: per-factory policy trailer (one entry per factory in
		 * flat-list order):
		 *   [u16 BE policy_blob_len][policy_blob_len bytes blob]
		 * Backward-compat: if message ends at the flat list (older
		 * LSP), every factory's policy is "all defaults".  We decode
		 * the blobs and expose the joiner-relevant fields as a JSON
		 * array; the wallet UI renders them so the user sees what
		 * the LSP is advertising BEFORE deciding to join. */
		if (offset < len && n_factories > 0) {
			/* B1.5: ALSO cache each policy so the validator can
			 * look it up at FACTORY_PROPOSE time without needing
			 * the wallet to round-trip the policy back. */
			uint8_t lsp_pk[33];
			bool lsp_pk_ok = ss_peer_id_hex_to_bytes(peer_id, lsp_pk);
			json_array_start(js, "factory_policies");
			for (uint8_t i = 0; i < n_factories; i++) {
				if (offset + 2 > len) break;
				uint16_t blob_len =
					((uint16_t)data[offset] << 8)
					| (uint16_t)data[offset + 1];
				offset += 2;
				if ((size_t)offset + blob_len > len) break;
				ss_factory_policy_t pol;
				ss_factory_policy_init_defaults(&pol);
				if (blob_len > 0)
					ss_factory_policy_decode(
						data + offset, blob_len, &pol);
				offset += blob_len;

				/* Cache for validator lookup (B1.5).  Keyed by
				 * (lsp_node_id, instance_id). */
				if (lsp_pk_ok)
					ss_policy_cache_put(lsp_pk,
						data + 13 + i*47, &pol);

				/* Echo the matching instance_id so the wallet
				 * can correlate to the entry in the "factories"
				 * array above. */
				char iid_hex[65];
				for (int j = 0; j < 32; j++)
					sprintf(iid_hex + j*2, "%02x",
						data[13 + i*47 + j]);
				iid_hex[64] = 0;

				json_object_start(js, NULL);
				json_add_string(js, "instance_id", iid_hex);
				json_add_u32(js, "schema_version",
					pol.schema_version);
				/* Tree shape */
				json_add_u32(js, "arity_mode",
					(uint32_t)pol.arity_mode);
				json_add_u32(js, "leaf_arity",
					(uint32_t)pol.leaf_arity);
				/* Lifecycle */
				json_add_u32(js, "lifetime_blocks",
					pol.lifetime_blocks);
				json_add_u32(js, "dying_period_blocks",
					pol.dying_period_blocks);
				json_add_u32(js, "block_early_count",
					(uint32_t)pol.block_early_count);
				/* Economics — what the user pays */
				json_add_u64(js, "per_client_capacity_sat",
					pol.per_client_capacity_sat);
				json_add_u64(js, "lsp_fee_sat",
					pol.lsp_fee_sat);
				json_add_u32(js, "lsp_fee_ppm",
					pol.lsp_fee_ppm);
				json_add_u64(js, "join_fee_sat",
					pol.join_fee_sat);
				/* The 12 joiner_enforceable_hard fields that
				 * the B1.5 validator will check */
				json_add_u64(js, "htlc_min_sat",
					pol.htlc_min_sat);
				json_add_u64(js, "htlc_max_sat",
					pol.htlc_max_sat);
				json_add_u32(js, "max_concurrent_htlcs_per_channel",
					(uint32_t)pol.max_concurrent_htlcs_per_channel);
				json_add_u64(js, "max_in_flight_msat_per_channel",
					pol.max_in_flight_msat_per_channel);
				json_add_u32(js, "min_final_cltv_expiry_delta",
					pol.min_final_cltv_expiry_delta);
				json_add_u32(js, "cltv_expiry_delta_forward",
					pol.cltv_expiry_delta_forward);
				json_add_u64(js, "min_capacity_per_join_sat",
					pol.min_capacity_per_join_sat);
				json_add_u64(js, "max_capacity_per_join_sat",
					pol.max_capacity_per_join_sat);
				json_add_u32(js, "proof_tier_required",
					(uint32_t)pol.proof_tier_required);
				json_add_u32(js, "rotation_interval_blocks",
					pol.rotation_interval_blocks);
				json_add_bool(js, "allow_tier_b_rollover",
					pol.allow_tier_b_rollover);
				json_add_u32(js, "state_replay_defense_window_blocks",
					pol.state_replay_defense_window_blocks);
				json_object_end(js);
			}
			json_array_end(js);
		}

		plugin_log(plugin_handle, LOG_INFORM,
			   "factory-browse-host: resolved req_id=%llu with %u factories from %s",
			   (unsigned long long)req_id, (unsigned)n_factories, peer_id);

		ss_peer_usage_release_slot(ss_browse_pending[slot].peer_id);
		ss_browse_pending[slot].request_id = 0;
		ss_browse_pending[slot].cmd = NULL;
		ss_browse_pending[slot].deadline = 0;

		struct command_result *_cf_unused = command_finished(orig_cmd, js);
		(void)_cf_unused;
		#undef BROWSE_FAIL_MALFORMED
		break;
	}

	/* Phase 3: SS_SUBMSG_JOIN_REQUEST — LSP-side handler.
	 * Client is asking to join our factory. Decide accept/reject/dedup
	 * by hardcoded permissive policy (TODO: replace with real policy
	 * fields when they're added to factory_instance_t). Respond with
	 * JOIN_RESPONSE; persist updated queue.
	 *
	 * Wire format (variable, min 18 bytes):
	 *   u64    request_id
	 *   u8[32] instance_id
	 *   u64    contribution_sats
	 *   u16    trailing_tlv_len
	 * (TLV trailer bytes ignored in v1)
	 */
	case SS_SUBMSG_JOIN_REQUEST: {
		if (len < 50) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "JOIN_REQUEST from %s too short (%zu bytes, need 50)",
				   peer_id, len);
			break;
		}
		uint64_t req_id = 0;
		for (int i = 0; i < 8; i++) req_id = (req_id << 8) | data[i];
		const uint8_t *iid = data + 8;
		uint64_t contribution_sats = 0;
		for (int i = 0; i < 8; i++)
			contribution_sats = (contribution_sats << 8) | data[40 + i];
		/* trailing_tlv_len at data[48..49] — ignored for v1 */

		factory_instance_t *target_fi = ss_factory_find(&ss_state, iid);
		if (!target_fi || !target_fi->is_lsp) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "JOIN_REQUEST from %s for unknown or "
				   "non-LSP factory (req_id=%llu)",
				   peer_id, (unsigned long long)req_id);
			/* Build and send REJECTED response */
			uint8_t resp[3 + 8 + 1 + 4 + 1 + 64 + 2];
			uint8_t *rp = resp;
			for (int k = 7; k >= 0; k--) *rp++ = (req_id >> (k*8)) & 0xFF;
			*rp++ = (uint8_t)JOIN_STATUS_REJECTED;
			for (int k = 0; k < 4; k++) *rp++ = 0;
			const char *reason = "unknown factory";
			size_t rlen = strlen(reason);
			*rp++ = (uint8_t)rlen;
			memcpy(rp, reason, rlen); rp += rlen;
			*rp++ = 0; *rp++ = 0;
			size_t actual = (size_t)(rp - resp);
			send_factory_msg(cmd, peer_id,
					 SS_SUBMSG_JOIN_RESPONSE,
					 resp, actual);
			break;
		}

		/* Decode peer_id hex (66 chars) into 33-byte client pubkey */
		uint8_t client_pk[33];
		if (strlen(peer_id) != 66) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "JOIN_REQUEST peer_id has wrong length %zu",
				   strlen(peer_id));
			break;
		}
		for (int k = 0; k < 33; k++) {
			unsigned int by;
			sscanf(peer_id + k*2, "%2x", &by);
			client_pk[k] = (uint8_t)by;
		}

		/* Dedup: any existing entry for this client_node_id in this
		 * factory's queue (any status)? */
		int dup_idx = -1;
		for (size_t i = 0; i < target_fi->n_join_queue; i++) {
			if (memcmp(target_fi->join_queue[i].client_node_id,
				   client_pk, 33) == 0) {
				dup_idx = (int)i;
				break;
			}
		}

		/* Determine status to respond with */
		factory_join_status_t resp_status;
		const char *resp_reason = "";

		if (dup_idx >= 0) {
			factory_join_status_t prev =
				target_fi->join_queue[dup_idx].status;
			if (prev == JOIN_STATUS_SIGNED) {
				resp_status = JOIN_STATUS_ALREADY_MEMBER;
				resp_reason = "already a member of this factory";
			} else if (prev == JOIN_STATUS_QUEUED ||
				   prev == JOIN_STATUS_ACCEPTED) {
				resp_status = JOIN_STATUS_ALREADY_MEMBER;
				resp_reason = "duplicate join request, "
					      "cancel previous one first";
			} else {
				/* Previous was REJECTED or CANCELLED — allow
				 * re-application. Overwrite the old entry. */
				factory_join_t *j = &target_fi->join_queue[dup_idx];
				j->request_id = req_id;
				j->contribution_sats = contribution_sats;
				j->received_at_block = ss_state.current_blockheight;
				j->accepted_at_block = ss_state.current_blockheight;
				j->decided_at_block = ss_state.current_blockheight;
				j->status = JOIN_STATUS_ACCEPTED;
				memset(j->reason, 0, 64);
				resp_status = JOIN_STATUS_ACCEPTED;
				plugin_log(plugin_handle, LOG_INFORM,
					   "join: re-accepted previously-declined "
					   "client %s for factory (req_id=%llu, "
					   "contribution=%llu sats)",
					   peer_id,
					   (unsigned long long)req_id,
					   (unsigned long long)contribution_sats);
				ss_save_factory(cmd, target_fi);
			}
		} else if (target_fi->n_join_queue >= MAX_JOIN_QUEUE) {
			resp_status = JOIN_STATUS_REJECTED;
			resp_reason = "factory join queue full";
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "join: rejecting %s (req_id=%llu) — queue full",
				   peer_id, (unsigned long long)req_id);
		} else {
			/* Read LSP operator prefs (per-factory, fallback global)
			 * to decide initial status. Session-2 ships the editor;
			 * this site reads it back. Sentinel 0 means "unset" for
			 * each pref. */
			uint64_t min_contrib = ss_db_get_operator_pref_u64(
				target_fi->instance_id, "min_contribution", 0);
			uint64_t max_contrib = ss_db_get_operator_pref_u64(
				target_fi->instance_id, "max_contribution", 0);
			uint64_t auto_accept_thresh = ss_db_get_operator_pref_u64(
				target_fi->instance_id, "auto_accept_threshold", 0);

			factory_join_status_t initial_status;
			const char *initial_reason = "";
			if (min_contrib > 0 && contribution_sats < min_contrib) {
				initial_status = JOIN_STATUS_REJECTED;
				initial_reason = "below operator minimum contribution";
			} else if (max_contrib > 0 && contribution_sats > max_contrib) {
				initial_status = JOIN_STATUS_REJECTED;
				initial_reason = "above operator maximum contribution";
			} else if (auto_accept_thresh > 0 &&
				   contribution_sats < auto_accept_thresh) {
				initial_status = JOIN_STATUS_QUEUED;
				initial_reason = "below auto-accept threshold; queued for operator review";
			} else {
				initial_status = JOIN_STATUS_ACCEPTED;
			}

			factory_join_t *j =
				&target_fi->join_queue[target_fi->n_join_queue++];
			memcpy(j->client_node_id, client_pk, 33);
			j->request_id = req_id;
			j->contribution_sats = contribution_sats;
			j->received_at_block = ss_state.current_blockheight;
			j->accepted_at_block =
				(initial_status == JOIN_STATUS_ACCEPTED)
					? ss_state.current_blockheight : 0;
			j->decided_at_block = ss_state.current_blockheight;
			j->status = initial_status;
			memset(j->reason, 0, 64);
			if (initial_reason[0])
				strncpy(j->reason, initial_reason, 63);
			resp_status = initial_status;
			resp_reason = initial_reason;
			plugin_log(plugin_handle, LOG_INFORM,
				   "join: accepted client %s for factory "
				   "(req_id=%llu, contribution=%llu sats, "
				   "queue_size=%zu)",
				   peer_id,
				   (unsigned long long)req_id,
				   (unsigned long long)contribution_sats,
				   target_fi->n_join_queue);
			ss_audit_log(LOG_INFORM, "join_status",
				     "\"peer\":\"%s\",\"req_id\":%llu,"
				     "\"transition\":\"->ACCEPTED\","
				     "\"contribution_sats\":%llu,"
				     "\"queue_size\":%zu",
				     peer_id,
				     (unsigned long long)req_id,
				     (unsigned long long)contribution_sats,
				     target_fi->n_join_queue);
			ss_save_factory(cmd, target_fi);
		}

		/* Build JOIN_RESPONSE: u64 req_id + u8 status + u32 expected_block
		 * + u8 reason_len + reason + u16 trailing_tlv_len */
		size_t rlen = strlen(resp_reason);
		if (rlen > 64) rlen = 64;
		uint8_t resp[8 + 1 + 4 + 1 + 64 + 2];
		uint8_t *rp = resp;
		for (int k = 7; k >= 0; k--) *rp++ = (req_id >> (k*8)) & 0xFF;
		*rp++ = (uint8_t)resp_status;
		/* expected_signing_block = 0 for v1 (TODO: real estimate) */
		for (int k = 0; k < 4; k++) *rp++ = 0;
		*rp++ = (uint8_t)rlen;
		memcpy(rp, resp_reason, rlen); rp += rlen;
		*rp++ = 0; *rp++ = 0;
		size_t actual = (size_t)(rp - resp);
		send_factory_msg(cmd, peer_id, SS_SUBMSG_JOIN_RESPONSE,
				 resp, actual);
		plugin_log(plugin_handle, LOG_DBG,
			   "join: sent JOIN_RESPONSE to %s (req_id=%llu, "
			   "status=%d, %zu bytes)",
			   peer_id, (unsigned long long)req_id,
			   (int)resp_status, actual);
		break;
	}

	/* Phase 3: SS_SUBMSG_JOIN_RESPONSE — client-side handler.
	 * LSP has decided on our outstanding JOIN_REQUEST. Update both the
	 * pending-RPC slot AND the persistent outgoing_joins entry. */
	case SS_SUBMSG_JOIN_RESPONSE: {
		if (len < 14) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "JOIN_RESPONSE from %s too short (%zu bytes)",
				   peer_id, len);
			break;
		}
		uint64_t req_id = 0;
		for (int i = 0; i < 8; i++) req_id = (req_id << 8) | data[i];
		uint8_t status = data[8];
		uint32_t exp_block = 0;
		for (int i = 0; i < 4; i++)
			exp_block = (exp_block << 8) | data[9 + i];
		uint8_t reason_len = data[13];
		if (reason_len > 64) reason_len = 64;
		if (len < (size_t)(14 + reason_len + 2)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "JOIN_RESPONSE truncated body");
			break;
		}
		char reason[65];
		memcpy(reason, data + 14, reason_len);
		reason[reason_len] = 0;

		/* Update persistent outgoing_joins state */
		outgoing_join_t *oj = NULL;
		for (size_t i = 0; i < ss_state.n_outgoing_joins; i++) {
			if (ss_state.outgoing_joins[i].request_id == req_id) {
				oj = &ss_state.outgoing_joins[i];
				break;
			}
		}
		if (oj) {
			oj->expected_signing_block = exp_block;
			oj->updated_at_block = ss_state.current_blockheight;
			memcpy(oj->reason, reason, sizeof(oj->reason) - 1);
			oj->reason[sizeof(oj->reason) - 1] = 0;
			switch ((factory_join_status_t)status) {
			case JOIN_STATUS_QUEUED:
				oj->status = OUTGOING_JOIN_QUEUED; break;
			case JOIN_STATUS_ACCEPTED:
				oj->status = OUTGOING_JOIN_ACCEPTED; break;
			case JOIN_STATUS_SIGNED:
				oj->status = OUTGOING_JOIN_SIGNED; break;
			case JOIN_STATUS_REJECTED:
				oj->status = OUTGOING_JOIN_REJECTED; break;
			case JOIN_STATUS_CANCELLED:
				oj->status = OUTGOING_JOIN_CANCELLED; break;
			case JOIN_STATUS_ALREADY_MEMBER:
				oj->status = OUTGOING_JOIN_ALREADY_MEMBER; break;
			}
			/* Task #62: ss_save_outgoing_joins disabled — see json_factory_join_request comment */
			plugin_log(plugin_handle, LOG_INFORM,
				   "join: updated outgoing join req_id=%llu "
				   "status=%d reason='%s'",
				   (unsigned long long)req_id,
				   (int)status, reason);
		}

		/* Resolve any pending factory-join-request RPC */
		int slot = ss_join_find_slot(req_id);
		if (slot < 0) {
			plugin_log(plugin_handle, LOG_DBG,
				   "JOIN_RESPONSE for req_id=%llu has no pending "
				   "RPC (unsolicited or already timed out)",
				   (unsigned long long)req_id);
			break;
		}
		struct command *orig_cmd = ss_join_pending[slot].cmd;
		ss_peer_usage_release_slot(ss_join_pending[slot].peer_id);
		ss_join_pending[slot].request_id = 0;
		ss_join_pending[slot].cmd = NULL;
		ss_join_pending[slot].deadline = 0;

		if (!orig_cmd) break;

		struct json_stream *js = jsonrpc_stream_success(orig_cmd);
		json_add_u64(js, "request_id", req_id);
		const char *status_name = "unknown";
		switch ((factory_join_status_t)status) {
		case JOIN_STATUS_QUEUED:         status_name = "queued"; break;
		case JOIN_STATUS_ACCEPTED:       status_name = "accepted"; break;
		case JOIN_STATUS_SIGNED:         status_name = "signed"; break;
		case JOIN_STATUS_REJECTED:       status_name = "rejected"; break;
		case JOIN_STATUS_CANCELLED:      status_name = "cancelled"; break;
		case JOIN_STATUS_ALREADY_MEMBER: status_name = "already_member"; break;
		}
		json_add_string(js, "status", status_name);
		json_add_u32(js, "expected_signing_block", exp_block);
		json_add_string(js, "reason", reason);
		struct command_result *_cf = command_finished(orig_cmd, js);
		(void)_cf;
		break;
	}

	/* Phase 3: SS_SUBMSG_JOIN_CANCEL — LSP-side handler.
	 * Client withdrew a pending join. Mark the queue entry as CANCELLED.
	 * No response sent (fire-and-forget per design). Client's local
	 * wallet has already locally marked the cancellation; LSP's record
	 * is for visibility in factory-incoming-joins.
	 *
	 * Wire format (42 bytes):
	 *   u64    request_id
	 *   u8[32] instance_id
	 *   u16    trailing_tlv_len
	 */
	case SS_SUBMSG_JOIN_CANCEL: {
		if (len < 42) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "JOIN_CANCEL from %s too short (%zu bytes)",
				   peer_id, len);
			break;
		}
		uint64_t req_id = 0;
		for (int i = 0; i < 8; i++) req_id = (req_id << 8) | data[i];
		const uint8_t *iid = data + 8;

		factory_instance_t *target_fi = ss_factory_find(&ss_state, iid);
		if (!target_fi || !target_fi->is_lsp) {
			plugin_log(plugin_handle, LOG_DBG,
				   "JOIN_CANCEL for unknown/non-LSP factory "
				   "(req_id=%llu) — ignored",
				   (unsigned long long)req_id);
			break;
		}

		/* Decode peer_id to verify the cancel comes from the same
		 * client who originally requested. */
		uint8_t client_pk[33];
		if (strlen(peer_id) != 66) break;
		for (int k = 0; k < 33; k++) {
			unsigned int by;
			sscanf(peer_id + k*2, "%2x", &by);
			client_pk[k] = (uint8_t)by;
		}

		bool found = false;
		for (size_t i = 0; i < target_fi->n_join_queue; i++) {
			factory_join_t *j = &target_fi->join_queue[i];
			if (j->request_id != req_id) continue;
			if (memcmp(j->client_node_id, client_pk, 33) != 0) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "JOIN_CANCEL req_id=%llu sender %s "
					   "doesn't match original requester — "
					   "ignored",
					   (unsigned long long)req_id, peer_id);
				break;
			}
			j->status = JOIN_STATUS_CANCELLED;
			j->decided_at_block = ss_state.current_blockheight;
			strncpy((char *)j->reason, "client cancelled",
				sizeof(j->reason) - 1);
			j->reason[sizeof(j->reason) - 1] = 0;
			found = true;
			plugin_log(plugin_handle, LOG_INFORM,
				   "join: cancelled by client %s "
				   "(req_id=%llu)",
				   peer_id, (unsigned long long)req_id);
			ss_save_factory(cmd, target_fi);
			break;
		}
		if (!found) {
			plugin_log(plugin_handle, LOG_DBG,
				   "JOIN_CANCEL req_id=%llu not found in queue "
				   "(already processed or never existed)",
				   (unsigned long long)req_id);
		}
		break;
	}

	/* PR 3: CEREMONY_START — client-side receipt of "LSP wants to
	 * sign". Decodes the ceremony_id and factory_instance_id, looks
	 * up the local factory_instance_t, transitions to CEREMONY_RUNNING,
	 * and caches the ceremony_id so subsequent MuSig2 messages can
	 * be matched.
	 *
	 * PR 3 foundation note: the lsp_nonce field is zeroed in this PR
	 * (the existing FACTORY_PROPOSE 0x0100 flow still carries the
	 * real MuSig2 nonces). When PR 3b retires FACTORY_PROPOSE in
	 * favor of CEREMONY_START as the MuSig2 round-1 carrier, the
	 * client-side handler here will read lsp_nonce and start its own
	 * nonce generation. */
	case SS_SUBMSG_CEREMONY_START: {
		struct ss_ceremony_start_msg start_msg;
		if (!ss_decode_ceremony_start(data, len, &start_msg)) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "CEREMONY_START from %s: malformed payload "
				   "(len=%zu)",
				   peer_id, len);
			break;
		}

		/* Look up factory by instance_id */
		factory_instance_t *target_fi =
			ss_factory_find(&ss_state, start_msg.factory_instance_id);
		if (!target_fi) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "CEREMONY_START from %s: unknown factory_instance_id "
				   "%02x%02x%02x%02x... (ceremony will be ignored; "
				   "consider sending REFUSE_UNKNOWN_FACTORY when "
				   "NONCE_REPLY response path is wired)",
				   peer_id,
				   start_msg.factory_instance_id[0],
				   start_msg.factory_instance_id[1],
				   start_msg.factory_instance_id[2],
				   start_msg.factory_instance_id[3]);
			break;
		}

		/* Sanity: type byte should be INITIAL for v1 INITIAL ceremonies.
		 * Other types (ROTATE/FORCE_OUT/ABORT) are deferred. */
		if (start_msg.type != SS_CEREMONY_TYPE_INITIAL) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "CEREMONY_START from %s: type=0x%02x not yet "
				   "supported (v1 supports INITIAL=0x01 only)",
				   peer_id, start_msg.type);
			break;
		}

		char cid_hex[17];
		for (int i = 0; i < 8; i++)
			sprintf(cid_hex + i*2, "%02x", start_msg.ceremony_id[i]);
		cid_hex[16] = 0;

		ss_audit_log(LOG_INFORM, "ceremony_start_received",
			     "\"peer\":\"%.16s\","
			     "\"iid_prefix\":\"%02x%02x%02x%02x\","
			     "\"ceremony_id_hex\":\"%s\","
			     "\"type\":\"INITIAL\","
			     "\"deadline_block\":%u",
			     peer_id,
			     target_fi->instance_id[0],
			     target_fi->instance_id[1],
			     target_fi->instance_id[2],
			     target_fi->instance_id[3],
			     cid_hex,
			     start_msg.deadline_block);

		/* Transition client-side lifecycle. If we were AWAITING_JOINS
		 * (deferred client) move to CEREMONY_RUNNING. If we were INIT
		 * (legacy flow already started) leave it alone — the existing
		 * FACTORY_PROPOSE will drive the rest. */
		if (factory_is_awaiting_signing(target_fi->lifecycle))
			target_fi->lifecycle = FACTORY_LIFECYCLE_CEREMONY_RUNNING;

		/* Cache ceremony_id on the factory so subsequent ceremony
		 * submsgs (NONCE_REPLY, PARTIAL_SIG, etc.) can match this
		 * ceremony. Stored in factory_instance_t.active_ceremony_id;
		 * see factory_state.h. PR 3 foundation: field added below. */
		memcpy(target_fi->active_ceremony_id, start_msg.ceremony_id, 8);
		target_fi->active_ceremony_deadline_block = start_msg.deadline_block;

		ss_save_factory(cmd, target_fi);
		break;
	}

	/* PR 3: remaining ceremony submsgs (NONCE_REPLY, PARTIAL_SIG_REQ,
	 * PARTIAL_SIG, RESULT, ABORT, STATUS_QUERY, STATUS_REPLY) are
	 * decoded-and-logged only in this PR. Full handlers land in PR 3b
	 * when the MuSig2 round-1/round-2 plumbing is wired to the new
	 * wire and the lib SQLite persist_t is open. */
	case SS_SUBMSG_CEREMONY_NONCE_REPLY:
	case SS_SUBMSG_CEREMONY_PARTIAL_SIG_REQ:
	case SS_SUBMSG_CEREMONY_PARTIAL_SIG:
	case SS_SUBMSG_CEREMONY_RESULT:
	case SS_SUBMSG_CEREMONY_STATUS_QUERY:
	case SS_SUBMSG_CEREMONY_STATUS_REPLY:
		plugin_log(plugin_handle, LOG_DBG,
			   "Ceremony submsg 0x%04x from %s (len=%zu) — "
			   "handler is PR 3b scope; received but not yet "
			   "processed",
			   submsg_id, peer_id, len);
		break;

	case SS_SUBMSG_CEREMONY_ABORT: {
		/* Audit item #3: explicit client refusal of a ceremony slot.
		 * Payload is [instance_id(32) || reason(1)]. */
		if (len < 33) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "CEREMONY_ABORT from %s too short (%zu)",
				   peer_id, len);
			break;
		}
		uint8_t inst_id[32];
		memcpy(inst_id, data, 32);
		uint8_t reason = data[32];

		char inst_hex[65];
		for (int i = 0; i < 32; i++)
			sprintf(inst_hex + i*2, "%02x", inst_id[i]);
		inst_hex[64] = '\0';

		const char *rname =
			reason == SS_CEREMONY_ABORT_USER_REFUSED    ? "USER_REFUSED" :
			reason == SS_CEREMONY_ABORT_POLICY_VIOLATED ? "POLICY_VIOLATED" :
			reason == SS_CEREMONY_ABORT_DEADLINE_PASSED ? "DEADLINE_PASSED" :
			reason == SS_CEREMONY_ABORT_OTHER           ? "OTHER" : "UNKNOWN";

		factory_instance_t *fi = ss_factory_find(&ss_state, inst_id);
		if (!fi) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "CEREMONY_ABORT from %s for unknown instance %s "
				   "(reason=%s) — ignored",
				   peer_id, inst_hex, rname);
			break;
		}

		/* Find the client slot for the peer that sent the abort. */
		uint8_t peer_pk[33];
		bool found = false;
		if (ss_decode_node_id_hex(peer_id, peer_pk)) {
			for (size_t ci = 0; ci < fi->n_clients; ci++) {
				if (memcmp(fi->clients[ci].node_id, peer_pk, 33) == 0) {
					/* Mark them disconnected so the deadline tick
					 * cleans up without waiting. */
					fi->clients[ci].connected = false;
					found = true;
					plugin_log(plugin_handle, LOG_INFORM,
						   "CEREMONY_ABORT: client %zu (%s) "
						   "refused factory %s reason=%s",
						   ci, peer_id, inst_hex, rname);
					break;
				}
			}
		}
		if (!found) {
			plugin_log(plugin_handle, LOG_INFORM,
				   "CEREMONY_ABORT: %s refused factory %s reason=%s "
				   "(peer not a client of this factory)",
				   peer_id, inst_hex, rname);
		}
		break;
	}


	case SS_SUBMSG_SIGN_QUEUE_REQUEST: {
		/* D.3 LSP handler: parse optional TLVs (factory_iid filter,
		 * since_block filter), then build SIGN_QUEUE_RESPONSE with
		 * matching entries from ss_lsp_sig_queue. */
		uint8_t filter_iid[32];
		bool has_iid_filter = false;
		uint32_t since_block = 0;
		size_t p = 0;
		while (p + 2 <= len) {
			uint8_t t = data[p++];
			uint8_t l = data[p++];
			if (p + l > len) break;
			if (t == 0x00 && l == 32) {
				memcpy(filter_iid, data + p, 32);
				has_iid_filter = true;
			} else if (t == 0x01 && l == 4) {
				since_block = ((uint32_t)data[p] << 24)
					    | ((uint32_t)data[p+1] << 16)
					    | ((uint32_t)data[p+2] << 8)
					    | ((uint32_t)data[p+3]);
			}
			p += l;
		}

		/* Build the response payload. */
		uint8_t client_pk[33];
		if (!ss_decode_node_id_hex(peer_id, client_pk)) break;

		uint8_t *resp = NULL;
		size_t resp_cap = 4096;
		size_t resp_len = 0;
		resp = malloc(resp_cap);
		if (!resp) break;

		for (int i = 0; i < SS_LSP_SIG_QUEUE_SIZE; i++) {
			struct ss_lsp_sig_queue_entry *e = &ss_lsp_sig_queue[i];
			if (!e->used) continue;
			if (memcmp(e->client_peer_id, client_pk, 33) != 0) continue;
			if (has_iid_filter
			    && memcmp(e->factory_instance_id, filter_iid, 32) != 0) continue;
			if (e->inserted_at_block < since_block) continue;

			/* Reserve worst-case bytes: 6 TLV headers + 32 + 8 + 1 + 4 + blob */
			size_t need = resp_len + 6 + 32 + 8 + 1 + 4 + e->proposal_blob_len + 4;
			if (need > resp_cap) {
				size_t new_cap = resp_cap;
				while (new_cap < need) new_cap *= 2;
				uint8_t *bigger = realloc(resp, new_cap);
				if (!bigger) break;
				resp = bigger; resp_cap = new_cap;
			}

			/* Entry framing: 0xFE 0xFE (sentinel), then TLVs */
			resp[resp_len++] = 0xFE; resp[resp_len++] = 0xFE;

			/* TLV 0x00: factory_instance_id */
			resp[resp_len++] = 0x00; resp[resp_len++] = 32;
			memcpy(resp + resp_len, e->factory_instance_id, 32);
			resp_len += 32;

			/* TLV 0x01: ceremony_id */
			resp[resp_len++] = 0x01; resp[resp_len++] = 8;
			memcpy(resp + resp_len, e->ceremony_id, 8);
			resp_len += 8;

			/* TLV 0x02: state */
			resp[resp_len++] = 0x02; resp[resp_len++] = 1;
			resp[resp_len++] = e->state;

			/* TLV 0x03: deadline_block */
			resp[resp_len++] = 0x03; resp[resp_len++] = 4;
			resp[resp_len++] = (e->deadline_block >> 24) & 0xFF;
			resp[resp_len++] = (e->deadline_block >> 16) & 0xFF;
			resp[resp_len++] = (e->deadline_block >>  8) & 0xFF;
			resp[resp_len++] = (e->deadline_block      ) & 0xFF;

			/* TLV 0x04: proposal_blob (only if AWAITING) */
			if (e->state == SS_SIGQUEUE_AWAITING_YOUR_SIGNATURE
			    && e->proposal_blob && e->proposal_blob_len > 0
			    && e->proposal_blob_len < 65535) {
				resp[resp_len++] = 0x04;
				/* 2-byte length prefix for blob */
				resp[resp_len++] = 0xfd;
				resp[resp_len++] = (e->proposal_blob_len >> 8) & 0xFF;
				resp[resp_len++] = e->proposal_blob_len & 0xFF;
				memcpy(resp + resp_len, e->proposal_blob, e->proposal_blob_len);
				resp_len += e->proposal_blob_len;
			}
		}

		plugin_log(plugin_handle, LOG_INFORM,
			   "SIGN_QUEUE_REQUEST from %s -> sending response "
			   "(%zu bytes, has_iid_filter=%d)",
			   peer_id, resp_len, has_iid_filter);

		send_factory_msg(cmd, peer_id, SS_SUBMSG_SIGN_QUEUE_RESPONSE,
				 resp, resp_len);
		free(resp);
		break;
	}

	case SS_SUBMSG_SIGN_QUEUE_RESPONSE: {
		/* D.4 client-side: parse entries, log + (for AWAITING)
		 * re-dispatch as a fresh FACTORY_PROPOSE so the existing
		 * client-side handler picks it up + runs validator. */
		plugin_log(plugin_handle, LOG_INFORM,
			   "SIGN_QUEUE_RESPONSE from %s (len=%zu)",
			   peer_id, len);

		size_t p = 0;
		while (p + 2 <= len) {
			/* Entry sentinel */
			if (data[p] != 0xFE || data[p+1] != 0xFE) break;
			p += 2;

			uint8_t entry_iid[32]; bool have_iid = false;
			uint8_t entry_state = 0xFF;
			uint32_t entry_deadline = 0;
			const uint8_t *entry_blob = NULL;
			size_t entry_blob_len = 0;

			while (p + 2 <= len && !(data[p] == 0xFE && data[p+1] == 0xFE)) {
				uint8_t t = data[p++];
				size_t vlen = data[p++];
				if (vlen == 0xfd && p + 2 <= len) {
					vlen = ((size_t)data[p] << 8) | data[p+1];
					p += 2;
				}
				if (p + vlen > len) break;
				switch (t) {
				case 0x00: if (vlen == 32) { memcpy(entry_iid, data + p, 32); have_iid = true; } break;
				case 0x02: if (vlen == 1) entry_state = data[p]; break;
				case 0x03: if (vlen == 4) {
					entry_deadline = ((uint32_t)data[p] << 24)
						       | ((uint32_t)data[p+1] << 16)
						       | ((uint32_t)data[p+2] << 8)
						       | ((uint32_t)data[p+3]);
				} break;
				case 0x04: entry_blob = data + p; entry_blob_len = vlen; break;
				}
				p += vlen;
			}

			if (!have_iid) continue;

			char iid_prefix[9];
			for (int j = 0; j < 4; j++) sprintf(iid_prefix + j*2, "%02x", entry_iid[j]);
			iid_prefix[8] = 0;

			plugin_log(plugin_handle, LOG_INFORM,
				   "SIGN_QUEUE entry: iid_prefix=%s state=%u deadline=%u blob=%zu",
				   iid_prefix, entry_state, entry_deadline, entry_blob_len);
			ss_audit_log(LOG_INFORM, "sign_queue_entry",
				"{\"peer\":\"%s\",\"iid_prefix\":\"%s\",\"state\":%u,"
				"\"deadline_block\":%u,\"blob_len\":%zu}",
				peer_id, iid_prefix, entry_state, entry_deadline, entry_blob_len);

			/* D follow-up: stash non-AWAITING entries in the ring
			 * for the wallet missed-ceremony banner. */
			if (entry_state == SS_SIGQUEUE_MISSED
			    || entry_state == SS_SIGQUEUE_EXPIRED
			    || entry_state == SS_SIGQUEUE_REFUSED) {
				uint8_t lsp_pk[33];
				if (ss_decode_node_id_hex(peer_id, lsp_pk)) {
					uint8_t dummy_cid[8] = { 0 };
					ss_recent_sq_push(entry_iid, lsp_pk,
						dummy_cid, entry_state, entry_deadline);
				}
			}

			/* Re-dispatch AWAITING entries via the existing FACTORY_PROPOSE
			 * handler — validator runs, then either auto-sign or hold. */
			if (entry_state == SS_SIGQUEUE_AWAITING_YOUR_SIGNATURE
			    && entry_blob && entry_blob_len > 0) {
				uint8_t *blob_copy = malloc(entry_blob_len);
				if (blob_copy) {
					memcpy(blob_copy, entry_blob, entry_blob_len);
					dispatch_superscalar_submsg(cmd, peer_id,
						SS_SUBMSG_FACTORY_PROPOSE,
						blob_copy, entry_blob_len);
					free(blob_copy);
				}
			}
		}
		break;
	}

	default:
		plugin_log(plugin_handle, LOG_DBG,
			   "Unknown submsg 0x%04x from %s (len=%zu)",
			   submsg_id, peer_id, len);
		break;
	}
}

/* Dispatch bLIP-56 factory change submessages */
static void dispatch_blip56_submsg(struct command *cmd,
				   const char *peer_id,
				   u16 submsg_id,
				   const u8 *data, size_t len)
{
	switch (submsg_id) {
	case BLIP56_SUBMSG_SUPPORTED_PROTOCOLS: /* 2 */
		/* Peer sent their supported factory protocol IDs.
		 * TLV type 512: concatenated 32-byte IDs. */
		plugin_log(plugin_handle, LOG_INFORM,
			   "supported_factory_protocols from %s (len=%zu)",
			   peer_id, len);
		if (len >= 35) {
			/* Parse TLV: skip type(3)+len(1), read IDs */
			const uint8_t *ids = data + 4;
			size_t ids_len = len - 4;
			size_t n_protos = ids_len / 32;
			bool has_superscalar = false;
			for (size_t pi = 0; pi < n_protos; pi++) {
				if (memcmp(ids + pi * 32,
					   SUPERSCALAR_PROTOCOL_ID, 32) == 0) {
					has_superscalar = true;
					break;
				}
			}
			plugin_log(plugin_handle, LOG_INFORM,
				   "Peer %s supports %zu protocols, "
				   "SuperScalar=%s",
				   peer_id, n_protos,
				   has_superscalar ? "yes" : "no");
		}
		break;

	case BLIP56_SUBMSG_FACTORY_PIGGYBACK: /* 4 */
		/* Unwrap factory_piggyback: extract protocol_id + payload.
		 * TLV[0]=protocol_id(32), TLV[1024]=payload(ss_submsg+data) */
		if (len >= 36) {
			/* Skip TLV type 0 header (type=1byte, len=1byte) */
			const uint8_t *proto_id = data + 2;
			if (memcmp(proto_id, SUPERSCALAR_PROTOCOL_ID, 32) != 0) {
				plugin_log(plugin_handle, LOG_DBG,
					   "Unknown factory protocol in piggyback");
				break;
			}
			/* Find TLV type 1024 payload */
			const uint8_t *p = data + 34;
			size_t remaining = len - 34;
			if (remaining < 4) break;
			/* Skip TLV type 1024 header (fd 04 00 + len) */
			p += 3; remaining -= 3;
			size_t payload_len;
			if (*p < 253) {
				payload_len = *p++;
				remaining--;
			} else {
				payload_len = (p[1] << 8) | p[2];
				p += 3; remaining -= 3;
			}
			if (remaining < 2 || payload_len < 2) break;
			uint16_t ss_sub = (p[0] << 8) | p[1];
			dispatch_superscalar_submsg(cmd, peer_id,
				ss_sub, p + 2, payload_len - 2);
		}
		break;

	case 6: /* factory_change_init */
		plugin_log(plugin_handle, LOG_INFORM,
			   "factory_change_init from %s (len=%zu)",
			   peer_id, len);
		/* Extract channel_id + funding_contribution + funding_pubkey
		 * from TLV type 1536. Validate with our factory state.
		 * For now, auto-ack to proceed with the change. */
		{
			/* Send factory_change_ack (submsg 8) with same TLVs */
			uint8_t ack_wire[4 + 256];
			ack_wire[0] = (FACTORY_MSG_TYPE >> 8) & 0xFF;
			ack_wire[1] = FACTORY_MSG_TYPE & 0xFF;
			ack_wire[2] = 0x00; ack_wire[3] = 0x08;
			memcpy(ack_wire + 4, data, len < 256 ? len : 256);
			size_t ack_len = 4 + (len < 256 ? len : 256);

			char *ahex = tal_arr(cmd, char, ack_len * 2 + 1);
			for (size_t h = 0; h < ack_len; h++)
				sprintf(ahex + h*2, "%02x", ack_wire[h]);

			struct out_req *areq = jsonrpc_request_start(cmd,
				"sendcustommsg", rpc_done, rpc_err, cmd);
			json_add_string(areq->js, "node_id", peer_id);
			json_add_string(areq->js, "msg", ahex);
			send_outreq(areq);

			plugin_log(plugin_handle, LOG_INFORM,
				   "Sent factory_change_ack to %s", peer_id);
		}
		break;

	case 8: /* factory_change_ack */
		plugin_log(plugin_handle, LOG_INFORM,
			   "factory_change_ack from %s (len=%zu)",
			   peer_id, len);
		/* Peer acknowledged our factory_change_init.
		 * Next: send factory_change_funding (submsg 10) with new txid. */
		break;

	case 10: /* factory_change_funding */
		plugin_log(plugin_handle, LOG_INFORM,
			   "factory_change_funding from %s (len=%zu)",
			   peer_id, len);
		/* Peer sent new funding txid. Validate against our factory state.
		 * Next: sign commitment for new funding outpoint. */
		break;

	case 12: /* factory_change_continue */
		plugin_log(plugin_handle, LOG_INFORM,
			   "factory_change_continue from %s", peer_id);
		/* Peer says new factory state is valid. Resume channel. */
		break;

	case 14: /* factory_change_locked */
		plugin_log(plugin_handle, LOG_INFORM,
			   "factory_change_locked from %s", peer_id);
		/* Old state invalidated. New state is the sole valid state. */
		break;

	default:
		/* Direct SuperScalar submessages (0x0100+) for backward compat */
		if (submsg_id >= 0x0100 && submsg_id <= 0x01FF) {
			dispatch_superscalar_submsg(cmd, peer_id,
						    submsg_id, data, len);
		} else {
			plugin_log(plugin_handle, LOG_DBG,
				   "Unknown submsg %u from %s", submsg_id, peer_id);
		}
		break;
	}
}

/* Handle incoming factory messages from peers */
static struct command_result *handle_custommsg(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	const jsmntok_t *payload_tok, *peer_id_tok;
	const u8 *payload;
	const char *peer_id;
	u16 type, submsg_id;

	peer_id_tok = json_get_member(buf, params, "peer_id");
	payload_tok = json_get_member(buf, params, "payload");
	if (!payload_tok || !peer_id_tok)
		return command_hook_success(cmd);

	peer_id = json_strdup(cmd, buf, peer_id_tok);
	payload = json_tok_bin_from_hex(cmd, buf, payload_tok);
	if (!payload || tal_bytelen(payload) < 4)
		return command_hook_success(cmd);

	type = (payload[0] << 8) | payload[1];
	if (type != FACTORY_MSG_TYPE)
		return command_hook_success(cmd);

	submsg_id = (payload[2] << 8) | payload[3];
	dispatch_blip56_submsg(cmd, peer_id, submsg_id,
			       payload + 4, tal_bytelen(payload) - 4);

	/* If a factory entered CEREMONY_FUNDING_PENDING, an async RPC
	 * (withdraw) is in flight. Don't destroy cmd yet — the callback
	 * will call command_hook_success when done. */
	for (size_t i = 0; i < ss_state.n_factories; i++) {
		if (ss_state.factories[i]->ceremony == CEREMONY_FUNDING_PENDING)
			return command_still_pending(cmd);
	}

	return command_hook_success(cmd);
}

/* Handle htlc_accepted hook — enforce factory_early_warning_time CLTV.
 * Reject incoming HTLCs on factory channels if cltv_expiry is too tight
 * (not enough headroom for the factory's nested relative timelocks). */
static struct command_result *handle_htlc_accepted(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params)
{
	const jsmntok_t *htlc_tok = json_get_member(buf, params, "htlc");
	if (!htlc_tok)
		return command_hook_success(cmd);

	const jsmntok_t *cltv_tok = json_get_member(buf, htlc_tok,
						     "cltv_expiry");
	const jsmntok_t *scid_tok = json_get_member(buf, htlc_tok,
						     "short_channel_id");
	if (!cltv_tok)
		return command_hook_success(cmd);

	u32 cltv_expiry;
	if (!json_to_u32(buf, cltv_tok, &cltv_expiry))
		return command_hook_success(cmd);

	uint32_t max_early_warning = 0;
	for (size_t i = 0; i < ss_state.n_factories; i++) {
		factory_instance_t *fi = ss_state.factories[i];
		if (fi->lifecycle == FACTORY_LIFECYCLE_ACTIVE
		    && fi->early_warning_time > max_early_warning)
			max_early_warning = fi->early_warning_time;
	}

	if (max_early_warning > 0
	    && cltv_expiry < ss_state.current_blockheight
			     + max_early_warning + 1) {
		plugin_log(plugin_handle, LOG_INFORM,
			   "htlc_accepted: rejecting cltv=%u (need >= %u for ewt=%u)",
			   cltv_expiry,
			   ss_state.current_blockheight + max_early_warning + 1,
			   max_early_warning);

		u8 *failmsg = towire_incorrect_cltv_expiry(cmd, cltv_expiry,
							    NULL);
		struct json_stream *response = jsonrpc_stream_success(cmd);
		json_add_string(response, "result", "fail");
		json_add_hex(response, "failure_message", failmsg,
			     tal_count(failmsg));
		return command_finished(cmd, response);
	}

	return command_hook_success(cmd);
}

/* Handle openchannel hook — process channel_in_factory TLV (65600) */
static struct command_result *handle_openchannel(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	const jsmntok_t *openchannel;

	openchannel = json_get_member(buf, params, "openchannel");
	if (!openchannel)
		return command_hook_success(cmd);

	/* Check if the peer opening this channel is a known factory
	 * participant. If so, accept with mindepth=0 (zero-conf)
	 * since factory channels have virtual funding outpoints. */
	const jsmntok_t *id_tok = json_get_member(buf, openchannel, "id");
	if (!id_tok)
		return command_hook_success(cmd);

	const char *peer_hex = json_strdup(cmd, buf, id_tok);
	if (!peer_hex || strlen(peer_hex) != 66)
		return command_hook_success(cmd);

	/* Parse peer node_id */
	uint8_t peer_id[33];
	for (int j = 0; j < 33; j++) {
		unsigned int b;
		sscanf(peer_hex + j*2, "%02x", &b);
		peer_id[j] = (uint8_t)b;
	}

	/* Check if this peer is the LSP of any of our factories,
	 * or a client in any factory we're the LSP of. */
	bool is_factory_peer = false;
	for (size_t i = 0; i < ss_state.n_factories; i++) {
		factory_instance_t *fi = ss_state.factories[i];

		/* Client side: check if peer is our LSP */
		if (!fi->is_lsp &&
		    memcmp(fi->lsp_node_id, peer_id, 33) == 0) {
			is_factory_peer = true;
			break;
		}

		/* LSP side: check if peer is a client */
		if (fi->is_lsp) {
			for (size_t ci = 0; ci < fi->n_clients; ci++) {
				if (memcmp(fi->clients[ci].node_id,
					   peer_id, 33) == 0) {
					is_factory_peer = true;
					break;
				}
			}
			if (is_factory_peer) break;
		}
	}

	if (is_factory_peer) {
		plugin_log(plugin_handle, LOG_INFORM,
			   "Factory peer %s opening channel — "
			   "accepting with mindepth=0", peer_hex);

		/* Return mindepth=0 to accept zero-conf */
		struct json_stream *js = jsonrpc_stream_success(cmd);
		json_add_string(js, "result", "continue");
		json_add_u32(js, "mindepth", 0);
		return command_finished(cmd, js);
	}

	return command_hook_success(cmd);
}

/* factory-create RPC — LSP creates a new factory (Phase 1)
 * Takes client node IDs and creates the DW tree. */
/* Bug C fix: context carried across the listpeers preflight callback */
struct browse_preflight_ctx {
	const char *node_id_str;
	uint32_t since_block;
	char *address;  /* Task #118: optional connect address hint */
};

/* Bug C fix: listpeers preflight succeeded. Check the peer is actually
 * connected before allocating a slot and sending the wire request. */

/* ============================================================================
 * Task #118: ss_ensure_peer_connected — async helper used by browse-host /
 * join-request RPCs to ensure BOLT-8 peering before sending custommsg.
 *
 * Flow:
 *   listpeers id=node_id
 *      \-> if connected:  call done_cb(cmd, user)
 *      \-> if not connected AND address provided: connect id=node_id host=address
 *           \-> on success: done_cb(cmd, user)
 *           \-> on failure: err_cb(cmd, user, msg)
 *      \-> if not connected AND no address: err_cb(cmd, user, "no address hint")
 *
 * The caller passes a tal-allocated user-context pointer and the two
 * callbacks; this helper takes ownership of bridging through the listpeers
 * + optional connect calls.
 *
 * In the auto-connect path we let CLN handle gossip lookup: if the caller
 * passes a bare pubkey to connect (no host), CLN walks the node_announcement
 * gossip itself.  Most useful for testnet4 fleets where addresses arent
 * yet learned via gossip — the wallet passes the address explicitly from
 * the rendezvous vouch.
 * ============================================================================ */
struct ss_ensure_connect_ctx {
	char *node_id_str;
	char *address;  /* may be NULL */
	void *user;
	struct command_result *(*done_cb)(struct command *cmd, void *user);
	struct command_result *(*err_cb)(struct command *cmd, void *user,
					 const char *errmsg);
};

static struct command_result *ss_ensure_connect_done(
	struct command *cmd, const char *method UNUSED,
	const char *buf UNUSED, const jsmntok_t *result UNUSED, void *arg)
{
	struct ss_ensure_connect_ctx *ec = arg;
	plugin_log(plugin_handle, LOG_INFORM,
		   "auto-connect to %s succeeded", ec->node_id_str);
	return ec->done_cb(cmd, ec->user);
}

static struct command_result *ss_ensure_connect_failed(
	struct command *cmd, const char *method UNUSED,
	const char *buf, const jsmntok_t *result, void *arg)
{
	struct ss_ensure_connect_ctx *ec = arg;
	const jsmntok_t *m = json_get_member(buf, result, "message");
	const char *msg = m ? json_strdup(cmd, buf, m) : "connect failed";
	plugin_log(plugin_handle, LOG_UNUSUAL,
		   "auto-connect to %s failed: %s", ec->node_id_str, msg);
	return ec->err_cb(cmd, ec->user, msg);
}

static struct command_result *ss_ensure_connect_listpeers_ok(
	struct command *cmd, const char *method UNUSED,
	const char *buf, const jsmntok_t *result, void *arg)
{
	struct ss_ensure_connect_ctx *ec = arg;

	bool connected = false;
	const jsmntok_t *peers = json_get_member(buf, result, "peers");
	if (peers && peers->type == JSMN_ARRAY && peers->size > 0) {
		const jsmntok_t *peer = peers + 1;
		const jsmntok_t *conn = json_get_member(buf, peer, "connected");
		if (conn) json_to_bool(buf, conn, &connected);
	}

	if (connected) {
		return ec->done_cb(cmd, ec->user);
	}

	plugin_log(plugin_handle, LOG_INFORM,
		   "auto-connect: peer %s not connected, attempting connect "
		   "(address_hint=%s)",
		   ec->node_id_str, ec->address ? ec->address : "(none, will use gossip)");

	struct out_req *req = jsonrpc_request_start(cmd, "connect",
		ss_ensure_connect_done, ss_ensure_connect_failed, ec);
	json_add_string(req->js, "id", ec->node_id_str);
	if (ec->address && *ec->address)
		json_add_string(req->js, "host", ec->address);
	return send_outreq(req);
}

static struct command_result *ss_ensure_peer_connected(
	struct command *cmd,
	const char *node_id_str,
	const char *address_hint,  /* may be NULL */
	void *user,
	struct command_result *(*done_cb)(struct command *, void *),
	struct command_result *(*err_cb)(struct command *, void *,
					 const char *errmsg))
{
	struct ss_ensure_connect_ctx *ec = tal(cmd, struct ss_ensure_connect_ctx);
	ec->node_id_str = tal_strdup(ec, node_id_str);
	ec->address = address_hint ? tal_strdup(ec, address_hint) : NULL;
	ec->user = user;
	ec->done_cb = done_cb;
	ec->err_cb = err_cb;

	struct out_req *req = jsonrpc_request_start(cmd, "listpeers",
		ss_ensure_connect_listpeers_ok,
		ss_ensure_connect_failed, ec);
	json_add_string(req->js, "id", node_id_str);
	return send_outreq(req);
}


/* Task #118: invoked after ss_ensure_peer_connected verifies peer is up.
 * Carries out the original browse_preflight_ok body (slot alloc + send). */
static struct command_result *browse_send_now(struct command *cmd, void *user)
{
	struct browse_preflight_ctx *ctx = user;

	int slot = ss_browse_alloc_slot();
	if (slot < 0) {
		ss_audit_log(LOG_UNUSUAL, "slot_exhausted",
			     "\"rpc\":\"factory-browse-host\","
			     "\"peer\":\"%s\",\"max\":%d",
			     ctx->node_id_str, SS_BROWSE_MAX_PENDING);
		return command_fail(cmd, SS_ERR_SLOT_EXHAUSTED,
			"factory-browse-host: too many pending requests "
			"(max %d). Try again later.",
			SS_BROWSE_MAX_PENDING);
	}

	uint64_t req_id = ss_fresh_request_id();
	ss_browse_pending[slot].request_id = req_id;
	ss_browse_pending[slot].cmd = cmd;
	ss_browse_pending[slot].deadline = time(NULL) + ss_browse_timeout_secs;

	uint8_t payload[12];
	uint8_t *p = payload;
	for (int i = 7; i >= 0; i--) *p++ = (uint8_t)(req_id >> (i*8));
	for (int i = 3; i >= 0; i--)
		*p++ = (uint8_t)(ctx->since_block >> (i*8));

	send_factory_msg_browse(cmd, ctx->node_id_str,
				SS_SUBMSG_FACTORY_INFO_REQUEST,
				payload, sizeof(payload));

	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-browse-host: sent FACTORY_INFO_REQUEST to %s "
		   "(req_id=%llu since_block=%u)",
		   ctx->node_id_str, (unsigned long long)req_id,
		   ctx->since_block);

	return command_still_pending(cmd);
}

static struct command_result *browse_autoconnect_failed(struct command *cmd,
							void *user UNUSED,
							const char *errmsg)
{
	return command_fail(cmd, LIGHTNINGD,
		"factory-browse-host: cannot reach peer (%s). "
		"Either pass an `address` parameter (e.g. 127.0.0.1:9735), or "
		"first run `lightning-cli connect <node_id>@<host>:<port>`.",
		errmsg);
}

static struct command_result *browse_preflight_ok(struct command *cmd,
						  const char *method,
						  const char *buf,
						  const jsmntok_t *result,
						  void *arg)
{
	struct browse_preflight_ctx *ctx = arg;

	const jsmntok_t *peers_tok = json_get_member(buf, result, "peers");
	if (!peers_tok || peers_tok->type != JSMN_ARRAY ||
	    peers_tok->size == 0) {
		return command_fail(cmd, LIGHTNINGD,
			"factory-browse-host: not connected to %s. "
			"Run `lightning-cli connect <node_id>@<host>:<port>` first.",
			ctx->node_id_str);
	}

	/* First (and only) peer in the array */
	const jsmntok_t *peer_tok = peers_tok + 1;
	const jsmntok_t *conn_tok = json_get_member(buf, peer_tok,
						   "connected");
	bool connected = false;
	if (!conn_tok || !json_to_bool(buf, conn_tok, &connected) ||
	    !connected) {
		return command_fail(cmd, LIGHTNINGD,
			"factory-browse-host: peer %s known but not currently "
			"connected. Run `lightning-cli connect "
			"<node_id>@<host>:<port>` to reconnect.",
			ctx->node_id_str);
	}

	int slot = ss_browse_alloc_slot();
	if (slot < 0) {
		ss_audit_log(LOG_UNUSUAL, "slot_exhausted",
			     "\"rpc\":\"factory-browse-host\","
			     "\"peer\":\"%s\",\"max\":%d",
			     ctx->node_id_str, SS_BROWSE_MAX_PENDING);
		return command_fail(cmd, SS_ERR_SLOT_EXHAUSTED,
			"factory-browse-host: too many pending requests "
			"(max %d). Try again later.",
			SS_BROWSE_MAX_PENDING);
	}

	uint64_t req_id = ss_fresh_request_id();
	ss_browse_pending[slot].request_id = req_id;
	ss_browse_pending[slot].cmd = cmd;
	ss_browse_pending[slot].deadline = time(NULL) + ss_browse_timeout_secs;

	uint8_t payload[12];
	uint8_t *p = payload;
	for (int i = 7; i >= 0; i--) *p++ = (uint8_t)(req_id >> (i*8));
	for (int i = 3; i >= 0; i--)
		*p++ = (uint8_t)(ctx->since_block >> (i*8));

	send_factory_msg_browse(cmd, ctx->node_id_str,
				SS_SUBMSG_FACTORY_INFO_REQUEST,
				payload, sizeof(payload));

	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-browse-host: sent FACTORY_INFO_REQUEST to %s "
		   "(req_id=%llu since_block=%u)",
		   ctx->node_id_str, (unsigned long long)req_id,
		   ctx->since_block);

	return command_still_pending(cmd);
}

static struct command_result *browse_preflight_err(struct command *cmd,
						   const char *method,
						   const char *buf,
						   const jsmntok_t *result,
						   void *arg)
{
	struct browse_preflight_ctx *ctx = arg;
	const jsmntok_t *msg_tok = json_get_member(buf, result, "message");
	const char *errmsg = msg_tok
		? json_strdup(cmd, buf, msg_tok)
		: "listpeers failed";
	return command_fail(cmd, LIGHTNINGD,
		"factory-browse-host: peer connectivity check failed for %s: %s",
		ctx->node_id_str, errmsg);
}


/* ============================================================================
 * B4 follow-up: factory-approve-proposal / factory-refuse-proposal RPCs.
 *
 * Today's behaviour: ADVISORY ACK ONLY.  The B1.5 validator auto-decides
 * every FACTORY_PROPOSE the moment it arrives — auto-sign on OK,
 * auto-drop on HARD_FAIL.  By the time the wallet UI calls these RPCs
 * the outcome is already on the wire.  These handlers verify a matching
 * pending_proposals slot exists and acknowledge the user's preference,
 * but they do not roll back a signature already sent or revive a
 * dropped proposal.
 *
 * Phase D scope: add a PENDING_USER_DECISION state to the validator so
 * the plugin waits for explicit approve/refuse before responding.  Then
 * these RPCs become load-bearing.
 * ========================================================================= */

static struct command_result *ss_lookup_proposal_for_action(
	struct command *cmd, const char *buf, const jsmntok_t *params,
	struct ss_pending_proposal_entry **out_slot)
{
	const char *iid_hex = NULL, *lsp_hex = NULL;
	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &iid_hex),
		   p_req("lsp_peer_id", param_string, &lsp_hex),
		   NULL))
		return command_param_failed();

	uint8_t iid[32];
	if (strlen(iid_hex) != 64 || !hex_decode(iid_hex, 64, iid, 32))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "instance_id must be 64 hex chars");
	uint8_t lsp_pk[33];
	if (strlen(lsp_hex) != 66 || !hex_decode(lsp_hex, 66, lsp_pk, 33))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "lsp_peer_id must be 66 hex chars");

	for (int i = 0; i < SS_POLICY_CACHE_SIZE; i++) {
		struct ss_pending_proposal_entry *e = &ss_pending_proposals[i];
		if (e->used
		    && memcmp(e->lsp_peer_id, lsp_pk, 33) == 0
		    && memcmp(e->instance_id, iid, 32) == 0) {
			*out_slot = e;
			return NULL;
		}
	}
	*out_slot = NULL;
	return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
			    "no pending proposal matches instance_id + lsp_peer_id");
}

static struct command_result *json_client_list_held_proposals(
	struct command *cmd, const char *buf UNUSED, const jsmntok_t *params)
{
	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_array_start(js, "held");

	for (int i = 0; i < SS_POLICY_CACHE_SIZE; i++) {
		struct ss_pending_proposal_entry *e = &ss_pending_proposals[i];
		if (!e->used) continue;
		if (!e->held_payload || e->held_payload_len == 0) continue;

		json_object_start(js, NULL);
		char iid_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(iid_hex + j*2, "%02x", e->instance_id[j]);
		iid_hex[64] = '\0';
		json_add_string(js, "instance_id", iid_hex);

		char lsp_hex[67];
		for (int j = 0; j < 33; j++)
			sprintf(lsp_hex + j*2, "%02x", e->lsp_peer_id[j]);
		lsp_hex[66] = '\0';
		json_add_string(js, "lsp_peer_id", lsp_hex);

		json_add_u64(js, "funding_sats", e->funding_sats);
		json_add_u32(js, "n_participants", e->n_participants);
		json_add_u32(js, "our_pidx", e->our_pidx);
		json_add_u32(js, "received_at_block", e->received_at_block);
		json_add_u32(js, "validator_result", (uint32_t)e->last_validate_result);
		json_object_end(js);
	}

	json_array_end(js);
	return command_finished(cmd, js);
}

/* Task #152: client-list-outgoing-joins -- surface ss_state.outgoing_joins
 * as JSON so the wallet can render the "My join attempts" view (every
 * factory-join-request we sent + its current status). Data lives plugin-
 * side already; this RPC just exposes the snapshot. No params. */
static struct command_result *json_client_list_outgoing_joins(
	struct command *cmd, const char *buf UNUSED, const jsmntok_t *params)
{
	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_array_start(js, "joins");

	for (size_t i = 0; i < ss_state.n_outgoing_joins; i++) {
		const outgoing_join_t *o = &ss_state.outgoing_joins[i];

		json_object_start(js, NULL);

		char iid_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(iid_hex + j*2, "%02x", o->instance_id[j]);
		iid_hex[64] = '\0';
		json_add_string(js, "instance_id", iid_hex);

		char lsp_hex[67];
		for (int j = 0; j < 33; j++)
			sprintf(lsp_hex + j*2, "%02x", o->lsp_node_id[j]);
		lsp_hex[66] = '\0';
		json_add_string(js, "lsp_node_id", lsp_hex);

		json_add_u64(js, "request_id", o->request_id);
		json_add_u64(js, "contribution_sats", o->contribution_sats);
		json_add_u32(js, "sent_at_block", o->sent_at_block);
		json_add_u32(js, "expected_signing_block", o->expected_signing_block);
		json_add_u32(js, "updated_at_block", o->updated_at_block);

		const char *status_name;
		switch (o->status) {
		case OUTGOING_JOIN_SENT:           status_name = "sent"; break;
		case OUTGOING_JOIN_QUEUED:         status_name = "queued"; break;
		case OUTGOING_JOIN_ACCEPTED:       status_name = "accepted"; break;
		case OUTGOING_JOIN_SIGNED:         status_name = "signed"; break;
		case OUTGOING_JOIN_REJECTED:       status_name = "rejected"; break;
		case OUTGOING_JOIN_CANCELLED:      status_name = "cancelled"; break;
		case OUTGOING_JOIN_TIMEOUT:        status_name = "timeout"; break;
		case OUTGOING_JOIN_ALREADY_MEMBER: status_name = "already_member"; break;
		default:                           status_name = "unknown"; break;
		}
		json_add_string(js, "status", status_name);
		json_add_u32(js, "status_code", (uint32_t)o->status);

		/* reason is a 64-byte C-string; emit only if populated. */
		if (o->reason[0] != 0) {
			/* Defensive: make sure it's NUL-terminated for the
			 * length of the field. */
			char reason_buf[65];
			memcpy(reason_buf, o->reason, 64);
			reason_buf[64] = '\0';
			json_add_string(js, "reason", reason_buf);
		}

		json_object_end(js);
	}

	json_array_end(js);
	return command_finished(cmd, js);
}

static struct command_result *json_client_list_recent_sign_queue_events(
	struct command *cmd, const char *buf UNUSED, const jsmntok_t *params)
{
	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_array_start(js, "events");
	for (int i = 0; i < SS_RECENT_SQ_EVENTS_SIZE; i++) {
		struct ss_recent_sq_event *e = &ss_recent_sq_events[i];
		if (!e->used) continue;
		json_object_start(js, NULL);
		char iid_hex[65];
		for (int j = 0; j < 32; j++) sprintf(iid_hex + j*2, "%02x", e->factory_instance_id[j]);
		iid_hex[64] = 0;
		json_add_string(js, "instance_id", iid_hex);
		char lsp_hex[67];
		for (int j = 0; j < 33; j++) sprintf(lsp_hex + j*2, "%02x", e->lsp_peer_id[j]);
		lsp_hex[66] = 0;
		json_add_string(js, "lsp_peer_id", lsp_hex);
		json_add_u32(js, "state", e->state);
		json_add_u32(js, "deadline_block", e->deadline_block);
		json_add_u32(js, "observed_at_block", e->observed_at_block);
		json_add_bool(js, "dismissed", e->dismissed);
		json_object_end(js);
	}
	json_array_end(js);
	return command_finished(cmd, js);
}

static struct command_result *json_client_dismiss_sign_queue_event(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *iid_hex = NULL;
	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &iid_hex),
		   NULL))
		return command_param_failed();

	uint8_t iid[32];
	if (strlen(iid_hex) != 64 || !hex_decode(iid_hex, 64, iid, 32))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "instance_id must be 64 hex chars");

	int dismissed = 0;
	for (int i = 0; i < SS_RECENT_SQ_EVENTS_SIZE; i++) {
		struct ss_recent_sq_event *e = &ss_recent_sq_events[i];
		if (!e->used) continue;
		if (memcmp(e->factory_instance_id, iid, 32) != 0) continue;
		if (e->dismissed) continue;
		e->dismissed = true;
		dismissed++;
	}

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_bool(js, "ok", true);
	json_add_u32(js, "dismissed_count", dismissed);
	return command_finished(cmd, js);
}

static struct command_result *json_factory_approve_proposal(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	struct ss_pending_proposal_entry *slot;
	struct command_result *err = ss_lookup_proposal_for_action(cmd, buf, params, &slot);
	if (err) return err;

	/* D.6: if the slot has a held payload (auto_sign_on_validator_pass=OFF
	 * caught this proposal earlier), release it by re-dispatching the
	 * FACTORY_PROPOSE through the same handler.  The gate checks
	 * user_approved and lets it through to nonce-generation this time. */
	if (slot->held_payload && slot->held_payload_len > 0) {
		char peer_hex[67];
		for (int j = 0; j < 33; j++)
			sprintf(peer_hex + j*2, "%02x", slot->lsp_peer_id[j]);
		peer_hex[66] = '\0';

		slot->user_approved = true;

		uint8_t *payload_copy = malloc(slot->held_payload_len);
		size_t payload_len = slot->held_payload_len;
		if (payload_copy) memcpy(payload_copy, slot->held_payload, payload_len);

		plugin_log(plugin_handle, LOG_INFORM,
			   "factory-approve-proposal: releasing held FACTORY_PROPOSE "
			   "for instance (%zu bytes) — re-dispatching",
			   payload_len);

		dispatch_superscalar_submsg(cmd, peer_hex,
			SS_SUBMSG_FACTORY_PROPOSE,
			payload_copy ? payload_copy : slot->held_payload,
			payload_len);

		if (payload_copy) free(payload_copy);

		struct json_stream *js = jsonrpc_stream_success(cmd);
		json_add_bool(js, "ok", true);
		json_add_string(js, "action", "released");
		json_add_string(js, "note",
			"Held FACTORY_PROPOSE re-dispatched. Plugin is now generating "
			"nonces and sending NONCE_BUNDLE.");
		return command_finished(cmd, js);
	}

	/* No held payload — the slot is either pre-D.6 advisory state, or
	 * auto-sign was ON when the proposal arrived (so it already signed). */
	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-approve-proposal: no held payload in slot — "
		   "either auto-sign was ON at proposal time (already signed) "
		   "or proposal already released. validator_result=%d",
		   slot->last_validate_result);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_bool(js, "ok", true);
	json_add_string(js, "action", "noop");
	json_add_string(js, "note",
		"No held proposal to release. Validator already auto-decided "
		"(auto_sign_on_validator_pass was ON when this proposal arrived) "
		"or the proposal was already approved/refused.");
	json_add_u32(js, "validator_result", (uint32_t)slot->last_validate_result);
	return command_finished(cmd, js);
}


/* Audit item #3 + #5 follow-up: send a CEREMONY_ABORT (0x014A) submsg to a
 * peer. Payload is [instance_id(32) || reason(1)]. Best-effort fire-and-forget
 * — if the peer is unreachable, the existing deadline machinery still cleans
 * up eventually.
 *
 * Used by:
 *   - json_factory_refuse_proposal (reason=USER_REFUSED) — client telling
 *     the LSP it refused a proposal
 *   - NONCE_BUNDLE / PSIG_BUNDLE stale-msg guard (reason=OTHER) — LSP
 *     telling a peer to stop retrying after restart drops the session
 */
static void ss_send_factory_abort(struct command *cmd,
				  const char *peer_id_hex,
				  const uint8_t instance_id[32],
				  uint8_t reason)
{
	uint8_t payload[33];
	memcpy(payload, instance_id, 32);
	payload[32] = reason;

	plugin_log(plugin_handle, LOG_INFORM,
		   "CEREMONY_ABORT -> %s reason=%u",
		   peer_id_hex, (unsigned)reason);

	send_factory_msg(cmd, peer_id_hex, SS_SUBMSG_CEREMONY_ABORT,
			 payload, sizeof(payload));
}

/* ============================================================================
 * Task #149: ss_terminalize_failed - move a factory to the FAILED terminal
 * state and notify peers so client and LSP views converge.
 *
 * Use this in place of bare `fi->ceremony = CEREMONY_FAILED` assignments
 * at ceremony-failure sites (withdraw error, malformed peer message,
 * internal invariant violation, etc.). It:
 *
 *   1. Sets fi->ceremony = CEREMONY_FAILED.
 *   2. Sets fi->lifecycle = FACTORY_LIFECYCLE_FAILED, so the wallet's
 *      bucket UI puts the factory in "Failed / abandoned" instead of
 *      leaving it lingering as a "live" init forever.
 *   3. Broadcasts CEREMONY_ABORT to known participants - LSP fans out
 *      to every client; client tells the LSP - so the counterparty stops
 *      waiting on a ceremony we have given up on (this fixes the d607
 *      "phantom proposed on the client side" divergence).
 *   4. Stamps aborted_at_block (reused for failure timestamps) and
 *      persists.
 *
 * No-op if the factory is already in any closed/terminal lifecycle, so
 * repeated calls from re-entrant error paths are safe.
 * ============================================================================ */
static void ss_terminalize_failed(struct command *cmd,
				  factory_instance_t *fi,
				  uint8_t abort_reason)
{
	if (!fi) return;
	if (factory_is_closed(fi->lifecycle)) {
		/* Already terminal; do not re-broadcast or rewrite state. */
		return;
	}

	factory_lifecycle_t prior_lc = fi->lifecycle;
	ceremony_state_t   prior_cer = fi->ceremony;

	fi->ceremony = CEREMONY_FAILED;
	fi->lifecycle = FACTORY_LIFECYCLE_FAILED;
	if (!fi->aborted_at_block)
		fi->aborted_at_block = ss_state.current_blockheight;

	/* Broadcast CEREMONY_ABORT so the counterparty stops tracking this
	 * factory. LSP side: tell every client. Client side: tell the LSP. */
	size_t n_notified = 0;
	char peer_hex[67];
	if (fi->is_lsp) {
		for (size_t ci = 0; ci < fi->n_clients; ci++) {
			for (int j = 0; j < 33; j++)
				sprintf(peer_hex + j*2, "%02x",
					fi->clients[ci].node_id[j]);
			peer_hex[66] = '\0';
			ss_send_factory_abort(cmd, peer_hex,
					      fi->instance_id, abort_reason);
			n_notified++;
		}
	} else {
		for (int j = 0; j < 33; j++)
			sprintf(peer_hex + j*2, "%02x",
				fi->lsp_node_id[j]);
		peer_hex[66] = '\0';
		ss_send_factory_abort(cmd, peer_hex,
				      fi->instance_id, abort_reason);
		n_notified = 1;
	}

	plugin_log(plugin_handle, LOG_UNUSUAL,
		   "Terminalized factory %02x%02x%02x%02x: lifecycle %d -> FAILED, "
		   "ceremony %d -> FAILED, abort_reason=%u, notified %zu peer(s)",
		   fi->instance_id[0], fi->instance_id[1],
		   fi->instance_id[2], fi->instance_id[3],
		   (int)prior_lc, (int)prior_cer,
		   (unsigned)abort_reason, n_notified);

	ss_save_factory(cmd, fi);
}

/* ============================================================================
 * Audit #5 follow-up: stale-msg guard for NONCE_BUNDLE / PSIG_BUNDLE.
 *
 * After a plugin restart, the in-memory MuSig2 session_t is gone but the
 * persisted factory_instance_t reloads with lifecycle/ceremony past
 * CEREMONY_RUNNING. Stale NONCE_BUNDLEs from reconnecting clients then
 * hit factory_sessions_finalize against a fresh-but-empty session, which
 * fails noisily on every retry.
 *
 * This helper checks whether the factory is in a state where the given
 * message is expected. If not, we send CEREMONY_ABORT(OTHER) so the
 * sender stops retrying, and return false so the caller skips the
 * broken path.
 *
 * Long-term fix is lib task #80 (serialize MuSig2 sessions). Until then
 * this turns a noisy infinite-retry loop into a single ABORT exchange.
 * ============================================================================ */
static bool ss_ceremony_expecting_nonces(const factory_instance_t *fi)
{
	if (!fi) return false;
	/* PROPOSED: LSP collecting initial nonces.
	 * NONCES_COLLECTED: ceremony has all nonces but is still in the
	 *   finalize/rebuild-tree window; late retransmits arriving here
	 *   from a slow client are harmless duplicates, not stale.
	 * ROTATING: rotation-round nonce collection. */
	return fi->ceremony == CEREMONY_PROPOSED
	    || fi->ceremony == CEREMONY_NONCES_COLLECTED
	    || fi->ceremony == CEREMONY_ROTATING;
}

static bool ss_ceremony_expecting_psigs(const factory_instance_t *fi)
{
	if (!fi) return false;
	/* NONCES_COLLECTED: ceremony is producing psigs for the new tree.
	 * PSIGS_COLLECTED: all psigs collected but still finalizing the
	 *   distribution TX; late retransmits here are harmless dups.
	 * ROTATING: rotation-round psig collection. */
	return fi->ceremony == CEREMONY_NONCES_COLLECTED
	    || fi->ceremony == CEREMONY_PSIGS_COLLECTED
	    || fi->ceremony == CEREMONY_ROTATING;
}


static struct command_result *json_factory_refuse_proposal(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	struct ss_pending_proposal_entry *slot;
	struct command_result *err = ss_lookup_proposal_for_action(cmd, buf, params, &slot);
	if (err) return err;

	bool was_held = (slot->held_payload != NULL);

	/* D.6: drop any held payload and mark the slot REFUSED. */
	if (slot->held_payload) {
		free(slot->held_payload);
		slot->held_payload = NULL;
		slot->held_payload_len = 0;
	}
	slot->user_refused = true;
	slot->user_approved = false;

	/* Audit item #3: send the explicit ABORT so the LSP doesn't have to wait
	 * for the deadline. Reason code is USER_REFUSED. */
	{
		char lsp_hex[67];
		for (int i = 0; i < 33; i++)
			sprintf(lsp_hex + i*2, "%02x", slot->lsp_peer_id[i]);
		lsp_hex[66] = '\0';
		ss_send_factory_abort(cmd, lsp_hex, slot->instance_id,
				      SS_CEREMONY_ABORT_USER_REFUSED);
	}

	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-refuse-proposal: %s. Sent CEREMONY_ABORT (USER_REFUSED) "
		   "to LSP.",
		   was_held ? "released held proposal + marked REFUSED"
			    : "marked REFUSED (no held payload)");

	/* Bug A fix: also drop the in-memory factory_instance_t for the refused
	 * iid so it doesn\'t persist as a stale init/proposed ghost in
	 * factory-list. Without this, the slot is marked refused but the
	 * factory_instance_t lives forever, accumulating every reconnect
	 * (the LSP-side handle_connect retry sees CEREMONY_PROPOSED and
	 * re-sends FACTORY_PROPOSE, which creates fresh duplicates here).
	 *
	 * We only refuse client-side proposals (LSP never sees its own
	 * factory through this path), so fi->is_lsp will be false. fi may
	 * not have a lib_factory yet (refuse can happen pre-ceremony) —
	 * the free pattern below is null-safe. */
	{
		factory_instance_t *fi_refused = NULL;
		size_t fi_slot = SIZE_MAX;
		for (size_t i = 0; i < ss_state.n_factories; i++) {
			if (memcmp(ss_state.factories[i]->instance_id,
				   slot->instance_id, 32) == 0) {
				fi_refused = ss_state.factories[i];
				fi_slot = i;
				break;
			}
		}
		if (fi_refused && fi_slot != SIZE_MAX) {
			for (size_t i = fi_slot + 1; i < ss_state.n_factories; i++)
				ss_state.factories[i - 1] = ss_state.factories[i];
			ss_state.n_factories--;
			ss_state.factories[ss_state.n_factories] = NULL;
			if (fi_refused->breach_data) free(fi_refused->breach_data);
			if (fi_refused->dist_signed_tx) free(fi_refused->dist_signed_tx);
			if (fi_refused->keyagg_snapshots) free(fi_refused->keyagg_snapshots);
			free(fi_refused);
			plugin_log(plugin_handle, LOG_DBG,
				   "factory-refuse-proposal: dropped in-memory "
				   "factory_instance_t (n_factories now %u)",
				   (unsigned)ss_state.n_factories);
		}
	}

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_bool(js, "ok", true);
	json_add_string(js, "action", was_held ? "released_and_refused" : "marked_refused");
	json_add_string(js, "note", was_held
		? "Held proposal dropped. CEREMONY_ABORT (USER_REFUSED) sent to LSP."
		: "Slot marked REFUSED. CEREMONY_ABORT (USER_REFUSED) sent to LSP (no held payload).");
	json_add_u32(js, "validator_result", (uint32_t)slot->last_validate_result);
	return command_finished(cmd, js);
}


/* B2: factory-review-proposal RPC — read-only view of the most recent
 * FACTORY_PROPOSE we received for a given (lsp_peer_id, instance_id).
 *
 * Used by the wallet UI to render a pre-sign confirmation modal: shows
 * the proposal (allocations, funding) plus the LSP's advertised policy
 * plus the validator outcome, so the user sees what they would be
 * signing AND whether it passes their prefs.
 *
 * Params:
 *   instance_id (required, 64-hex)
 *   lsp_peer_id (optional, 66-hex) — if omitted, scan all entries
 *
 * Returns 404-ish error if no proposal cached for that (lsp, instance);
 * else JSON with proposed/advertised_policy/user_prefs/validation. */
static struct command_result *json_factory_review_proposal(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *iid_hex = NULL;
	const char *lsp_hex = NULL;
	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &iid_hex),
		   p_opt("lsp_peer_id", param_string, &lsp_hex),
		   NULL))
		return command_param_failed();

	if (strlen(iid_hex) != 64)
		return command_fail(cmd, LIGHTNINGD,
			"instance_id must be 64 hex chars");

	uint8_t iid[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(iid_hex + j*2, "%2x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
				"instance_id is not valid hex");
		iid[j] = (uint8_t)b;
	}

	const struct ss_pending_proposal_entry *pp = NULL;
	uint8_t lsp_pk_arg[33];
	if (lsp_hex && strlen(lsp_hex) == 66
	    && ss_peer_id_hex_to_bytes(lsp_hex, lsp_pk_arg)) {
		pp = ss_pending_proposals_get(lsp_pk_arg, iid);
	} else {
		/* Scan for the first match against any LSP. */
		for (int i = 0; i < SS_POLICY_CACHE_SIZE; i++) {
			const struct ss_pending_proposal_entry *e =
				&ss_pending_proposals[i];
			if (e->used && memcmp(e->instance_id, iid, 32) == 0) {
				pp = e;
				break;
			}
		}
	}

	if (!pp)
		return command_fail(cmd, LIGHTNINGD,
			"no FACTORY_PROPOSE cached for instance_id %s%s%s",
			iid_hex,
			lsp_hex ? " from lsp_peer_id " : "",
			lsp_hex ? lsp_hex : "");

	/* Look up advertised policy for the same key, if cached. */
	const ss_factory_policy_t *adv = ss_policy_cache_get(
		pp->lsp_peer_id, iid);

	/* User prefs from persisted client-signing-prefs (task #115). */
	ss_signing_prefs_load_or_default();
	const ss_client_signing_prefs_t *prefs_ref = &g_signing_prefs;

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", iid_hex);
	char lsp_hex_out[67];
	for (int j = 0; j < 33; j++)
		sprintf(lsp_hex_out + j*2, "%02x", pp->lsp_peer_id[j]);
	lsp_hex_out[66] = '\0';
	json_add_string(js, "lsp_peer_id", lsp_hex_out);
	json_add_u32(js, "received_at_block", pp->received_at_block);

	/* Proposed parameters from the wire (what we'd sign if accepted). */
	json_object_start(js, "proposed");
	json_add_u64(js, "funding_sats", pp->funding_sats);
	json_add_u32(js, "n_participants", pp->n_participants);
	json_add_u32(js, "our_pidx", pp->our_pidx);
	if (pp->our_pidx < pp->n_allocs)
		json_add_u64(js, "our_allocation_sats",
			pp->allocs[pp->our_pidx]);
	json_array_start(js, "all_allocations");
	for (uint8_t i = 0; i < pp->n_allocs; i++)
		json_add_u64(js, NULL, pp->allocs[i]);
	json_array_end(js);
	/* Derived: our allocation as a percentage of total funding. */
	if (pp->funding_sats > 0
	    && pp->our_pidx < pp->n_allocs) {
		uint64_t our_alloc = pp->allocs[pp->our_pidx];
		uint64_t pct_x100 = (our_alloc * 10000) / pp->funding_sats;
		json_add_u64(js, "our_allocation_pct_x100", pct_x100);
	}
	json_object_end(js);

	/* The LSP's advertised policy at browse time, if any. */
	if (adv) {
		json_object_start(js, "advertised_policy");
		json_add_u32(js, "schema_version", adv->schema_version);
		json_add_u32(js, "arity_mode", (uint32_t)adv->arity_mode);
		json_add_u32(js, "leaf_arity", (uint32_t)adv->leaf_arity);
		json_add_u32(js, "lifetime_blocks", adv->lifetime_blocks);
		json_add_u32(js, "dying_period_blocks", adv->dying_period_blocks);
		json_add_u64(js, "per_client_capacity_sat",
			adv->per_client_capacity_sat);
		json_add_u64(js, "lsp_fee_sat", adv->lsp_fee_sat);
		json_add_u32(js, "lsp_fee_ppm", adv->lsp_fee_ppm);
		json_add_u64(js, "htlc_min_sat", adv->htlc_min_sat);
		json_add_u64(js, "htlc_max_sat", adv->htlc_max_sat);
		json_add_u64(js, "min_capacity_per_join_sat",
			adv->min_capacity_per_join_sat);
		json_add_u64(js, "max_capacity_per_join_sat",
			adv->max_capacity_per_join_sat);
		json_add_u32(js, "proof_tier_required",
			(uint32_t)adv->proof_tier_required);
		json_add_u32(js, "rotation_interval_blocks",
			adv->rotation_interval_blocks);
		json_add_bool(js, "allow_tier_b_rollover",
			adv->allow_tier_b_rollover);
		json_add_u32(js, "state_replay_defense_window_blocks",
			adv->state_replay_defense_window_blocks);
		json_object_end(js);
	} else {
		json_add_bool(js, "advertised_policy_known", false);
	}

	/* User's current signing prefs (the thresholds the validator uses). */
	json_object_start(js, "user_prefs");
	json_add_u64(js, "max_htlc_min_sat", prefs_ref->max_htlc_min_sat);
	json_add_u64(js, "min_htlc_max_sat", prefs_ref->min_htlc_max_sat);
	json_add_u32(js, "min_max_concurrent_htlcs",
		(uint32_t)prefs_ref->min_max_concurrent_htlcs);
	json_add_u64(js, "min_max_in_flight_msat", prefs_ref->min_max_in_flight_msat);
	json_add_u32(js, "max_min_final_cltv_delta", prefs_ref->max_min_final_cltv_delta);
	json_add_u32(js, "max_cltv_delta_forward", prefs_ref->max_cltv_delta_forward);
	json_add_u64(js, "max_min_capacity_per_join_sat",
		prefs_ref->max_min_capacity_per_join_sat);
	json_add_u64(js, "min_max_capacity_per_join_sat",
		prefs_ref->min_max_capacity_per_join_sat);
	json_add_u32(js, "min_rotation_interval_blocks",
		prefs_ref->min_rotation_interval_blocks);
	json_add_u32(js, "min_state_replay_defense_window_blocks",
		prefs_ref->min_state_replay_defense_window_blocks);
	json_object_end(js);

	/* Validator outcome from the most recent FACTORY_PROPOSE. */
	json_object_start(js, "validation");
	const char *result_name;
	switch (pp->last_validate_result) {
	case SS_POLICY_VALIDATE_OK:        result_name = "ok"; break;
	case SS_POLICY_VALIDATE_HARD_FAIL: result_name = "hard_fail"; break;
	case SS_POLICY_VALIDATE_SOFT_FAIL: result_name = "soft_fail"; break;
	default:                            result_name = "unknown"; break;
	}
	json_add_string(js, "result", result_name);
	json_add_u32(js, "field_tlv", (uint32_t)pp->last_validate_field_tlv);
	json_add_string(js, "reason",
		pp->last_validate_reason[0] ? pp->last_validate_reason : "");
	json_object_end(js);

	return command_finished(cmd, js);
}

static struct command_result *json_factory_browse_host(struct command *cmd,
						       const char *buf,
						       const jsmntok_t *params)
{
	const char *node_id_str = NULL;
	const char *address_str = NULL;
	uint32_t *since_block_opt = NULL;

	if (!param(cmd, buf, params,
		   p_req("node_id", param_string, &node_id_str),
		   p_opt("since_block", param_u32, &since_block_opt),
		   p_opt("address", param_string, &address_str),
		   NULL))
		return command_param_failed();

	/* Task #118: route through ss_ensure_peer_connected — auto-connect
	 * if not currently peered AND caller supplied an address hint. */
	struct browse_preflight_ctx *ctx =
		tal(cmd, struct browse_preflight_ctx);
	ctx->node_id_str = tal_strdup(ctx, node_id_str);
	ctx->since_block = since_block_opt ? *since_block_opt : 0;
	ctx->address = address_str ? tal_strdup(ctx, address_str) : NULL;

	return ss_ensure_peer_connected(cmd, ctx->node_id_str, ctx->address, ctx,
		browse_send_now,
		browse_autoconnect_failed);
}

/* ============================================================================
 * Phase 3: factory-join-request / factory-cancel-join /
 *          factory-incoming-joins / factory-kick-joiner RPCs
 *
 * factory-join-request: client RPC. Sends JOIN_REQUEST (0x0142) to a
 *   specific LSP for a specific factory. Returns command_still_pending
 *   while waiting for the LSPs JOIN_RESPONSE (0x0143).
 *
 * factory-cancel-join: client RPC. Marks a local outgoing_join entry as
 *   CANCELLED and sends a fire-and-forget JOIN_CANCEL (0x0144) to the LSP
 *   for visibility. Synchronous return.
 *
 * factory-incoming-joins: LSP RPC. Returns the join_queue for one or all
 *   factories the LSP is hosting. Read-only, synchronous.
 *
 * factory-kick-joiner: LSP RPC. Marks a queue entry as REJECTED with an
 *   optional reason and sends unsolicited JOIN_RESPONSE so the kicked
 *   client's wallet can update.
 *
 * TODO(privacy): all four RPCs write/read persistent join records; the
 * pre-mainnet privacy pass needs to review each.
 * ============================================================================ */

/* Helper: decode a 66-char hex node_id string into a 33-byte pubkey.
 * Returns true on success, false on bad input. */
static bool ss_decode_node_id_hex(const char *hex, uint8_t out[33])
{
	if (!hex || strlen(hex) != 66) return false;
	for (int k = 0; k < 33; k++) {
		unsigned int by;
		if (sscanf(hex + k*2, "%2x", &by) != 1) return false;
		out[k] = (uint8_t)by;
	}
	return true;
}

/* Helper: decode a 64-char hex instance_id string into a 32-byte buffer. */
static bool ss_decode_instance_id_hex(const char *hex, uint8_t out[32])
{
	if (!hex || strlen(hex) != 64) return false;
	for (int k = 0; k < 32; k++) {
		unsigned int by;
		if (sscanf(hex + k*2, "%2x", &by) != 1) return false;
		out[k] = (uint8_t)by;
	}
	return true;
}

/* Helper: status enum to lowercase string for JSON output. */
static const char *ss_outgoing_join_status_name(outgoing_join_status_t s)
{
	switch (s) {
	case OUTGOING_JOIN_SENT:           return "sent";
	case OUTGOING_JOIN_QUEUED:         return "queued";
	case OUTGOING_JOIN_ACCEPTED:       return "accepted";
	case OUTGOING_JOIN_SIGNED:         return "signed";
	case OUTGOING_JOIN_REJECTED:       return "rejected";
	case OUTGOING_JOIN_CANCELLED:      return "cancelled";
	case OUTGOING_JOIN_TIMEOUT:        return "timeout";
	case OUTGOING_JOIN_ALREADY_MEMBER: return "already_member";
	}
	return "unknown";
}

static const char *ss_factory_join_status_name(factory_join_status_t s)
{
	switch (s) {
	case JOIN_STATUS_QUEUED:         return "queued";
	case JOIN_STATUS_ACCEPTED:       return "accepted";
	case JOIN_STATUS_SIGNED:         return "signed";
	case JOIN_STATUS_REJECTED:       return "rejected";
	case JOIN_STATUS_CANCELLED:      return "cancelled";
	case JOIN_STATUS_ALREADY_MEMBER: return "already_member";
	}
	return "unknown";
}

/* ----- factory-join-request ----------------------------------------------- */

/* Context carried across the listpeers preflight callback for join. */
struct join_preflight_ctx {
	const char *lsp_node_id_str;
	uint8_t  instance_id[32];
	uint64_t contribution_sats;
};

static struct command_result *join_preflight_ok(struct command *cmd,
						const char *method,
						const char *buf,
						const jsmntok_t *result,
						void *arg)
{
	plugin_log(plugin_handle, LOG_INFORM,
		   "DEBUG: join_preflight_ok entered");
	struct join_preflight_ctx *ctx = arg;
	plugin_log(plugin_handle, LOG_INFORM,
		   "DEBUG: ctx unpacked, lsp=%s", ctx->lsp_node_id_str);

	const jsmntok_t *peers_tok = json_get_member(buf, result, "peers");
	if (!peers_tok || peers_tok->type != JSMN_ARRAY ||
	    peers_tok->size == 0) {
		return command_fail(cmd, LIGHTNINGD,
			"factory-join-request: not connected to %s. "
			"Run `lightning-cli connect <node_id>@<host>:<port>` first.",
			ctx->lsp_node_id_str);
	}
	const jsmntok_t *peer_tok = peers_tok + 1;
	const jsmntok_t *conn_tok = json_get_member(buf, peer_tok,
						   "connected");
	bool connected = false;
	if (!conn_tok || !json_to_bool(buf, conn_tok, &connected) ||
	    !connected) {
		return command_fail(cmd, LIGHTNINGD,
			"factory-join-request: peer %s known but not "
			"currently connected. Run `lightning-cli connect "
			"<node_id>@<host>:<port>` to reconnect.",
			ctx->lsp_node_id_str);
	}

	/* Check we don't already have an outstanding join for this
	 * (lsp, instance_id). Dedup safety net at the local layer. */
	uint8_t lsp_pk[33];
	if (!ss_decode_node_id_hex(ctx->lsp_node_id_str, lsp_pk)) {
		return command_fail(cmd, LIGHTNINGD,
			"factory-join-request: invalid lsp node_id");
	}
	for (size_t i = 0; i < ss_state.n_outgoing_joins; i++) {
		outgoing_join_t *o = &ss_state.outgoing_joins[i];
		if (memcmp(o->lsp_node_id, lsp_pk, 33) == 0 &&
		    memcmp(o->instance_id, ctx->instance_id, 32) == 0 &&
		    (o->status == OUTGOING_JOIN_SENT ||
		     o->status == OUTGOING_JOIN_QUEUED ||
		     o->status == OUTGOING_JOIN_ACCEPTED ||
		     o->status == OUTGOING_JOIN_SIGNED)) {
			return command_fail(cmd, SS_ERR_DUPLICATE_JOIN,
				"factory-join-request: already have an active "
				"join for this factory (status=%s, "
				"request_id=%llu). Cancel it first with "
				"factory-cancel-join.",
				ss_outgoing_join_status_name(o->status),
				(unsigned long long)o->request_id);
		}
	}

	/* Check we have room in outgoing_joins */
	if (ss_state.n_outgoing_joins >= MAX_OUTGOING_JOINS) {
		return command_fail(cmd, SS_ERR_OUTGOING_JOINS_FULL,
			"factory-join-request: outgoing joins full "
			"(max %d). Cancel or wait for existing ones.",
			MAX_OUTGOING_JOINS);
	}

	/* Allocate slot for response correlation */
	int slot = ss_join_alloc_slot();
	if (slot < 0) {
		ss_audit_log(LOG_UNUSUAL, "slot_exhausted",
			     "\"rpc\":\"factory-join-request\","
			     "\"max\":%d", SS_JOIN_MAX_PENDING);
		return command_fail(cmd, SS_ERR_SLOT_EXHAUSTED,
			"factory-join-request: too many pending requests "
			"(max %d). Try again later.", SS_JOIN_MAX_PENDING);
	}
	uint64_t req_id = ss_fresh_request_id();
	ss_join_pending[slot].request_id = req_id;
	ss_join_pending[slot].cmd = cmd;
	ss_join_pending[slot].deadline = time(NULL) + ss_join_timeout_secs;

	/* Add persistent outgoing_join_t entry */
	/* TODO(privacy): retention review pre-mainnet */
	outgoing_join_t *o = &ss_state.outgoing_joins[ss_state.n_outgoing_joins++];
	memcpy(o->lsp_node_id, lsp_pk, 33);
	memcpy(o->instance_id, ctx->instance_id, 32);
	o->request_id = req_id;
	o->contribution_sats = ctx->contribution_sats;
	o->sent_at_block = ss_state.current_blockheight;
	o->expected_signing_block = 0;
	o->updated_at_block = ss_state.current_blockheight;
	o->status = OUTGOING_JOIN_SENT;
	memset(o->reason, 0, 64);
	plugin_log(plugin_handle, LOG_INFORM,
		   "DEBUG: about to save outgoing joins n=%zu",
		   ss_state.n_outgoing_joins);
	/* Task #62: ss_save_outgoing_joins disabled — see json_factory_join_request comment */
	plugin_log(plugin_handle, LOG_INFORM,
		   "DEBUG: saved outgoing joins, about to send wire");

	/* Build wire payload: req_id(8) + instance_id(32) + contribution(8) + tlv_len(2) = 50 */
	uint8_t payload[50];
	uint8_t *p = payload;
	for (int i = 7; i >= 0; i--) *p++ = (uint8_t)(req_id >> (i*8));
	memcpy(p, ctx->instance_id, 32); p += 32;
	for (int i = 7; i >= 0; i--)
		*p++ = (uint8_t)(ctx->contribution_sats >> (i*8));
	*p++ = 0; *p++ = 0;  /* trailing_tlv_len = 0 */

	send_factory_msg_join(cmd, ctx->lsp_node_id_str,
			      SS_SUBMSG_JOIN_REQUEST, payload, sizeof(payload));

	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-join-request: sent JOIN_REQUEST to %s "
		   "(req_id=%llu, contribution=%llu sats)",
		   ctx->lsp_node_id_str, (unsigned long long)req_id,
		   (unsigned long long)ctx->contribution_sats);

	return command_still_pending(cmd);
}

static struct command_result *join_preflight_err(struct command *cmd,
						 const char *method,
						 const char *buf,
						 const jsmntok_t *result,
						 void *arg)
{
	plugin_log(plugin_handle, LOG_INFORM,
		   "DEBUG: join_preflight_err entered");
	struct join_preflight_ctx *ctx = arg;
	const jsmntok_t *msg_tok = json_get_member(buf, result, "message");
	const char *errmsg = msg_tok
		? json_strdup(cmd, buf, msg_tok)
		: "listpeers failed";
	return command_fail(cmd, LIGHTNINGD,
		"factory-join-request: peer connectivity check failed "
		"for %s: %s", ctx->lsp_node_id_str, errmsg);
}

/* Task #118: join_request stash struct for auto-connect detour. */
struct ss_join_ctx {
	char *lsp_node_id_str;
	char *instance_id_str;
	char *address;
	uint64_t contribution_sats;
};

static struct command_result *join_send_now(struct command *cmd, void *user);
static struct command_result *join_autoconnect_failed(struct command *cmd,
						      void *user,
						      const char *errmsg);

static struct command_result *json_factory_join_request(struct command *cmd,
							const char *buf,
							const jsmntok_t *params)
{
	const char *lsp_node_id_str = NULL;
	const char *instance_id_str = NULL;
	const char *address_str = NULL;
	uint64_t *contribution_sats = NULL;

	if (!param(cmd, buf, params,
		   p_req("lsp_node_id", param_string, &lsp_node_id_str),
		   p_req("instance_id", param_string, &instance_id_str),
		   p_req("contribution_sats", param_u64, &contribution_sats),
		   p_opt("address", param_string, &address_str),
		   NULL))
		return command_param_failed();

	/* Stash for auto-connect detour. */
	struct ss_join_ctx *ctx = tal(cmd, struct ss_join_ctx);
	ctx->lsp_node_id_str = tal_strdup(ctx, lsp_node_id_str);
	ctx->instance_id_str = tal_strdup(ctx, instance_id_str);
	ctx->contribution_sats = *contribution_sats;
	ctx->address = address_str ? tal_strdup(ctx, address_str) : NULL;

	return ss_ensure_peer_connected(cmd, ctx->lsp_node_id_str, ctx->address,
		ctx, join_send_now, join_autoconnect_failed);
}

/* Task #118: the original json_factory_join_request body, lifted to a
 * post-auto-connect callback.  Re-derives uint8 buffers inside. */
static struct command_result *join_send_now(struct command *cmd, void *user)
{
	struct ss_join_ctx *ctx = user;
	const char *lsp_node_id_str = ctx->lsp_node_id_str;
	const char *instance_id_str = ctx->instance_id_str;
	uint64_t contribution_sats_val = ctx->contribution_sats;
	uint64_t *contribution_sats = &contribution_sats_val;


	uint8_t lsp_pk[33], iid[32];
	if (!ss_decode_node_id_hex(lsp_node_id_str, lsp_pk))
		return command_fail(cmd, LIGHTNINGD, "lsp_node_id must be 66-char hex");
	if (!ss_decode_instance_id_hex(instance_id_str, iid))
		return command_fail(cmd, LIGHTNINGD, "instance_id must be 64-char hex");

	if (ss_state.n_outgoing_joins >= MAX_OUTGOING_JOINS)
		return command_fail(cmd, SS_ERR_OUTGOING_JOINS_FULL, "outgoing joins full");

	/* Hardening Task #67: per-peer slot cap + rate limit */
	const char *limit_err = ss_peer_check_limits(lsp_pk);
	if (limit_err) {
		ss_peer_record_fail(lsp_pk);
		ss_audit_log(LOG_UNUSUAL, "peer_limit_reject",
			     "\"rpc\":\"factory-join-request\","
			     "\"reason\":\"%s\"", limit_err);
		return command_fail(cmd, SS_ERR_PEER_RATE_LIMIT,
			"factory-join-request: %s", limit_err);
	}

	int slot = ss_join_alloc_slot();
	if (slot < 0)
		return command_fail(cmd, SS_ERR_SLOT_EXHAUSTED, "too many pending requests");

	uint64_t req_id = ss_fresh_request_id();
	ss_join_pending[slot].request_id = req_id;
	ss_join_pending[slot].cmd = cmd;
	ss_join_pending[slot].deadline = time(NULL) + ss_join_timeout_secs;
	memcpy(ss_join_pending[slot].peer_id, lsp_pk, 33);
	ss_peer_usage_commit_slot(lsp_pk);

	outgoing_join_t *o = &ss_state.outgoing_joins[ss_state.n_outgoing_joins++];
	memcpy(o->lsp_node_id, lsp_pk, 33);
	memcpy(o->instance_id, iid, 32);
	o->request_id = req_id;
	o->contribution_sats = *contribution_sats;
	o->sent_at_block = ss_state.current_blockheight;
	o->expected_signing_block = 0;
	o->updated_at_block = ss_state.current_blockheight;
	o->status = OUTGOING_JOIN_SENT;
	memset(o->reason, 0, 64);
	ss_save_outgoing_joins(cmd);

	uint8_t payload[50];
	uint8_t *p = payload;
	for (int i = 7; i >= 0; i--) *p++ = (uint8_t)(req_id >> (i*8));
	memcpy(p, iid, 32); p += 32;
	for (int i = 7; i >= 0; i--)
		*p++ = (uint8_t)(*contribution_sats >> (i*8));
	*p++ = 0; *p++ = 0;

	send_factory_msg_join(cmd, lsp_node_id_str,
			      SS_SUBMSG_JOIN_REQUEST, payload, sizeof(payload));
	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-join-request: sent JOIN_REQUEST to %s (req_id=%llu)",
		   lsp_node_id_str, (unsigned long long)req_id);

	return command_still_pending(cmd);
}

static struct command_result *join_autoconnect_failed(struct command *cmd,
						      void *user UNUSED,
						      const char *errmsg)
{
	return command_fail(cmd, LIGHTNINGD,
		"factory-join-request: cannot reach LSP (%s). "
		"Either pass an `address` parameter (e.g. 127.0.0.1:9735), or "
		"first run `lightning-cli connect <node_id>@<host>:<port>`.",
		errmsg);
}


/* ----- factory-cancel-join ------------------------------------------------ */

static struct command_result *json_factory_cancel_join(struct command *cmd,
						       const char *buf,
						       const jsmntok_t *params)
{
	uint64_t *request_id = NULL;

	if (!param(cmd, buf, params,
		   p_req("request_id", param_u64, &request_id),
		   NULL))
		return command_param_failed();

	outgoing_join_t *o = NULL;
	size_t found_idx = 0;
	for (size_t i = 0; i < ss_state.n_outgoing_joins; i++) {
		if (ss_state.outgoing_joins[i].request_id == *request_id) {
			o = &ss_state.outgoing_joins[i];
			found_idx = i;
			break;
		}
	}
	if (!o)
		return command_fail(cmd, LIGHTNINGD,
			"factory-cancel-join: no outgoing join with "
			"request_id=%llu",
			(unsigned long long)*request_id);
	(void)found_idx;

	if (o->status == OUTGOING_JOIN_CANCELLED ||
	    o->status == OUTGOING_JOIN_REJECTED ||
	    o->status == OUTGOING_JOIN_SIGNED) {
		return command_fail(cmd, LIGHTNINGD,
			"factory-cancel-join: join request_id=%llu is "
			"already in status=%s, cannot cancel.",
			(unsigned long long)*request_id,
			ss_outgoing_join_status_name(o->status));
	}

	/* Build wire payload: req_id(8) + instance_id(32) + tlv_len(2) = 42 */
	uint8_t payload[42];
	uint8_t *p = payload;
	for (int i = 7; i >= 0; i--) *p++ = (uint8_t)(*request_id >> (i*8));
	memcpy(p, o->instance_id, 32); p += 32;
	*p++ = 0; *p++ = 0;

	/* Hex-encode lsp_node_id for the send call */
	char lsp_hex[67];
	for (int k = 0; k < 33; k++)
		sprintf(lsp_hex + k*2, "%02x", o->lsp_node_id[k]);
	lsp_hex[66] = 0;

	/* Fire-and-forget: use generic send_factory_msg (any error just gets
	 * logged by rpc_err; we mark cancelled locally regardless). */
	send_factory_msg(cmd, lsp_hex, SS_SUBMSG_JOIN_CANCEL,
			 payload, sizeof(payload));

	/* Update local state */
	o->status = OUTGOING_JOIN_CANCELLED;
	o->updated_at_block = ss_state.current_blockheight;
	strncpy((char *)o->reason, "user cancelled", sizeof(o->reason) - 1);
	o->reason[sizeof(o->reason) - 1] = 0;
	/* Task #62: ss_save_outgoing_joins disabled — see json_factory_join_request comment */

	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-cancel-join: cancelled join req_id=%llu to %s",
		   (unsigned long long)*request_id, lsp_hex);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_u64(js, "request_id", *request_id);
	json_add_string(js, "status", "cancelled");
	return command_finished(cmd, js);
}

/* ----- factory-incoming-joins --------------------------------------------- */

static struct command_result *json_factory_incoming_joins(struct command *cmd,
							  const char *buf,
							  const jsmntok_t *params)
{
	const char *instance_id_str = NULL;

	if (!param(cmd, buf, params,
		   p_opt("instance_id", param_string, &instance_id_str),
		   NULL))
		return command_param_failed();

	uint8_t filter_iid[32];
	bool filter = false;
	if (instance_id_str) {
		if (!ss_decode_instance_id_hex(instance_id_str, filter_iid))
			return command_fail(cmd, LIGHTNINGD,
				"instance_id must be 64-char hex (32 bytes)");
		filter = true;
	}

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_array_start(js, "factories");

	for (size_t fi_idx = 0; fi_idx < ss_state.n_factories; fi_idx++) {
		factory_instance_t *fi = ss_state.factories[fi_idx];
		if (!fi || !fi->is_lsp) continue;
		if (filter && memcmp(fi->instance_id, filter_iid, 32) != 0)
			continue;

		json_object_start(js, NULL);
		char iid_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(iid_hex + j*2, "%02x",
				fi->instance_id[j]);
		iid_hex[64] = 0;
		json_add_string(js, "instance_id", iid_hex);
		json_add_u32(js, "n_clients", fi->n_clients);
		json_add_u32(js, "n_channels", fi->n_channels);
		json_add_string(js, "lifecycle",
			fi->lifecycle == FACTORY_LIFECYCLE_INIT ? "init" :
			fi->lifecycle == FACTORY_LIFECYCLE_ACTIVE ? "active" :
			fi->lifecycle == FACTORY_LIFECYCLE_DYING ? "dying" :
			fi->lifecycle == FACTORY_LIFECYCLE_EXPIRED ? "expired" :
			fi->lifecycle == FACTORY_LIFECYCLE_AWAITING_JOINS ? "awaiting_joins" :
			fi->lifecycle == FACTORY_LIFECYCLE_READY_TO_TRIGGER ? "ready_to_trigger" :
			fi->lifecycle == FACTORY_LIFECYCLE_CEREMONY_RUNNING ? "ceremony_running" :
			fi->lifecycle == FACTORY_LIFECYCLE_SIGNED ? "signed" :
			fi->lifecycle == FACTORY_LIFECYCLE_FAILED ? "failed" :
			"other");

		json_array_start(js, "joins");
		for (size_t i = 0; i < fi->n_join_queue; i++) {
			factory_join_t *j = &fi->join_queue[i];
			json_object_start(js, NULL);
			char cnid_hex[67];
			for (int k = 0; k < 33; k++)
				sprintf(cnid_hex + k*2, "%02x",
					j->client_node_id[k]);
			cnid_hex[66] = 0;
			json_add_string(js, "client_node_id", cnid_hex);
			json_add_u64(js, "request_id", j->request_id);
			json_add_u64(js, "contribution_sats",
				     j->contribution_sats);
			json_add_string(js, "status",
				ss_factory_join_status_name(j->status));
			json_add_u32(js, "received_at_block",
				     j->received_at_block);
			json_add_u32(js, "accepted_at_block",
				     j->accepted_at_block);
			json_add_u32(js, "decided_at_block",
				     j->decided_at_block);
			if (j->last_seen_block)
				json_add_u32(js, "last_seen_block",
					     j->last_seen_block);
			if (j->reason[0])
				json_add_string(js, "reason",
						(const char *)j->reason);
			json_object_end(js);
		}
		json_array_end(js);
		json_object_end(js);
	}
	json_array_end(js);
	return command_finished(cmd, js);
}

/* ----- factory-kick-joiner ------------------------------------------------ */

static struct command_result *json_factory_kick_joiner(struct command *cmd,
						       const char *buf,
						       const jsmntok_t *params)
{
	const char *instance_id_str = NULL;
	const char *client_node_id_str = NULL;
	const char *reason_str = NULL;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &instance_id_str),
		   p_req("client_node_id", param_string, &client_node_id_str),
		   p_opt("reason", param_string, &reason_str),
		   NULL))
		return command_param_failed();

	uint8_t iid[32], client_pk[33];
	if (!ss_decode_instance_id_hex(instance_id_str, iid))
		return command_fail(cmd, LIGHTNINGD,
			"instance_id must be 64-char hex");
	if (!ss_decode_node_id_hex(client_node_id_str, client_pk))
		return command_fail(cmd, LIGHTNINGD,
			"client_node_id must be 66-char hex");

	factory_instance_t *fi = ss_factory_find(&ss_state, iid);
	if (!fi || !fi->is_lsp)
		return command_fail(cmd, LIGHTNINGD,
			"factory-kick-joiner: factory %s not found or "
			"not hosted by us", instance_id_str);

	factory_join_t *target = NULL;
	for (size_t i = 0; i < fi->n_join_queue; i++) {
		if (memcmp(fi->join_queue[i].client_node_id, client_pk, 33) == 0) {
			target = &fi->join_queue[i];
			break;
		}
	}
	if (!target)
		return command_fail(cmd, LIGHTNINGD,
			"factory-kick-joiner: no queue entry for "
			"client %s in factory %s",
			client_node_id_str, instance_id_str);

	if (target->status == JOIN_STATUS_REJECTED ||
	    target->status == JOIN_STATUS_CANCELLED)
		return command_fail(cmd, LIGHTNINGD,
			"factory-kick-joiner: client %s is already in "
			"status=%s, cannot kick",
			client_node_id_str,
			ss_factory_join_status_name(target->status));

	target->status = JOIN_STATUS_REJECTED;
	target->decided_at_block = ss_state.current_blockheight;
	const char *use_reason = (reason_str && reason_str[0])
		? reason_str : "kicked by LSP operator";
	strncpy((char *)target->reason, use_reason, sizeof(target->reason) - 1);
	target->reason[sizeof(target->reason) - 1] = 0;

	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-kick-joiner: kicked client %s from factory %s "
		   "(reason: %s)",
		   client_node_id_str, instance_id_str, use_reason);

	/* Send unsolicited JOIN_RESPONSE to the kicked client so their
	 * wallet status updates. */
	size_t rlen = strlen(use_reason);
	if (rlen > 64) rlen = 64;
	uint8_t resp[8 + 1 + 4 + 1 + 64 + 2];
	uint8_t *rp = resp;
	for (int k = 7; k >= 0; k--) *rp++ = (target->request_id >> (k*8)) & 0xFF;
	*rp++ = (uint8_t)JOIN_STATUS_REJECTED;
	for (int k = 0; k < 4; k++) *rp++ = 0;
	*rp++ = (uint8_t)rlen;
	memcpy(rp, use_reason, rlen); rp += rlen;
	*rp++ = 0; *rp++ = 0;
	size_t actual = (size_t)(rp - resp);
	send_factory_msg(cmd, client_node_id_str,
			 SS_SUBMSG_JOIN_RESPONSE, resp, actual);

	ss_save_factory(cmd, fi);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", instance_id_str);
	json_add_string(js, "client_node_id", client_node_id_str);
	json_add_string(js, "status", "rejected");
	json_add_string(js, "reason", use_reason);
	return command_finished(cmd, js);
}

/* PR 3b: extracted MuSig2 kickoff. Called by json_factory_create
 * (legacy synchronous flow) and by json_factory_trigger_ceremony
 * (new decoupled flow). Builds the libsuperscalar factory_t handle,
 * derives placeholder client pubkeys, builds the DW tree, configures
 * per-leaf amounts from allocations, generates LSP MuSig2 nonces, and
 * broadcasts FACTORY_PROPOSE (0x0100) to every client.
 *
 * Caller must set fi->funding_amount_sats, fi->n_clients, fi->clients[],
 * fi->arity_mode, and fi->instance_id before calling.
 *
 * Returns NULL on success (FACTORY_PROPOSE broadcasts queued). On
 * failure, returns the command_fail() result to be propagated. */
static struct command_result *ss_kickoff_factory_signing(
	struct command *cmd, factory_instance_t *fi)
{
	secp256k1_context *secp_ctx = global_secp_ctx;

/* Initialize the factory via libsuperscalar */

/* Build pubkey array: [LSP, client0, client1, ...] */
{
	factory_t *factory = calloc(1, sizeof(factory_t));
	size_t n_total = 1 + fi->n_clients;
	secp256k1_pubkey *pubkeys = calloc(n_total,
					   sizeof(secp256k1_pubkey));

	/* Pubkeys for tree construction.
	 * LSP (k=0): real factory key (HSM-derived or demo XOR).
	 * Clients (k≥1): placeholder keys — used only for tree
	 * topology, replaced by real pubkeys after NONCE_BUNDLE
	 * collection. All nodes produce identical placeholder keys
	 * for client slots since derive_placeholder_seckey is
	 * deterministic (instance_id + slot only). */
	for (size_t k = 0; k < n_total; k++) {
		unsigned char sk[32];
		if (k == 0)
			derive_factory_seckey(sk, fi->instance_id, 0);
		else
			derive_placeholder_seckey(sk, fi->instance_id, (int)k);
		if (!secp256k1_ec_pubkey_create(secp_ctx,
						&pubkeys[k], sk)) {
			return command_fail(cmd, LIGHTNINGD,
					    "Bad derived pubkey");
		}
	}

	/* Initialize factory with derived pubkeys */
	factory_init_from_pubkeys(factory, secp_ctx,
				  pubkeys, n_total,
				  DW_STEP_BLOCKS,
				  16); /* states_per_layer */

	/* Phase 3c3: wire the fee estimator so tree TXs carry
	 * P2A anchors (activates Phase 3c2/3c2.5 CPFP). */
	ss_factory_wire_fee_estimator(fi, factory);

	factory_set_arity(factory, ss_effective_arity(fi));

	/* Set funding — use a plausible P2TR scriptpubkey.
	 * Real funding comes from the on-chain UTXO backing
	 * the factory. For now use synthetic data. */
	uint8_t synth_txid[32];
	for (int j = 0; j < 32; j++) synth_txid[j] = j + 1;
	/* P2TR scriptpubkey: OP_1 <32-byte x-only key> */
	uint8_t synth_spk[34];
	synth_spk[0] = 0x51; /* OP_1 */
	synth_spk[1] = 0x20; /* PUSH 32 */
	/* Use the aggregate key as the taproot key */
	memset(synth_spk + 2, 0xAA, 32);
	factory_set_funding(factory, synth_txid, 0,
			    fi->funding_amount_sats, synth_spk, 34);

	/* Set lifecycle so DW nodes get CLTV timeout script leaves.
	 * This enables the timeout spend path (safety valve for
	 * client unilateral exit if LSP vanishes after expiry). */
	factory_set_lifecycle(factory,
		ss_state.current_blockheight,
		4320,   /* active period: ~30 days */
		432);   /* dying period: ~3 days */

	/* Derive L-stock revocation secrets BEFORE building the tree so
	 * build_l_stock_spk() produces hashlocked P2TR outputs from
	 * epoch 0 onward. This matters because the L-stock output keys
	 * are committed when the tree is built; setting secrets later
	 * would leave epoch-0 L-stock as bare-key (recoverable only by
	 * LSP with no hashlock). Deterministic derivation from HSM
	 * guarantees identical secrets after any restart. */
	if (ss_state.has_master_key) {
		static unsigned char secrets[256][32];
		derive_l_stock_secrets(secrets, 256, fi->instance_id);
		factory_set_flat_secrets(factory,
			(const unsigned char (*)[32])secrets, 256);
	}

	/* Build the DW tree */
	int rc = factory_build_tree(factory);
	if (rc == 0) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "factory_build_tree failed: %d", rc);
		free(factory);
		free(pubkeys);
		return command_fail(cmd, LIGHTNINGD,
				    "Failed to build factory tree");
	}

	plugin_log(plugin_handle, LOG_INFORM,
		   "Factory tree built: %zu participants",
		   n_total);

	/* Configure per-leaf amounts: each client gets either their
	 * explicit allocation_sats, or an even share if 0.
	 * L-stock (LSP liquidity) is the last output on each leaf. */
	{
		uint64_t total = fi->funding_amount_sats;
		uint64_t lstock_pct = 20;
		uint64_t lstock_total = total * lstock_pct / 100;
		uint64_t client_total = total - lstock_total;
		uint64_t default_per_client =
			client_total / (n_total - 1);

		for (int ls = 0; ls < factory->n_leaf_nodes; ls++) {
			size_t leaf_ni = factory->leaf_node_indices[ls];
			factory_node_t *ln = &factory->nodes[leaf_ni];
			size_t n_clients_on_leaf = 0;
			for (size_t s = 0; s < ln->n_signers; s++)
				if (ln->signer_indices[s] != 0)
					n_clients_on_leaf++;

			size_t n_outputs = n_clients_on_leaf + 1;
			uint64_t *amts = calloc(n_outputs, sizeof(uint64_t));
			if (amts) {
				/* Walk signers for this leaf, map
				 * participant_idx -> client_idx, pick
				 * allocation_sats (or default). */
				size_t out_idx = 0;
				uint64_t client_sum = 0;
				for (size_t s = 0; s < ln->n_signers; s++) {
					int pidx = ln->signer_indices[s];
					if (pidx == 0) continue; /* skip LSP */
					size_t ci = (size_t)(pidx - 1);
					uint64_t a = (ci < fi->n_clients &&
						      fi->clients[ci].allocation_sats > 0)
						? fi->clients[ci].allocation_sats
						: default_per_client;
					amts[out_idx++] = a;
					client_sum += a;
				}
				/* Library requires sum(amts) == sum(current node
				 * outputs), NOT ln->input_amount (which excludes the
				 * tree-fee deduction the library has already applied).
				 * Read current_total from outputs to satisfy the
				 * conservation check in factory_set_leaf_amounts. */
				uint64_t current_total = 0;
				for (size_t o = 0; o < ln->n_outputs; o++)
					current_total += ln->outputs[o].amount_sats;
				if (client_sum + 546 > current_total) {
					plugin_log(plugin_handle, LOG_UNUSUAL,
						   "Leaf %d: allocations sum %"PRIu64
						   " leaves L-stock below dust "
						   "(current_total=%"PRIu64
						   "); skipping rewrite",
						   ls, client_sum, current_total);
					free(amts);
					continue;
				}
				amts[n_clients_on_leaf] = current_total - client_sum;

				if (factory_set_leaf_amounts(factory, ls,
							    amts, n_outputs))
					plugin_log(plugin_handle, LOG_INFORM,
						   "Leaf %d: %zu clients, "
						   "L-stock=%"PRIu64" sats",
						   ls, n_clients_on_leaf,
						   amts[n_clients_on_leaf]);
				free(amts);
			}
		}
	}

	/* L-stock secrets were set before build_tree when the HSM is
	 * available (see above). Non-HSM fallback handled here —
	 * generates random secrets that will NOT survive restart.
	 * This path is for dev/test only. */
	if (!ss_state.has_master_key
	    && factory_generate_flat_secrets(factory, 256)) {
		factory_set_l_stock_hashes(factory,
			(const unsigned char (*)[32])factory->l_stock_hashes,
			factory->n_l_stock_hashes);
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "Generated %zu L-stock hashes from urandom "
			   "(no HSM — secrets will be lost on restart)",
			   factory->n_l_stock_hashes);
	} else if (factory->n_revocation_secrets > 0) {
		plugin_log(plugin_handle, LOG_INFORM,
			   "Using %zu HSM-derived L-stock secrets",
			   factory->n_revocation_secrets);
	}

	/* Store factory handle + populate metadata from tree */
	fi->lib_factory = factory;
	fi->n_tree_nodes = (uint32_t)factory->n_nodes;
	fi->max_epochs = factory->counter.total_states;
	fi->creation_block = ss_state.current_blockheight;
	fi->expiry_block = factory->cltv_timeout > 0
		? factory->cltv_timeout
		: ss_state.current_blockheight + 4320; /* ~30 days */

	/* Compute HTLC safety parameter from DW tree depth.
	 * This is the minimum time needed to force-close the
	 * factory before an HTLC times out. */
	fi->early_warning_time = compute_early_warning_time(
		fi->n_clients, ss_effective_arity(fi));

	/* Initialize signing sessions */
	rc = factory_sessions_init(factory);
	if (rc == 0) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "factory_sessions_init failed");
		free(factory);
		free(pubkeys);
		return command_fail(cmd, LIGHTNINGD,
				    "Failed to init signing sessions");
	}

	/* Generate nonces using nonce pool.
	 * Need a keypair for the LSP (participant 0). */
	{
		unsigned char lsp_seckey[32];
		secp256k1_keypair lsp_keypair;

		/* Derive LSP seckey deterministically (participant 0) */
		derive_factory_seckey(lsp_seckey, fi->instance_id, 0);
		if (!secp256k1_keypair_create(secp_ctx, &lsp_keypair,
					      lsp_seckey)) {
			return command_fail(cmd, LIGHTNINGD,
					    "Failed to create LSP keypair");
		}

		/* Store seckey for signing phase */
		memcpy(fi->our_seckey, lsp_seckey, 32);
		fi->our_participant_idx = 0;
		fi->n_secnonces = 0;

		/* Count nodes where LSP is a signer */
		size_t lsp_node_count = factory_count_nodes_for_participant(
			factory, 0);

		/* Heap-allocate pool so secnonces survive this scope */
		musig_nonce_pool_t *pool = calloc(1, sizeof(musig_nonce_pool_t));
		if (!musig_nonce_pool_generate(secp_ctx, pool,
					       lsp_node_count,
					       lsp_seckey,
					       &pubkeys[0],
					       NULL)) {
			free(pool);
			free(pubkeys);
			return command_fail(cmd, LIGHTNINGD,
					    "Failed to generate nonce pool");
		}
		fi->nonce_pool = pool;

		/* Extract nonces for each node.
		 * Heap-allocate: with 1024 entries nonce_bundle_t is ~79KB */
		nonce_bundle_t *nb = calloc(1, sizeof(nonce_bundle_t));
		if (!nb) {
			free(pool);
			free(pubkeys);
			return command_fail(cmd, LIGHTNINGD,
					    "OOM allocating nonce bundle");
		}
		memcpy(nb->instance_id, fi->instance_id, 32);
		nb->n_participants = n_total;
		nb->n_nodes = factory->n_nodes;
		nb->n_entries = 0;
		/* Tier 2.6: propagate our arity choice so the client
		 * builds an identical tree. 0 = auto (legacy). */
		nb->arity_mode = fi->arity_mode;

		plugin_log(plugin_handle, LOG_INFORM,
			   "factory-create: n_nodes=%zu lsp_node_count=%zu",
			   (size_t)factory->n_nodes, lsp_node_count);

		/* Include all pubkeys so client can reconstruct */
		for (size_t pk = 0; pk < n_total && pk < MAX_PARTICIPANTS; pk++) {
			size_t pklen = 33;
			secp256k1_ec_pubkey_serialize(secp_ctx,
				nb->pubkeys[pk], &pklen,
				&pubkeys[pk],
				SECP256K1_EC_COMPRESSED);
		}

		size_t pool_entry = 0;
		for (size_t ni = 0; ni < factory->n_nodes; ni++) {
			int slot = factory_find_signer_slot(
				factory, ni, 0);
			if (slot < 0) continue;

			if (nb->n_entries >= MAX_NONCE_ENTRIES ||
			    fi->n_secnonces >= MAX_NONCE_ENTRIES) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Nonce entries exceeded MAX_NONCE_ENTRIES"
					   " (%d) at node %zu — increase limit",
					   MAX_NONCE_ENTRIES, ni);
				break;
			}

			secp256k1_musig_secnonce *secnonce;
			secp256k1_musig_pubnonce pubnonce;

			if (!musig_nonce_pool_next(pool,
						   &secnonce,
						   &pubnonce)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Nonce pool exhausted at node %zu",
					   ni);
				break;
			}

			/* Track pool index → node mapping */
			fi->secnonce_pool_idx[fi->n_secnonces] = pool_entry;
			fi->secnonce_node_idx[fi->n_secnonces] = ni;
			fi->n_secnonces++;
			pool_entry++;

			/* Set on the factory session */
			factory_session_set_nonce(factory, ni,
						  (size_t)slot,
						  &pubnonce);

			/* Serialize for sending */
			musig_pubnonce_serialize(secp_ctx,
				nb->entries[nb->n_entries].pubnonce,
				&pubnonce);
			nb->entries[nb->n_entries].node_idx = ni;
			nb->entries[nb->n_entries].signer_slot = slot;
			nb->n_entries++;
		}

		/* Cache LSP's nonce entries for ALL_NONCES round. */
		if (fi->cached_nonces) free(fi->cached_nonces);
		fi->cached_nonces_cap = MAX_NONCE_ENTRIES;
		fi->cached_nonces = calloc(fi->cached_nonces_cap,
			sizeof(nonce_entry_t));
		fi->n_cached_nonces = 0;
		if (fi->cached_nonces && nb->n_entries <= fi->cached_nonces_cap) {
			memcpy(fi->cached_nonces, nb->entries,
			       nb->n_entries * sizeof(nonce_entry_t));
			fi->n_cached_nonces = nb->n_entries;
		}

		plugin_log(plugin_handle, LOG_INFORM,
			   "MuSig2 nonces: %zu entries for %zu nodes",
			   nb->n_entries,
			   (size_t)factory->n_nodes);

		/* Serialize the nonce bundle */
		uint8_t *nbuf = calloc(1, MAX_WIRE_BUF);
		size_t blen = nonce_bundle_serialize(nb, nbuf,
						     MAX_WIRE_BUF);
		free(nb);

		plugin_log(plugin_handle, LOG_INFORM,
			   "Nonce bundle serialized: %zu bytes",
			   blen);

		fi->ceremony = CEREMONY_PROPOSED;

		/* Send FACTORY_PROPOSE to each client.
		 * Payload format:
		 *   nonce_bundle || famt(8) || pidx(4)
		 *                [|| alloc[n_alloc](n*8) || n_alloc(1)]
		 * The allocations suffix is optional: n_alloc==0 means
		 * recipients fall back to even-split. */
		uint8_t n_alloc = 0;
		for (size_t ci = 0; ci < fi->n_clients; ci++) {
			if (fi->clients[ci].allocation_sats > 0) {
				n_alloc = (uint8_t)fi->n_clients;
				break;
			}
		}
		size_t alloc_bytes = (size_t)n_alloc * 8;
		size_t extra = 1 + alloc_bytes; /* always send n_alloc byte */

		for (size_t ci = 0; ci < fi->n_clients; ci++) {
			char client_hex[67];
			for (int h = 0; h < 33; h++)
				sprintf(client_hex + h*2, "%02x",
					fi->clients[ci].node_id[h]);

			uint32_t pidx = (uint32_t)(ci + 1);
			uint8_t *cbuf = calloc(1, blen + 12 + extra);
			memcpy(cbuf, nbuf, blen);
			uint64_t famt = fi->funding_amount_sats;
			cbuf[blen]     = (famt >> 56) & 0xFF;
			cbuf[blen + 1] = (famt >> 48) & 0xFF;
			cbuf[blen + 2] = (famt >> 40) & 0xFF;
			cbuf[blen + 3] = (famt >> 32) & 0xFF;
			cbuf[blen + 4] = (famt >> 24) & 0xFF;
			cbuf[blen + 5] = (famt >> 16) & 0xFF;
			cbuf[blen + 6] = (famt >>  8) & 0xFF;
			cbuf[blen + 7] = famt & 0xFF;
			cbuf[blen + 8]  = (pidx >> 24) & 0xFF;
			cbuf[blen + 9]  = (pidx >> 16) & 0xFF;
			cbuf[blen + 10] = (pidx >> 8)  & 0xFF;
			cbuf[blen + 11] = pidx & 0xFF;

			{
				size_t off = blen + 12;
				for (uint8_t ai = 0; ai < n_alloc; ai++) {
					uint64_t v = fi->clients[ai].allocation_sats;
					cbuf[off + 0] = (v >> 56) & 0xFF;
					cbuf[off + 1] = (v >> 48) & 0xFF;
					cbuf[off + 2] = (v >> 40) & 0xFF;
					cbuf[off + 3] = (v >> 32) & 0xFF;
					cbuf[off + 4] = (v >> 24) & 0xFF;
					cbuf[off + 5] = (v >> 16) & 0xFF;
					cbuf[off + 6] = (v >>  8) & 0xFF;
					cbuf[off + 7] = v & 0xFF;
					off += 8;
				}
				cbuf[off] = n_alloc; /* 0 when no allocs */
			}

			/* Phase C v2: switch to V2 submsg with policy diff
			 * trailer so the client validator sees THIS
			 * ceremony's policy, not a stale browse-time cache. */
			{
				uint8_t pol_buf[1024];
				size_t pol_len = ss_build_factory_policy_blob(fi, pol_buf, sizeof(pol_buf));
				size_t v2_len = blen + 12 + extra + 2 + pol_len;
				uint8_t *v2 = malloc(v2_len);
				if (v2) {
					memcpy(v2, cbuf, blen + 12 + extra);
					if (pol_len > 0)
						memcpy(v2 + blen + 12 + extra, pol_buf, pol_len);
					v2[blen + 12 + extra + pol_len] = (uint8_t)(pol_len >> 8);
					v2[blen + 12 + extra + pol_len + 1] = (uint8_t)(pol_len & 0xFF);
					send_factory_msg(cmd, client_hex,
						SS_SUBMSG_FACTORY_PROPOSE_V2,
						v2, v2_len);
					free(v2);
				} else {
					/* Fallback: send V1 if alloc fails. */
					send_factory_msg(cmd, client_hex,
						SS_SUBMSG_FACTORY_PROPOSE,
						cbuf, blen + 12 + extra);
				}
			}

			/* D.2: record this proposal in the LSP signature queue
			 * so we can replay it if the client reconnects later. */
			{
				uint8_t cli_pk[33];
				if (ss_decode_node_id_hex(client_hex, cli_pk)) {
					/* ceremony_id is fi->active_ceremony_id (first 8 bytes
					 * derived from instance + epoch + current_block). */
					uint8_t cid[8];
					memcpy(cid, fi->active_ceremony_id, 8);
					struct ss_lsp_sig_queue_entry *qe =
						ss_lsp_sig_queue_slot(fi->instance_id, cli_pk, cid);
					qe->state = SS_SIGQUEUE_AWAITING_YOUR_SIGNATURE;
					qe->deadline_block = fi->active_ceremony_deadline_block;
					qe->inserted_at_block = ss_state.current_blockheight;
					/* Stash a copy of the proposal payload for replay. */
					if (qe->proposal_blob) free(qe->proposal_blob);
					qe->proposal_blob = malloc(blen + 12 + extra);
					if (qe->proposal_blob) {
						memcpy(qe->proposal_blob, cbuf, blen + 12 + extra);
						qe->proposal_blob_len = blen + 12 + extra;
					}
					ss_lsp_sig_queue_persist();
				}
			}
			free(cbuf);

			plugin_log(plugin_handle, LOG_INFORM,
				   "Sent FACTORY_PROPOSE to client %zu "
				   "(%zu bytes, participant_idx=%u, n_alloc=%u)",
				   ci, blen + 12 + extra, pidx, n_alloc);
		}
		free(nbuf);
	}

	free(pubkeys);
}
	return NULL;
}

static struct command_result *json_factory_create(struct command *cmd,
						  const char *buf,
						  const jsmntok_t *params)
{
	const jsmntok_t *clients_tok;
	u64 *funding_sats;
	factory_instance_t *fi;
	secp256k1_context *secp_ctx;
	uint8_t instance_id[32];

	const jsmntok_t *allocations_tok = NULL;
	const char *arity_mode_str = NULL;
	u32 *feerate_perkw_opt = NULL;
	/* PR 3: defer_signing=true creates the factory in AWAITING_JOINS state
	 * without running MuSig2. Operator then accumulates joiners via the
	 * factory-join-request flow and fires factory-trigger-ceremony when
	 * ready. Default false preserves the legacy synchronous behavior. */
	bool *defer_signing_opt = NULL;
	if (!param(cmd, buf, params,
		   p_req("funding_sats", param_u64, &funding_sats),
		   p_req("clients", param_array, &clients_tok),
		   p_opt("allocations", param_array, &allocations_tok),
		   p_opt("arity_mode", param_string, &arity_mode_str),
		   p_opt("feerate_perkw", param_u32, &feerate_perkw_opt),
		   p_opt("defer_signing", param_bool, &defer_signing_opt),
		   NULL))
		return command_param_failed();

	bool defer_signing = defer_signing_opt && *defer_signing_opt;

	/* Tier 2.6: optional arity selection. Default "auto" preserves
	 * legacy ss_choose_arity behavior. "arity_ps" selects pseudo-Spilman
	 * leaves (upstream FACTORY_ARITY_PS) — replaces the leaf DW layer
	 * with a chained TX sequence, saving ~3 days of CLTV delta at the
	 * cost of O(K) force-close. */
	uint8_t parsed_arity_mode = 0; /* 0 = auto */
	if (arity_mode_str) {
		if (strcmp(arity_mode_str, "auto") == 0)
			parsed_arity_mode = 0;
		else if (strcmp(arity_mode_str, "arity_1") == 0)
			parsed_arity_mode = 1;
		else if (strcmp(arity_mode_str, "arity_2") == 0)
			parsed_arity_mode = 2;
		else if (strcmp(arity_mode_str, "arity_ps") == 0 ||
			 strcmp(arity_mode_str, "ps") == 0)
			parsed_arity_mode = 3;
		else
			return command_fail(cmd, LIGHTNINGD,
				"arity_mode must be one of: auto, arity_1, "
				"arity_2, arity_ps (got %s)",
				arity_mode_str);
	}

	/* Gap 8: deterministic instance_id from HSM master key when
	 * available. iid = SHA256(master_key || "ss-iid-v1" ||
	 * current_block_le4 || counter_le4). Counter is persisted under
	 * "superscalar/iid_counter" and increments on every call, so two
	 * factory-creates in the same block still get distinct iids.
	 *
	 * Fallback to random() when no master key is loaded (e.g. a demo
	 * build without HSM access — keeps existing behavior for that
	 * path). */
	if (ss_state.has_master_key) {
		uint32_t creation_block = ss_state.current_blockheight;
		uint32_t counter = ss_state.factory_counter;
		derive_instance_id_from_hsm(instance_id, creation_block,
					    counter);
		/* Increment in memory and persist so a restart doesn't
		 * reuse the counter. If the persist write fails (network,
		 * datastore quota), we still advance in memory; the worst
		 * case is that a later restart re-uses the same counter for
		 * a never-persisted factory, which is fine because that
		 * earlier factory wasn't persisted either. */
		ss_state.factory_counter = counter + 1;
		ss_save_iid_counter(cmd);
	} else {
		for (int i = 0; i < 32; i++)
			instance_id[i] = (uint8_t)(random() & 0xFF);
	}

	fi = ss_factory_new(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD,
				    "Too many active factories");

	fi->is_lsp = true;
	fi->lifecycle = FACTORY_LIFECYCLE_INIT;
	fi->ceremony = CEREMONY_IDLE;
	fi->arity_mode = parsed_arity_mode;
	fi->requested_feerate_perkw = feerate_perkw_opt ? *feerate_perkw_opt : 0;

	/* Parse client node IDs */
	const jsmntok_t *t;
	size_t i;
	json_for_each_arr(i, t, clients_tok) {
		if (fi->n_clients >= MAX_FACTORY_PARTICIPANTS)
			break;
		const char *hex = json_strdup(cmd, buf, t);
		if (hex && strlen(hex) == 66) {
			client_state_t *c = &fi->clients[fi->n_clients];
			for (int j = 0; j < 33; j++) {
				unsigned int byte;
				sscanf(hex + j*2, "%02x", &byte);
				c->node_id[j] = (uint8_t)byte;
			}
			c->signer_slot = fi->n_clients + 1; /* 0=LSP */
			c->allocation_sats = 0; /* Default: even split */
			c->pending_revoke_epoch = UINT32_MAX;
			c->last_acked_epoch = UINT32_MAX;
			fi->n_clients++;
		}
	}

	/* Parse optional allocations array (per-client sats, ordered to match
	 * clients array). If omitted, allocation_sats stays 0 and the even-
	 * split fallback is used downstream.
	 *
	 * ARITY_PS: apply_allocations_to_leaves does not currently rewrite
	 * chain[0]'s outputs (setup_ps_leaf_outputs hardcodes a 50/50
	 * channel/L-stock split that survives the allocation pass). Until
	 * PS-aware allocation logic lands, reject the parameter rather than
	 * silently ignoring it — operators who set allocations expect them
	 * to take effect. */
	fi->n_allocations = 0;
	if (allocations_tok && parsed_arity_mode == 3) {
		return command_fail(cmd, LIGHTNINGD,
			"allocations parameter is not supported for ARITY_PS "
			"factories — apply_allocations_to_leaves doesn't "
			"rewrite chain[0] outputs. Use arity_1 or arity_2 if "
			"you need explicit per-client allocations.");
	}
	if (allocations_tok) {
		const jsmntok_t *at;
		size_t ai;
		size_t alloc_count = 0;
		uint64_t alloc_sum = 0;
		size_t array_total = 0;
		json_for_each_arr(ai, at, allocations_tok)
			array_total++;
		if (array_total != fi->n_clients)
			return command_fail(cmd, LIGHTNINGD,
				"allocations length (%zu) != clients length (%zu)",
				array_total, fi->n_clients);
		json_for_each_arr(ai, at, allocations_tok) {
			u64 v;
			if (!json_to_u64(buf, at, &v))
				return command_fail(cmd, LIGHTNINGD,
					"allocations[%zu] not a u64", ai);
			fi->clients[alloc_count].allocation_sats = v;
			alloc_sum += v;
			alloc_count++;
		}
		/* Validate sum fits within non-L-stock 80% of funding. */
		uint64_t cap = (*funding_sats) * 80 / 100;
		if (alloc_sum > cap)
			return command_fail(cmd, LIGHTNINGD,
				"allocations sum %"PRIu64" exceeds 80%% of "
				"funding_sats (%"PRIu64")", alloc_sum, cap);
		/* Cache on fi for FACTORY_PROPOSE/ALL_NONCES serialization. */
		fi->n_allocations = (uint8_t)fi->n_clients;
		for (size_t i2 = 0; i2 < fi->n_clients; i2++)
			fi->allocations[i2] = fi->clients[i2].allocation_sats;
		plugin_log(plugin_handle, LOG_INFORM,
			   "factory-create: custom allocations sum=%"PRIu64" sats",
			   alloc_sum);
	}

	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-create: %zu clients, %"PRIu64" sats",
		   fi->n_clients, *funding_sats);

	/* PR 3: defer_signing branch. Stash the funding amount on the
	 * factory_instance_t (we keep it in a field that gets persisted
	 * via ss_save_factory so factory-trigger-ceremony can pick it up
	 * later), transition lifecycle to AWAITING_JOINS, persist, and
	 * return — skip the MuSig2 setup entirely. The trigger RPC will
	 * resume the MuSig2 dance from this point. */
	if (defer_signing) {
		fi->funding_amount_sats = *funding_sats;
		fi->lifecycle = FACTORY_LIFECYCLE_AWAITING_JOINS;

		ss_audit_log(LOG_INFORM, "factory_create_deferred",
			     "\"iid_prefix\":\"%02x%02x%02x%02x\","
			     "\"funding_sats\":%"PRIu64","
			     "\"n_clients\":%zu,"
			     "\"arity_mode\":%u,"
			     "\"feerate_perkw\":%u",
			     fi->instance_id[0], fi->instance_id[1],
			     fi->instance_id[2], fi->instance_id[3],
			     *funding_sats, fi->n_clients,
			     parsed_arity_mode,
			     fi->requested_feerate_perkw);

		ss_save_factory(cmd, fi);

		struct json_stream *response = jsonrpc_stream_success(cmd);
		char iid_hex[65];
		for (int i = 0; i < 32; i++)
			sprintf(iid_hex + i*2, "%02x", fi->instance_id[i]);
		iid_hex[64] = 0;
		json_add_string(response, "factory_instance_id_hex", iid_hex);
		json_add_string(response, "lifecycle", "awaiting_joins");
		json_add_u64(response, "funding_sats", *funding_sats);
		json_add_u64(response, "n_clients", fi->n_clients);
		json_add_string(response, "next_step",
				"call factory-trigger-ceremony with this "
				"factory_instance_id_hex when ready to sign");
		return command_finished(cmd, response);
	}

	/* PR 3b: set funding_amount_sats before the kickoff helper.
	 * (Previously the kickoff block set it inline; the helper no
	 * longer does so since the trigger path already sets it during
	 * defer_signing.) */
	fi->funding_amount_sats = *funding_sats;

	/* PR 3b: kickoff extracted into ss_kickoff_factory_signing.
	 * Same helper is called by json_factory_trigger_ceremony below. */
	{
		struct command_result *kres = ss_kickoff_factory_signing(cmd, fi);
		if (kres) return kres;
	}

	{
		char id_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(id_hex + j*2, "%02x", instance_id[j]);

		struct json_stream *js = jsonrpc_stream_success(cmd);
		json_add_string(js, "instance_id", id_hex);
		json_add_u64(js, "n_clients", fi->n_clients);
		json_add_string(js, "ceremony", "init");
		return command_finished(cmd, js);
	}
}

/* PR 3: factory-trigger-ceremony RPC.
 *
 * Operates on a factory created with defer_signing=true (lifecycle=
 * AWAITING_JOINS or READY_TO_TRIGGER). Generates a fresh ceremony_id,
 * sends CEREMONY_START (0x0145) to each participant, transitions
 * lifecycle to CEREMONY_RUNNING, persists.
 *
 * After this RPC returns, the LSP operator (or a follow-up RPC) is
 * expected to kick off the MuSig2 setup using the existing factory-
 * create code path's NONCE_BUNDLE flow. That kickoff is the scope of
 * PR 3b; for now this RPC fires CEREMONY_START as a heads-up and
 * transitions state. The participants treat CEREMONY_START as a "wake
 * up, you're about to be asked to sign" notification — they cache the
 * ceremony_id and prepare to receive the MuSig2 messages.
 *
 * Params:
 *   factory_instance_id_hex (required) — 64-char hex of the deferred factory
 *   force (optional bool, default false) — skip min-clients-to-start check
 *   deadline_block (optional u32) — defaults to current_blockheight + 144 (~24h)
 *
 * Returns:
 *   ceremony_id_hex — 16-char hex of the generated ceremony_id
 *   n_participants — count of CEREMONY_START messages sent
 *   lifecycle — "ceremony_running"
 */
static struct command_result *json_factory_trigger_ceremony(
	struct command *cmd, const char *buf, const jsmntok_t *params)
{
	const char *iid_hex_param;
	bool *force_opt = NULL;
	u32 *deadline_block_opt = NULL;

	if (!param(cmd, buf, params,
		   p_req("factory_instance_id_hex", param_string, &iid_hex_param),
		   p_opt("force", param_bool, &force_opt),
		   p_opt("deadline_block", param_u32, &deadline_block_opt),
		   NULL))
		return command_param_failed();

	if (strlen(iid_hex_param) != 64)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "factory_instance_id_hex must be 64 hex chars (got %zu)",
				    strlen(iid_hex_param));

	uint8_t target_iid[32];
	for (int i = 0; i < 32; i++) {
		unsigned int byte;
		if (sscanf(iid_hex_param + i*2, "%02x", &byte) != 1)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "factory_instance_id_hex invalid hex at offset %d", i*2);
		target_iid[i] = (uint8_t)byte;
	}

	/* Look up the factory */
	factory_instance_t *fi = NULL;
	for (size_t i = 0; i < ss_state.n_factories; i++) {
		if (memcmp(ss_state.factories[i]->instance_id, target_iid, 32) == 0) {
			fi = ss_state.factories[i];
			break;
		}
	}
	if (!fi)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "factory %s not found", iid_hex_param);

	if (!fi->is_lsp)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "factory-trigger-ceremony: only LSPs can trigger "
				    "ceremonies (this factory is is_lsp=false)");

	if (!factory_is_awaiting_signing(fi->lifecycle))
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "factory lifecycle is %d, expected "
				    "AWAITING_JOINS(9) or READY_TO_TRIGGER(10); "
				    "factory-trigger-ceremony only valid on "
				    "deferred-signing factories",
				    (int)fi->lifecycle);

	bool force = force_opt && *force_opt;
	if (!force && fi->n_clients < 2)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "factory has %zu clients; need at least 2 "
				    "to start a ceremony (or pass force=true to "
				    "override)",
				    fi->n_clients);

	/* Generate ceremony_id (8 random bytes for v1 — future PRs derive
	 * deterministically from instance_id+counter once we open the lib
	 * SQLite handle and can read ceremonies.ceremony_counter). */
	uint8_t ceremony_id[8];
	for (int i = 0; i < 8; i++)
		ceremony_id[i] = (uint8_t)(random() & 0xFF);

	uint32_t deadline_block = deadline_block_opt
		? *deadline_block_opt
		: ss_state.current_blockheight + 144;

	/* Build the CEREMONY_START payload using ceremony_wire codec.
	 * lsp_nonce is zeroed for PR 3 foundation — the real LSP pubnonce
	 * is generated during MuSig2 setup (existing FACTORY_PROPOSE flow).
	 * Participants treat zero lsp_nonce as "MuSig2 nonces will arrive
	 * via the existing NONCE_BUNDLE submsg (0x0101)". PR 3b switches
	 * the wire over so lsp_nonce here carries the real LSP pubnonce
	 * and FACTORY_PROPOSE retires. */
	struct ss_ceremony_start_msg start_msg = {0};
	memcpy(start_msg.ceremony_id, ceremony_id, 8);
	start_msg.type = SS_CEREMONY_TYPE_INITIAL;
	memcpy(start_msg.factory_instance_id, fi->instance_id, 32);
	memset(start_msg.parent_ceremony_id, 0, 8); /* INITIAL has no parent */
	start_msg.deadline_block = deadline_block;
	start_msg.deadline_epoch_secs = (uint64_t)time(NULL) + (deadline_block - ss_state.current_blockheight) * 600;
	/* lsp_nonce stays zero — see comment above */
	start_msg.tx_templates = NULL;
	start_msg.tx_templates_len = 0;

	uint8_t start_buf[SS_CEREMONY_START_FIXED_LEN];
	size_t start_len = ss_encode_ceremony_start(start_buf,
						    sizeof(start_buf),
						    &start_msg);
	if (start_len == 0)
		return command_fail(cmd, LIGHTNINGD,
				    "ss_encode_ceremony_start failed (internal)");

	/* Send CEREMONY_START to each client. fire-and-forget. */
	size_t sent = 0;
	for (size_t i = 0; i < fi->n_clients; i++) {
		char peer_hex[67];
		for (int j = 0; j < 33; j++)
			sprintf(peer_hex + j*2, "%02x", fi->clients[i].node_id[j]);
		peer_hex[66] = 0;
		send_factory_msg(cmd, peer_hex,
				 SS_SUBMSG_CEREMONY_START,
				 start_buf, start_len);
		sent++;
	}

	/* Transition state. */
	fi->lifecycle = FACTORY_LIFECYCLE_CEREMONY_RUNNING;

	/* PR 3b: kick off MuSig2 by calling the shared helper. This builds
	 * the tree, generates LSP nonces, and broadcasts FACTORY_PROPOSE
	 * (0x0100) to each client. The existing wire protocol drives the
	 * rest of the dance (NONCE_BUNDLE -> ALL_NONCES -> PSIG_BUNDLE ->
	 * FACTORY_READY). CEREMONY_START sent above serves as a heads-up
	 * notification; participants will receive FACTORY_PROPOSE next. */
	{
		struct command_result *kres = ss_kickoff_factory_signing(cmd, fi);
		if (kres) {
			/* Revert lifecycle on failure so re-trigger is possible. */
			fi->lifecycle = FACTORY_LIFECYCLE_AWAITING_JOINS;
			return kres;
		}
	}
	/* Stash ceremony_id in unused field for now (a typed lib SQLite
	 * row will replace this in a follow-up). We persist via ss_save_factory
	 * which currently serializes the whole struct; ceremony_id will land
	 * via that path if we add the field, or we punt persistence to PR 3b
	 * once persist_t is open. */
	ss_save_factory(cmd, fi);

	char cid_hex[17];
	for (int i = 0; i < 8; i++)
		sprintf(cid_hex + i*2, "%02x", ceremony_id[i]);
	cid_hex[16] = 0;

	ss_audit_log(LOG_INFORM, "ceremony_triggered",
		     "\"iid_prefix\":\"%02x%02x%02x%02x\","
		     "\"ceremony_id_hex\":\"%s\","
		     "\"type\":\"INITIAL\","
		     "\"n_participants\":%zu,"
		     "\"deadline_block\":%u,"
		     "\"force\":%s",
		     fi->instance_id[0], fi->instance_id[1],
		     fi->instance_id[2], fi->instance_id[3],
		     cid_hex, sent, deadline_block,
		     force ? "true" : "false");

	struct json_stream *response = jsonrpc_stream_success(cmd);
	json_add_string(response, "factory_instance_id_hex", iid_hex_param);
	json_add_string(response, "ceremony_id_hex", cid_hex);
	json_add_string(response, "ceremony_type", "INITIAL");
	json_add_u64(response, "n_participants", sent);
	json_add_u32(response, "deadline_block", deadline_block);
	json_add_string(response, "lifecycle", "ceremony_running");
	json_add_string(response, "next_step",
			"CEREMONY_START sent + FACTORY_PROPOSE broadcast. "
			"MuSig2 dance now in progress; watch for FACTORY_READY "
			"on each participant.");
	return command_finished(cmd, response);
}

/* factory-list RPC — show all factory instances */
static struct command_result *json_factory_list(struct command *cmd,
					       const char *buf,
					       const jsmntok_t *params)
{
	struct json_stream *js;

	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	js = jsonrpc_stream_success(cmd);
	json_array_start(js, "factories");
	for (size_t i = 0; i < ss_state.n_factories; i++) {
		factory_instance_t *fi = ss_state.factories[i];
		char id_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(id_hex + j*2, "%02x", fi->instance_id[j]);

		json_object_start(js, NULL);
		json_add_string(js, "instance_id", id_hex);
		json_add_bool(js, "is_lsp", fi->is_lsp);
		json_add_u32(js, "n_clients", fi->n_clients);
		json_add_u32(js, "epoch", fi->epoch);
		json_add_u32(js, "n_channels", fi->n_channels);
		json_add_string(js, "lifecycle",
			fi->lifecycle == FACTORY_LIFECYCLE_INIT ? "init" :
			fi->lifecycle == FACTORY_LIFECYCLE_ACTIVE ? "active" :
			fi->lifecycle == FACTORY_LIFECYCLE_DYING ? "dying" :
			fi->lifecycle == FACTORY_LIFECYCLE_EXPIRED ? "expired" :
			fi->lifecycle == FACTORY_LIFECYCLE_CLOSED_EXTERNALLY
				? "closed_externally" :
			fi->lifecycle == FACTORY_LIFECYCLE_CLOSED_COOPERATIVE
				? "closed_cooperative" :
			fi->lifecycle == FACTORY_LIFECYCLE_CLOSED_UNILATERAL
				? "closed_unilateral" :
			fi->lifecycle == FACTORY_LIFECYCLE_CLOSED_BREACHED
				? "closed_breached" :
			fi->lifecycle == FACTORY_LIFECYCLE_ABORTED
				? "aborted" :
			fi->lifecycle == FACTORY_LIFECYCLE_AWAITING_JOINS
				? "awaiting_joins" :
			fi->lifecycle == FACTORY_LIFECYCLE_READY_TO_TRIGGER
				? "ready_to_trigger" :
			fi->lifecycle == FACTORY_LIFECYCLE_CEREMONY_RUNNING
				? "ceremony_running" :
			fi->lifecycle == FACTORY_LIFECYCLE_SIGNED
				? "signed" :
			"unknown");
		if (fi->closed_externally_at_block > 0)
			json_add_u32(js, "closed_externally_at_block",
				     fi->closed_externally_at_block);
		if (fi->aborted_at_block > 0)
			json_add_u32(js, "aborted_at_block",
				     fi->aborted_at_block);
		if (fi->lifecycle == FACTORY_LIFECYCLE_INIT
		    && fi->creation_block > 0
		    && ss_state.current_blockheight >= fi->creation_block)
			json_add_u32(js, "blocks_in_init",
				     ss_state.current_blockheight
				     - fi->creation_block);

		/* Phase 2a classification output. Only render when we have
		 * something meaningful — all-zero spending_txid means the
		 * scan never ran or didn't find a spending TX. */
		bool any_nonzero = false;
		for (int b = 0; b < 32; b++)
			if (fi->spending_txid[b] != 0) { any_nonzero = true; break; }
		if (any_nonzero) {
			char stxid_hex[65];
			for (int j = 0; j < 32; j++)
				sprintf(stxid_hex + j*2, "%02x",
					fi->spending_txid[31-j]);
			stxid_hex[64] = '\0';
			json_add_string(js, "spending_txid", stxid_hex);
		}
		if (fi->first_noticed_block > 0)
			json_add_u32(js, "first_noticed_block",
				     fi->first_noticed_block);
		json_add_string(js, "closed_by",
			fi->closed_by == CLOSED_BY_SELF ? "self" :
			fi->closed_by == CLOSED_BY_COUNTERPARTY ? "counterparty" :
			"unknown");

		/* Phase 2b classification details. */
		{
			bool any_dist = false;
			for (int b = 0; b < 32; b++)
				if (fi->dist_signed_txid[b]) {
					any_dist = true; break;
				}
			if (any_dist) {
				char dhex[65];
				for (int j = 0; j < 32; j++)
					sprintf(dhex + j*2, "%02x",
						fi->dist_signed_txid[31-j]);
				dhex[64] = '\0';
				json_add_string(js, "dist_signed_txid", dhex);
			}
		}
		if (fi->breach_epoch != UINT32_MAX)
			json_add_u32(js, "breach_epoch", fi->breach_epoch);
		if (fi->n_history_kickoff_sigs > 0)
			json_add_u32(js, "kickoff_sig_history_epochs_cached",
				     (u32)fi->n_history_kickoff_sigs);

		/* Phase 3b: signals observed + state-TX scan result. */
		if (fi->signals_observed) {
			json_add_u32(js, "signals_observed",
				     (u32)fi->signals_observed);
			json_array_start(js, "signals");
			if (fi->signals_observed & SIGNAL_UTXO_SPENT)
				json_add_string(js, NULL, "utxo_spent");
			if (fi->signals_observed & SIGNAL_BROADCAST_MISSING)
				json_add_string(js, NULL, "broadcast_missing");
			if (fi->signals_observed & SIGNAL_BROADCAST_KNOWN)
				json_add_string(js, NULL, "broadcast_known");
			if (fi->signals_observed & SIGNAL_DIST_TXID_MATCHED)
				json_add_string(js, NULL, "dist_txid_matched");
			if (fi->signals_observed & SIGNAL_KICKOFF_TXID_MATCHED)
				json_add_string(js, NULL, "kickoff_txid_matched");
			if (fi->signals_observed & SIGNAL_WITNESS_CURRENT_MATCH)
				json_add_string(js, NULL, "witness_current_match");
			if (fi->signals_observed & SIGNAL_WITNESS_PAST_MATCH)
				json_add_string(js, NULL, "witness_past_match");
			if (fi->signals_observed & SIGNAL_STATE_TX_MATCH)
				json_add_string(js, NULL, "state_tx_match");
			if (fi->signals_observed & SIGNAL_PENALTY_CONFIRMED)
				json_add_string(js, NULL, "penalty_confirmed");
			json_array_end(js);
		}

		/* Phase 3c2: pending CPFPs surfaced for operator visibility
		 * into the anchor-bumping pipeline. */
		if (fi->n_pending_cpfps > 0) {
			json_array_start(js, "pending_cpfps");
			for (size_t ci = 0; ci < fi->n_pending_cpfps; ci++) {
				pending_cpfp_t *pc =
					&fi->pending_cpfps[ci];
				json_object_start(js, NULL);
				json_add_string(js, "parent_kind",
					cpfp_parent_kind_name(pc->parent_kind));
				json_add_string(js, "state",
					cpfp_state_name(pc->state));
				{
					char thex[65];
					for (int j = 0; j < 32; j++)
						sprintf(thex + j*2, "%02x",
							pc->parent_txid[31-j]);
					thex[64] = '\0';
					json_add_string(js, "parent_txid",
							thex);
				}
				json_add_u32(js, "parent_vout_anchor",
					     pc->parent_vout_anchor);
				json_add_u64(js, "parent_value_at_stake",
					     pc->parent_value_at_stake);
				json_add_u32(js, "parent_broadcast_block",
					     pc->parent_broadcast_block);
				json_add_u32(js, "deadline_block",
					     pc->deadline_block);
				if (pc->parent_confirmed_block)
					json_add_u32(js,
						"parent_confirmed_block",
						pc->parent_confirmed_block);
				if (pc->cpfp_broadcast_block)
					json_add_u32(js,
						"cpfp_broadcast_block",
						pc->cpfp_broadcast_block);
				if (pc->cpfp_last_feerate)
					json_add_u64(js,
						"cpfp_last_feerate",
						pc->cpfp_last_feerate);
				json_object_end(js);
			}
			json_array_end(js);
		}

		/* Phase 4d: pending sweeps surfaced for operator visibility
		 * into the CSV claim pipeline. */
		if (fi->n_pending_sweeps > 0) {
			json_array_start(js, "pending_sweeps");
			for (size_t si = 0; si < fi->n_pending_sweeps; si++) {
				pending_sweep_t *ps =
					&fi->pending_sweeps[si];
				json_object_start(js, NULL);
				json_add_string(js, "type",
					sweep_type_name(ps->type));
				json_add_string(js, "state",
					sweep_state_name(ps->state));
				{
					char thex[65];
					for (int j = 0; j < 32; j++)
						sprintf(thex + j*2, "%02x",
							ps->source_txid[31-j]);
					thex[64] = '\0';
					json_add_string(js, "source_txid",
							thex);
				}
				json_add_u32(js, "source_vout",
					     ps->source_vout);
				json_add_u64(js, "amount_sats",
					     ps->amount_sats);
				json_add_u32(js, "csv_delay", ps->csv_delay);
				if (ps->confirmed_block)
					json_add_u32(js, "confirmed_block",
						     ps->confirmed_block);
				if (ps->broadcast_block)
					json_add_u32(js, "broadcast_block",
						     ps->broadcast_block);
				if (ps->sweep_confirmed_block)
					json_add_u32(js,
						"sweep_confirmed_block",
						ps->sweep_confirmed_block);
				json_object_end(js);
			}
			json_array_end(js);
		}

		/* Phase 3c: pending penalties. Surfaces the fee-bump
		 * scheduler state so operators can see whether breach
		 * response is stuck. */
		if (fi->n_pending_penalties > 0) {
			json_array_start(js, "pending_penalties");
			for (size_t pi = 0; pi < fi->n_pending_penalties; pi++) {
				pending_penalty_t *pp =
					&fi->pending_penalties[pi];
				json_object_start(js, NULL);
				json_add_u32(js, "epoch", pp->epoch);
				json_add_num(js, "leaf_index",
					     pp->leaf_index);
				json_add_u64(js, "lstock_sats",
					     pp->lstock_sats);
				json_add_u32(js, "csv_unlock_block",
					     pp->csv_unlock_block);
				json_add_u32(js, "first_broadcast_block",
					     pp->first_broadcast_block);
				json_add_u32(js, "last_broadcast_block",
					     pp->last_broadcast_block);
				if (pp->confirmed_block)
					json_add_u32(js, "confirmed_block",
						     pp->confirmed_block);
				json_add_u64(js, "last_feerate",
					     pp->last_feerate);
				json_add_u32(js, "tx_vsize", pp->tx_vsize);
				{
					char thex[65];
					for (int j = 0; j < 32; j++)
						sprintf(thex + j*2, "%02x",
							pp->burn_txid[31-j]);
					thex[64] = '\0';
					json_add_string(js, "burn_txid", thex);
				}
				json_add_string(js, "state",
					pp->state == PENALTY_STATE_PENDING
						? "pending" :
					pp->state == PENALTY_STATE_BROADCAST
						? "broadcast" :
					pp->state == PENALTY_STATE_CONFIRMED
						? "confirmed" :
					pp->state == PENALTY_STATE_REPLACED
						? "replaced" :
					pp->state == PENALTY_STATE_STALE
						? "stale" : "unknown");
				json_object_end(js);
			}
			json_array_end(js);
		}
		if (fi->state_tx_match_epoch != UINT32_MAX)
			json_add_u32(js, "state_tx_match_epoch",
				     fi->state_tx_match_epoch);
		json_add_string(js, "ceremony",
			fi->ceremony == CEREMONY_IDLE ? "idle" :
			fi->ceremony == CEREMONY_PROPOSED ? "proposed" :
			fi->ceremony == CEREMONY_NONCES_COLLECTED ? "nonces_collected" :
			fi->ceremony == CEREMONY_PSIGS_COLLECTED ? "psigs_collected" :
			fi->ceremony == CEREMONY_COMPLETE ? "complete" :
			fi->ceremony == CEREMONY_ROTATING ? "rotating" :
			fi->ceremony == CEREMONY_ROTATE_COMPLETE ? "rotate_complete" :
			fi->ceremony == CEREMONY_REVOKED ? "revoked" :
			"failed");
		json_add_u32(js, "max_epochs", fi->max_epochs);
		json_add_u32(js, "epochs_remaining",
			     fi->max_epochs > fi->epoch
				? fi->max_epochs - fi->epoch : 0);
		json_add_u32(js, "creation_block", fi->creation_block);
		json_add_u32(js, "expiry_block", fi->expiry_block);
		json_add_u32(js, "early_warning_time", fi->early_warning_time);
		/* Tier 2.6: surface the effective arity so operators can see
		 * whether this factory is DW-only or uses PS leaves. */
		{
			factory_arity_t eff = ss_effective_arity(fi);
			const char *mode = (eff == FACTORY_ARITY_PS) ? "arity_ps"
					 : (eff == FACTORY_ARITY_1) ? "arity_1"
					 : "arity_2";
			json_add_string(js, "arity_mode", mode);
			json_add_string(js, "tree_mode",
				eff == FACTORY_ARITY_PS ? "ps" : "dw");
		}
		json_add_bool(js, "rotation_in_progress",
			fi->rotation_in_progress);
		json_add_u32(js, "n_breach_epochs", fi->n_breach_epochs);

		/* Distribution TX status */
		factory_t *lf = (factory_t *)fi->lib_factory;
		if (lf) {
			json_add_string(js, "dist_tx_status",
				lf->dist_tx_ready == 2 ? "signed" :
				lf->dist_tx_ready == 1 ? "unsigned" :
				"none");
		} else {
			json_add_string(js, "dist_tx_status", "unknown");
		}

		/* tree_nodes: prefer live value, fall back to persisted */
		json_add_u32(js, "tree_nodes",
			lf ? (uint32_t)lf->n_nodes : fi->n_tree_nodes);

		/* Funding info (factory-level synthetic funding UTXO) */
		{
			char ftxid[65];
			for (int j = 0; j < 32; j++)
				sprintf(ftxid + j*2, "%02x",
					fi->funding_txid[31-j]);
			json_add_string(js, "funding_txid", ftxid);
			json_add_u32(js, "funding_outnum", fi->funding_outnum);
		}

		/* Funding amount (post-CLN-withdraw fee deduction). Tests
		 * use this to assert sums against the on-chain funding
		 * output without having to read the TX themselves. */
		json_add_u64(js, "funding_amount_sats",
			     (u64)fi->funding_amount_sats);

		/* Per-leaf snapshot: outputs (amount + scriptpubkey hex)
		 * for every leaf node. Tests use this to map per-party
		 * amounts to expected SPKs without having to read tree TXs
		 * back from the blockchain. The leaves are indexed by
		 * leaf_side (0..n_leaf_nodes-1) — same indexing as
		 * factory-ps-advance and factory-buy-liquidity. */
		if (lf) {
			json_array_start(js, "leaves");
			for (int ls = 0; ls < lf->n_leaf_nodes; ls++) {
				size_t nidx = lf->leaf_node_indices[ls];
				if (nidx >= lf->n_nodes) continue;
				factory_node_t *nd = &lf->nodes[nidx];
				json_object_start(js, NULL);
				json_add_u32(js, "leaf_side", (u32)ls);
				json_add_u32(js, "node_idx", (u32)nidx);
				json_add_u32(js, "n_signers",
					     (u32)nd->n_signers);
				json_add_bool(js, "is_ps_leaf",
					      nd->is_ps_leaf);
				if (nd->is_ps_leaf)
					json_add_u32(js, "ps_chain_len",
						     (u32)nd->ps_chain_len);
				/* signer participant indices (factory-wide,
				 * 0=LSP, 1..N=clients). Lets tests map an
				 * output to the party who controls its SPK. */
				json_array_start(js, "signers");
				for (size_t s = 0; s < nd->n_signers; s++)
					json_add_u32(js, NULL,
						(u32)nd->signer_indices[s]);
				json_array_end(js);
				/* Outputs with amount + spk hex */
				json_array_start(js, "outputs");
				for (size_t o = 0; o < nd->n_outputs; o++) {
					json_object_start(js, NULL);
					json_add_u64(js, "amount_sats",
						(u64)nd->outputs[o].amount_sats);
					char spk_hex[34*2 + 1] = {0};
					for (size_t k = 0;
					     k < nd->outputs[o].script_pubkey_len
					     && k < 34;
					     k++)
						sprintf(spk_hex + k*2, "%02x",
							nd->outputs[o].script_pubkey[k]);
					json_add_string(js, "scriptpubkey",
							spk_hex);
					json_object_end(js);
				}
				json_array_end(js);
				json_object_end(js);
			}
			json_array_end(js);
		}

		/* Per-channel data with DW leaf funding outpoint */
		json_array_start(js, "channels");
		for (size_t ch = 0; ch < fi->n_channels; ch++) {
			char cid[65];
			for (int j = 0; j < 32; j++)
				sprintf(cid + j*2, "%02x",
					fi->channels[ch].channel_id[j]);
			json_object_start(js, NULL);
			json_add_string(js, "channel_id", cid);
			json_add_u32(js, "leaf_index",
				fi->channels[ch].leaf_index);
			json_add_u32(js, "leaf_side",
				fi->channels[ch].leaf_side);
			/* Per-channel funding txid from DW leaf node */
			if (lf && (size_t)fi->channels[ch].leaf_index
			    < lf->n_nodes) {
				char ltxid[65];
				size_t li = fi->channels[ch].leaf_index;
				for (int j = 0; j < 32; j++)
					sprintf(ltxid + j*2, "%02x",
						lf->nodes[li].txid[31-j]);
				json_add_string(js, "funding_txid", ltxid);
				json_add_u32(js, "funding_outnum",
					fi->channels[ch].leaf_side);
			}
			json_object_end(js);
		}
		json_array_end(js);
		json_object_end(js);
	}
	json_array_end(js);
	return command_finished(cmd, js);
}

/* Phase 5c: operator observability.
 *
 * factory-metrics aggregates counts across all factories and their
 * pending_* sub-arrays into a single structured response suitable
 * for scraping into a monitoring pipeline. Zero side effects — pure
 * walk of in-memory state.
 *
 * Output shape:
 *   {
 *     "current_blockheight": N,
 *     "factories": { "total": N,
 *                    "by_lifecycle": { "active": N, "dying": N, ... },
 *                    "total_custody_sats": N },
 *     "penalties": { "total": N, "by_state": {...}, "highest_*_block": N },
 *     "cpfps":     { "total": N, "by_state": {...} },
 *     "sweeps":    { "total": N, "by_state": {...}, "n_failed": N }
 *   }
 *
 * Consumers should alert on:
 *   - sweeps.n_failed > 0 (operator must investigate)
 *   - penalties.by_state.pending > 0 (breach detected but not broadcast)
 *   - factories.by_lifecycle.dying > 0 sustained (stuck force-close)
 */
/* sweep_state_name and cpfp_state_name are already forward-declared
 * near the top of this file; they're defined with the scheduler
 * blocks below. We only add lifecycle_name_ext + penalty_state_name
 * here since those have no pre-existing stringifier. */
static const char *lifecycle_name_ext(factory_lifecycle_t l)
{
	switch (l) {
	case FACTORY_LIFECYCLE_INIT:               return "init";
	case FACTORY_LIFECYCLE_ACTIVE:             return "active";
	case FACTORY_LIFECYCLE_DYING:              return "dying";
	case FACTORY_LIFECYCLE_EXPIRED:            return "expired";
	case FACTORY_LIFECYCLE_CLOSED_EXTERNALLY:  return "closed_externally";
	case FACTORY_LIFECYCLE_CLOSED_COOPERATIVE: return "closed_cooperative";
	case FACTORY_LIFECYCLE_CLOSED_UNILATERAL:  return "closed_unilateral";
	case FACTORY_LIFECYCLE_CLOSED_BREACHED:    return "closed_breached";
	case FACTORY_LIFECYCLE_ABORTED:            return "aborted";
	case FACTORY_LIFECYCLE_FAILED:             return "failed";
	case FACTORY_LIFECYCLE_AWAITING_JOINS:     return "awaiting_joins";
	case FACTORY_LIFECYCLE_READY_TO_TRIGGER:   return "ready_to_trigger";
	case FACTORY_LIFECYCLE_CEREMONY_RUNNING:   return "ceremony_running";
	case FACTORY_LIFECYCLE_SIGNED:             return "signed";
	default:                                    return "unknown";
	}
}

static const char *penalty_state_name(uint8_t s)
{
	switch (s) {
	case PENALTY_STATE_PENDING:   return "pending";
	case PENALTY_STATE_BROADCAST: return "broadcast";
	case PENALTY_STATE_CONFIRMED: return "confirmed";
	case PENALTY_STATE_REPLACED:  return "replaced";
	case PENALTY_STATE_STALE:     return "stale";
	default:                       return "unknown";
	}
}

static struct command_result *json_factory_metrics(struct command *cmd,
						   const char *buf,
						   const jsmntok_t *params)
{
	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	/* Lifecycle enumeration covers 9 discrete values — index by enum. */
	#define LIFECYCLE_SLOTS 9
	unsigned int by_lifecycle[LIFECYCLE_SLOTS] = {0};
	uint64_t total_custody = 0;

	/* For penalties + sweeps we know the state enum bounds; use a
	 * fixed-size bucket that's zero-initialized and walk all values. */
	unsigned int pen_by_state[8] = {0};
	unsigned int cpfp_by_state[8] = {0};
	unsigned int swp_by_state[8] = {0};
	unsigned int n_penalties = 0, n_cpfps = 0, n_sweeps = 0;
	unsigned int n_sweeps_failed = 0;

	uint32_t highest_breach_block = 0;
	uint32_t highest_burn_confirm_block = 0;
	uint32_t highest_sweep_broadcast_block = 0;

	for (size_t i = 0; i < ss_state.n_factories; i++) {
		factory_instance_t *fi = ss_state.factories[i];
		unsigned int lc_idx = (unsigned int)fi->lifecycle;
		if (lc_idx < LIFECYCLE_SLOTS)
			by_lifecycle[lc_idx]++;

		if (fi->lifecycle == FACTORY_LIFECYCLE_ACTIVE
		    || fi->lifecycle == FACTORY_LIFECYCLE_DYING
		    || fi->lifecycle == FACTORY_LIFECYCLE_INIT)
			total_custody += fi->funding_amount_sats;

		for (size_t k = 0; k < fi->n_pending_penalties; k++) {
			pending_penalty_t *pp = &fi->pending_penalties[k];
			n_penalties++;
			if (pp->state < 8) pen_by_state[pp->state]++;
			/* first_broadcast_block proxies "breach response":
			 * the moment we reacted to a detected breach by
			 * broadcasting the burn TX. confirmed_block tracks
			 * when the burn landed on chain. */
			if (pp->first_broadcast_block > highest_breach_block)
				highest_breach_block = pp->first_broadcast_block;
			if (pp->confirmed_block > highest_burn_confirm_block)
				highest_burn_confirm_block = pp->confirmed_block;
		}

		for (size_t k = 0; k < fi->n_pending_cpfps; k++) {
			pending_cpfp_t *pc = &fi->pending_cpfps[k];
			n_cpfps++;
			if (pc->state < 8) cpfp_by_state[pc->state]++;
		}

		for (size_t k = 0; k < fi->n_pending_sweeps; k++) {
			pending_sweep_t *ps = &fi->pending_sweeps[k];
			n_sweeps++;
			if (ps->state < 8) swp_by_state[ps->state]++;
			if (ps->state == SWEEP_STATE_FAILED) n_sweeps_failed++;
			if (ps->broadcast_block > highest_sweep_broadcast_block)
				highest_sweep_broadcast_block = ps->broadcast_block;
		}
	}

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_u32(js, "current_blockheight", ss_state.current_blockheight);

	json_object_start(js, "factories");
	json_add_u32(js, "total", (u32)ss_state.n_factories);
	json_add_u64(js, "total_custody_sats", total_custody);
	json_object_start(js, "by_lifecycle");
	for (unsigned int e = 0; e < LIFECYCLE_SLOTS; e++) {
		if (by_lifecycle[e] > 0)
			json_add_u32(js,
				lifecycle_name_ext((factory_lifecycle_t)e),
				by_lifecycle[e]);
	}
	json_object_end(js);
	json_object_end(js);

	json_object_start(js, "penalties");
	json_add_u32(js, "total", n_penalties);
	json_add_u32(js, "highest_burn_first_broadcast_block", highest_breach_block);
	json_add_u32(js, "highest_burn_confirmed_block",
		     highest_burn_confirm_block);
	json_object_start(js, "by_state");
	for (unsigned int s = 0; s < 8; s++) {
		if (pen_by_state[s] > 0)
			json_add_u32(js, penalty_state_name((uint8_t)s),
				     pen_by_state[s]);
	}
	json_object_end(js);
	json_object_end(js);

	json_object_start(js, "cpfps");
	json_add_u32(js, "total", n_cpfps);
	json_object_start(js, "by_state");
	for (unsigned int s = 0; s < 8; s++) {
		if (cpfp_by_state[s] > 0)
			json_add_u32(js, cpfp_state_name((uint8_t)s),
				     cpfp_by_state[s]);
	}
	json_object_end(js);
	json_object_end(js);

	json_object_start(js, "sweeps");
	json_add_u32(js, "total", n_sweeps);
	json_add_u32(js, "n_failed", n_sweeps_failed);
	json_add_u32(js, "highest_broadcast_block",
		     highest_sweep_broadcast_block);
	json_object_start(js, "by_state");
	for (unsigned int s = 0; s < 8; s++) {
		if (swp_by_state[s] > 0)
			json_add_u32(js, sweep_state_name((uint8_t)s),
				     swp_by_state[s]);
	}
	json_object_end(js);
	json_object_end(js);

	/* Phase 4 / Task #68: slot-table + peer-table stats for dashboard */
	json_object_start(js, "slots");
	{
		unsigned int browse_used = 0, join_used = 0;
		time_t now = time(NULL);
		(void)now;
		for (int i = 0; i < SS_BROWSE_MAX_PENDING; i++)
			if (ss_browse_pending[i].request_id != 0) browse_used++;
		for (int i = 0; i < SS_JOIN_MAX_PENDING; i++)
			if (ss_join_pending[i].request_id != 0) join_used++;
		json_add_u32(js, "browse_used", browse_used);
		json_add_u32(js, "browse_total", SS_BROWSE_MAX_PENDING);
		json_add_u32(js, "join_used", join_used);
		json_add_u32(js, "join_total", SS_JOIN_MAX_PENDING);
	}
	json_object_end(js);

	json_object_start(js, "peer_table");
	{
		unsigned int peers_tracked = 0;
		unsigned int peers_with_active_slots = 0;
		for (int i = 0; i < SS_PEER_TABLE_SIZE; i++) {
			if (!ss_peer_table[i].in_use) continue;
			peers_tracked++;
			if (ss_peer_table[i].concurrent_slots > 0)
				peers_with_active_slots++;
		}
		json_add_u32(js, "peers_tracked", peers_tracked);
		json_add_u32(js, "peers_with_active_slots", peers_with_active_slots);
		json_add_u32(js, "table_capacity", SS_PEER_TABLE_SIZE);
	}
	json_object_end(js);

	json_object_start(js, "join_queue_summary");
	{
		unsigned int total_queued = 0, total_accepted = 0;
		unsigned int total_signed = 0, total_rejected = 0;
		unsigned int total_cancelled = 0;
		for (size_t fi_idx = 0; fi_idx < ss_state.n_factories; fi_idx++) {
			factory_instance_t *fi = ss_state.factories[fi_idx];
			if (!fi || !fi->is_lsp) continue;
			for (size_t j = 0; j < fi->n_join_queue; j++) {
				switch (fi->join_queue[j].status) {
				case JOIN_STATUS_QUEUED: total_queued++; break;
				case JOIN_STATUS_ACCEPTED: total_accepted++; break;
				case JOIN_STATUS_SIGNED: total_signed++; break;
				case JOIN_STATUS_REJECTED: total_rejected++; break;
				case JOIN_STATUS_CANCELLED: total_cancelled++; break;
				default: break;
				}
			}
		}
		json_add_u32(js, "queued", total_queued);
		json_add_u32(js, "accepted", total_accepted);
		json_add_u32(js, "signed", total_signed);
		json_add_u32(js, "rejected", total_rejected);
		json_add_u32(js, "cancelled", total_cancelled);
	}
	json_object_end(js);

	json_object_start(js, "outgoing_joins_summary");
	{
		unsigned int total_sent = 0, total_queued_out = 0;
		unsigned int total_accepted_out = 0, total_other = 0;
		for (size_t i = 0; i < ss_state.n_outgoing_joins; i++) {
			switch (ss_state.outgoing_joins[i].status) {
			case OUTGOING_JOIN_SENT: total_sent++; break;
			case OUTGOING_JOIN_QUEUED: total_queued_out++; break;
			case OUTGOING_JOIN_ACCEPTED: total_accepted_out++; break;
			default: total_other++; break;
			}
		}
		json_add_u32(js, "sent", total_sent);
		json_add_u32(js, "queued", total_queued_out);
		json_add_u32(js, "accepted", total_accepted_out);
		json_add_u32(js, "other", total_other);
		json_add_u32(js, "total", (unsigned)ss_state.n_outgoing_joins);
	}
	json_object_end(js);

	return command_finished(cmd, js);
	#undef LIFECYCLE_SLOTS
}

/* factory-close RPC — LSP initiates cooperative close.
 * Splits factory value equally among participants (demo). */
static struct command_result *json_factory_close(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	const char *id_hex;
	factory_instance_t *fi;
	uint8_t instance_id[32];

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id length");

	for (int j = 0; j < 32; j++) {
		unsigned int b;
		sscanf(id_hex + j*2, "%02x", &b);
		instance_id[j] = (uint8_t)b;
	}

	fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");
	if (!fi->is_lsp)
		return command_fail(cmd, LIGHTNINGD, "Only LSP can close");

	factory_t *factory = (factory_t *)fi->lib_factory;
	if (!factory)
		return command_fail(cmd, LIGHTNINGD, "No lib_factory handle");

	secp256k1_context *ctx = global_secp_ctx;
	size_t n_participants = 1 + fi->n_clients;

	/* Build output distribution using the library's balance-aware
	 * function. Falls back to equal split if no client amounts
	 * are provided (NULL). Fee set to 500 sats. */
	tx_output_t outputs[MAX_DIST_OUTPUTS];
	size_t n_outputs = factory_compute_distribution_outputs(
		factory, outputs, MAX_DIST_OUTPUTS, 500);
	if (n_outputs == 0)
		return command_fail(cmd, LIGHTNINGD,
				    "Failed to compute close distribution");

	/* Re-init just node 0 for close signing */
	factory_session_init_node(factory, 0);

	/* Generate LSP nonces */
	unsigned char lsp_seckey[32];
	derive_factory_seckey(lsp_seckey, fi->instance_id, 0);
	memcpy(fi->our_seckey, lsp_seckey, 32);
	fi->our_participant_idx = 0;

	secp256k1_pubkey lsp_pub;
	if (!secp256k1_ec_pubkey_create(ctx, &lsp_pub, lsp_seckey))
		return command_fail(cmd, LIGHTNINGD, "Bad LSP close pubkey");

	if (fi->nonce_pool) free(fi->nonce_pool);
	musig_nonce_pool_t *pool = calloc(1, sizeof(musig_nonce_pool_t));
	musig_nonce_pool_generate(ctx, pool, 1, lsp_seckey, &lsp_pub, NULL);
	fi->nonce_pool = pool;
	fi->n_secnonces = 0;

	secp256k1_musig_secnonce *secnonce;
	secp256k1_musig_pubnonce pubnonce;
	musig_nonce_pool_next(pool, &secnonce, &pubnonce);
	fi->secnonce_pool_idx[0] = 0;
	fi->secnonce_node_idx[0] = 0;
	fi->n_secnonces = 1;
	if (!factory_session_set_nonce(factory, 0, 0, &pubnonce)) {
		plugin_log(plugin_handle, LOG_BROKEN,
			"factory-close: LSP set_nonce(0,0) rejected "
			"(n_signers=%zu collected=%d)",
			factory->nodes[0].n_signers,
			factory->nodes[0].signing_session.nonces_collected);
	}

	/* Build CLOSE_PROPOSE payload:
	 * n_outputs(4) + per output: amount(8) + spk_len(2) + spk(var)
	 * + nonce_bundle */
	uint8_t payload[4096];
	uint8_t *p = payload;
	p[0] = 0; p[1] = 0; p[2] = 0; p[3] = (uint8_t)n_outputs;
	p += 4;
	for (size_t k = 0; k < n_outputs; k++) {
		uint64_t amt = outputs[k].amount_sats;
		p[0] = (amt >> 56) & 0xFF; p[1] = (amt >> 48) & 0xFF;
		p[2] = (amt >> 40) & 0xFF; p[3] = (amt >> 32) & 0xFF;
		p[4] = (amt >> 24) & 0xFF; p[5] = (amt >> 16) & 0xFF;
		p[6] = (amt >> 8) & 0xFF;  p[7] = amt & 0xFF;
		p += 8;
		uint16_t sl = (uint16_t)outputs[k].script_pubkey_len;
		p[0] = (sl >> 8) & 0xFF; p[1] = sl & 0xFF;
		p += 2;
		memcpy(p, outputs[k].script_pubkey, sl);
		p += sl;
	}

	/* Append nonce bundle (heap alloc: 79KB struct) */
	nonce_bundle_t *nb = calloc(1, sizeof(*nb));
	if (!nb)
		return command_fail(cmd, LIGHTNINGD, "nb alloc failed");
	memcpy(nb->instance_id, fi->instance_id, 32);
	nb->n_participants = n_participants;
	nb->n_nodes = 1;
	nb->n_entries = 1;
	nb->entries[0].node_idx = 0;
	nb->entries[0].signer_slot = 0;
	musig_pubnonce_serialize(ctx, nb->entries[0].pubnonce, &pubnonce);

	for (size_t pk = 0; pk < n_participants && pk < MAX_PARTICIPANTS; pk++) {
		unsigned char sk2[32];
		derive_factory_seckey(sk2, fi->instance_id, (int)pk);
		secp256k1_pubkey ppk;
		if (!secp256k1_ec_pubkey_create(ctx, &ppk, sk2))
			continue;
		size_t pklen = 33;
		secp256k1_ec_pubkey_serialize(ctx, nb->pubkeys[pk], &pklen,
			&ppk, SECP256K1_EC_COMPRESSED);
	}

	uint8_t nbuf[MAX_WIRE_BUF];
	size_t nlen = nonce_bundle_serialize(nb, nbuf, sizeof(nbuf));
	free(nb);
	memcpy(p, nbuf, nlen);
	size_t plen = (size_t)(p - payload) + nlen;

	for (size_t ci = 0; ci < fi->n_clients; ci++) {
		char client_hex[67];
		for (int j = 0; j < 33; j++)
			sprintf(client_hex + j*2, "%02x",
				fi->clients[ci].node_id[j]);
		client_hex[66] = '\0';
		send_factory_msg(cmd, client_hex,
			SS_SUBMSG_CLOSE_PROPOSE,
			payload, plen);
	}

	fi->lifecycle = FACTORY_LIFECYCLE_DYING;

	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-close: sent CLOSE_PROPOSE to %zu clients",
		   fi->n_clients);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_string(js, "status", "close_proposed");
	return command_finished(cmd, js);
}

/* factory-rotate RPC — LSP advances DW epoch and re-signs.
 * Takes instance_id of an existing factory. */
static struct command_result *json_factory_rotate(struct command *cmd,
						  const char *buf,
						  const jsmntok_t *params)
{
	const char *id_hex;
	factory_instance_t *fi;
	uint8_t instance_id[32];

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id length");

	for (int j = 0; j < 32; j++) {
		unsigned int b;
		sscanf(id_hex + j*2, "%02x", &b);
		instance_id[j] = (uint8_t)b;
	}

	fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");
	if (!fi->is_lsp)
		return command_fail(cmd, LIGHTNINGD, "Only LSP can rotate");
	if (fi->ceremony != CEREMONY_COMPLETE &&
	    fi->ceremony != CEREMONY_ROTATE_COMPLETE &&
	    fi->ceremony != CEREMONY_REVOKED)
		return command_fail(cmd, LIGHTNINGD,
				    "Factory not in signed state");

	/* Refuse to rotate if we still owe a client the ack for the
	 * previous REVOKE. Advancing now would reveal the NEXT epoch's
	 * secret before we've confirmed the previous one was durably
	 * stored — exactly the race this PR exists to close. Operator
	 * must resolve the pending ack (usually by waiting for the peer
	 * to reconnect so we resend) before calling factory-rotate
	 * again. */
	for (size_t ci = 0; ci < fi->n_clients; ci++) {
		if (fi->clients[ci].pending_revoke_epoch != UINT32_MAX) {
			return command_fail(cmd, LIGHTNINGD,
				"Client %zu has unacked REVOKE for epoch %u. "
				"Rotation blocked until ack received (will "
				"auto-resend on reconnect).",
				ci, fi->clients[ci].pending_revoke_epoch);
		}
	}

	factory_t *factory = (factory_t *)fi->lib_factory;
	if (!factory)
		return command_fail(cmd, LIGHTNINGD, "No lib_factory handle");

	secp256k1_context *ctx = global_secp_ctx;
	uint32_t old_epoch = fi->epoch;

	/* If secrets aren't loaded (e.g. factory was reloaded from datastore
	 * after a restart), regenerate them deterministically from HSM so
	 * the L-stock hashes match what went on-chain at factory creation. */
	if (factory->n_revocation_secrets == 0) {
		if (ss_state.has_master_key) {
			static unsigned char secrets[256][32];
			derive_l_stock_secrets(secrets, 256, fi->instance_id);
			factory_set_flat_secrets(factory,
				(const unsigned char (*)[32])secrets, 256);
		} else {
			factory_generate_flat_secrets(factory, 256);
		}
	}

	/* Check proximity to exhaustion before advancing */
	if (fi->max_epochs > 0 && fi->epoch >= fi->max_epochs - 1) {
		return command_fail(cmd, LIGHTNINGD,
			"DW epoch exhausted (%u/%u). Call factory-migrate "
			"to move channels to a new factory.",
			fi->epoch, fi->max_epochs);
	}
	if (fi->max_epochs > 0 && fi->epoch >= fi->max_epochs - 5) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "Factory %s: epoch %u/%u — approaching exhaustion, "
			   "schedule factory-migrate soon",
			   id_hex, fi->epoch, fi->max_epochs);
	}

	/* Phase 2b: snapshot current epoch's kickoff witness sig BEFORE
	 * advancing the counter. Used later to classify a spending TX
	 * as breach vs normal-exit. */
	ss_snapshot_current_epoch_kickoff_sig(fi);

	/* Advance the DW counter */
	if (!dw_counter_advance(&factory->counter)) {
		return command_fail(cmd, LIGHTNINGD,
				    "DW counter exhausted, cannot rotate");
	}
	fi->epoch = dw_counter_epoch(&factory->counter);

	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-rotate: epoch %u → %u",
		   old_epoch, fi->epoch);

	/* Rebuild all node transactions for new epoch.
	 * The kickoff (node 0) is re-signed but its txid stays stable:
	 * segwit txid = hash of non-witness data, and the kickoff's
	 * non-witness data never changes (same funding input, same output
	 * P2TR key, same nSequence=0xFFFFFFFF). All epoch state TXs
	 * reference the same kickoff txid — DW timelock race works. */
	for (size_t ni = 0; ni < factory->n_nodes; ni++) {
		if (!factory_rebuild_node_tx(factory, ni)) {
			plugin_log(plugin_handle, LOG_BROKEN,
				   "factory-rotate: rebuild node %zu failed", ni);
			return command_fail(cmd, LIGHTNINGD,
					    "Failed to rebuild tree");
		}
	}

	/* Reset PS chain state on every PS leaf. Rotation rebuilds the
	 * tree at a new epoch — the new state TXs supersede whatever PS
	 * chain we had advanced to in the old epoch. Without this reset,
	 * the next factory-ps-advance would increment ps_chain_len past
	 * the old value (e.g., chain_pos=3 instead of 1) and the persisted
	 * chain[0] from ss_save_all_ps_chain0 would no longer match the
	 * lib_factory's view. Upstream factory.c doesn't expose a reset
	 * helper for PS leaves, so do it inline. */
	for (size_t ni = 0; ni < factory->n_nodes; ni++) {
		factory_node_t *nd = &factory->nodes[ni];
		if (!nd->is_ps_leaf) continue;
		nd->ps_chain_len = 0;
		memset(nd->ps_prev_txid, 0, 32);
		nd->ps_prev_chan_amount = 0;
	}

	/* Re-initialize signing sessions */
	if (!factory_sessions_init(factory))
		return command_fail(cmd, LIGHTNINGD,
				    "Failed to reinit signing sessions");

	/* Generate new nonces (same flow as factory-create) */
	unsigned char lsp_seckey[32];
	derive_factory_seckey(lsp_seckey, fi->instance_id, 0);

	size_t n_participants = 1 + fi->n_clients;
	secp256k1_pubkey *pubkeys = calloc(n_participants,
					   sizeof(secp256k1_pubkey));
	for (size_t k = 0; k < n_participants; k++) {
		unsigned char sk[32];
		derive_factory_seckey(sk, fi->instance_id, (int)k);
		if (!secp256k1_ec_pubkey_create(ctx, &pubkeys[k], sk)) {
			free(pubkeys);
			return command_fail(cmd, LIGHTNINGD,
					    "Bad rotate pubkey");
		}
	}

	/* Store seckey for signing */
	memcpy(fi->our_seckey, lsp_seckey, 32);
	fi->our_participant_idx = 0;
	fi->n_secnonces = 0;

	/* Free old nonce pool if any */
	if (fi->nonce_pool) {
		free(fi->nonce_pool);
		fi->nonce_pool = NULL;
	}

	size_t lsp_node_count = factory_count_nodes_for_participant(factory, 0);
	musig_nonce_pool_t *pool = calloc(1, sizeof(musig_nonce_pool_t));
	if (!musig_nonce_pool_generate(ctx, pool, lsp_node_count,
				       lsp_seckey, &pubkeys[0], NULL)) {
		free(pool);
		free(pubkeys);
		return command_fail(cmd, LIGHTNINGD,
				    "Failed to generate nonce pool");
	}
	fi->nonce_pool = pool;

	/* Build nonce bundle for rotation (heap alloc: 79KB struct) */
	nonce_bundle_t *nb = calloc(1, sizeof(*nb));
	if (!nb)
		return command_fail(cmd, LIGHTNINGD, "nb alloc failed");
	memcpy(nb->instance_id, fi->instance_id, 32);
	nb->n_participants = n_participants;
	nb->n_nodes = factory->n_nodes;
	nb->n_entries = 0;

	for (size_t pk = 0; pk < n_participants && pk < MAX_PARTICIPANTS; pk++) {
		size_t pklen = 33;
		secp256k1_ec_pubkey_serialize(ctx,
			nb->pubkeys[pk], &pklen,
			&pubkeys[pk], SECP256K1_EC_COMPRESSED);
	}

	size_t pool_entry = 0;
	for (size_t ni = 0; ni < factory->n_nodes; ni++) {
		int slot = factory_find_signer_slot(factory, ni, 0);
		if (slot < 0) continue;

		secp256k1_musig_secnonce *secnonce;
		secp256k1_musig_pubnonce pubnonce;
		if (!musig_nonce_pool_next(pool, &secnonce, &pubnonce))
			break;

		fi->secnonce_pool_idx[fi->n_secnonces] = pool_entry;
		fi->secnonce_node_idx[fi->n_secnonces] = ni;
		fi->n_secnonces++;
		pool_entry++;

		factory_session_set_nonce(factory, ni, (size_t)slot, &pubnonce);
		musig_pubnonce_serialize(ctx,
			nb->entries[nb->n_entries].pubnonce, &pubnonce);
		nb->entries[nb->n_entries].node_idx = ni;
		nb->entries[nb->n_entries].signer_slot = slot;
		nb->n_entries++;
	}

	/* Cache LSP rotation nonces for ALL_NONCES round (3+ party) */
	if (fi->cached_nonces) free(fi->cached_nonces);
	fi->cached_nonces_cap = MAX_NONCE_ENTRIES;
	fi->cached_nonces = calloc(fi->cached_nonces_cap,
		sizeof(nonce_entry_t));
	fi->n_cached_nonces = 0;
	if (fi->cached_nonces && nb->n_entries <= fi->cached_nonces_cap) {
		memcpy(fi->cached_nonces, nb->entries,
		       nb->n_entries * sizeof(nonce_entry_t));
		fi->n_cached_nonces = nb->n_entries;
	}

	/* Serialize and send ROTATE_PROPOSE to all clients.
	 * Payload: [4 bytes: old_epoch] [4 bytes: new_epoch] + nonce_bundle */
	uint8_t nbuf[MAX_WIRE_BUF];
	size_t nlen = nonce_bundle_serialize(nb, nbuf, sizeof(nbuf));
	free(nb);

	/* Prepend epoch info: old(4) + new(4) + bundle */
	uint8_t payload[8 + MAX_WIRE_BUF];
	payload[0] = (old_epoch >> 24) & 0xFF;
	payload[1] = (old_epoch >> 16) & 0xFF;
	payload[2] = (old_epoch >> 8) & 0xFF;
	payload[3] = old_epoch & 0xFF;
	payload[4] = (fi->epoch >> 24) & 0xFF;
	payload[5] = (fi->epoch >> 16) & 0xFF;
	payload[6] = (fi->epoch >> 8) & 0xFF;
	payload[7] = fi->epoch & 0xFF;
	memcpy(payload + 8, nbuf, nlen);
	size_t plen = 8 + nlen;

	/* Cache the ROTATE_PROPOSE payload for reconnect recovery. If a
	 * client drops after receiving ROTATE_PROPOSE but before replying
	 * with ROTATE_NONCE, the peer_connected handler resends this blob
	 * so rotation doesn't wedge. Freed when rotation completes. */
	if (fi->cached_rotate_propose_wire) {
		free(fi->cached_rotate_propose_wire);
		fi->cached_rotate_propose_wire = NULL;
		fi->cached_rotate_propose_len = 0;
	}
	fi->cached_rotate_propose_wire = malloc(plen);
	if (fi->cached_rotate_propose_wire) {
		memcpy(fi->cached_rotate_propose_wire, payload, plen);
		fi->cached_rotate_propose_len = plen;
	}

	for (size_t ci = 0; ci < fi->n_clients; ci++) {
		char client_hex[67];
		for (int j = 0; j < 33; j++)
			sprintf(client_hex + j*2, "%02x",
				fi->clients[ci].node_id[j]);
		client_hex[66] = '\0';
		send_factory_msg(cmd, client_hex,
			SS_SUBMSG_ROTATE_PROPOSE,
			payload, plen);
	}

	/* Reset ceremony tracking for rotation */
	ss_factory_reset_ceremony(fi);
	fi->ceremony = CEREMONY_ROTATING;

	free(pubkeys);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "old_epoch", old_epoch);
	json_add_u32(js, "new_epoch", fi->epoch);
	json_add_string(js, "ceremony", "rotating");
	return command_finished(cmd, js);
}

/* factory-ps-advance RPC — Tier 2.6: advance a PS leaf's chain by one TX.
 *
 * Kicks off a 2-of-2 MuSig2 ceremony between the LSP and the single client
 * mapped to `leaf_side`. Mirrors upstream lsp_advance_leaf. Returns
 * immediately with "proposed" status; completion happens asynchronously
 * when LEAF_ADVANCE_PSIG arrives via custommsg.
 *
 * Only valid for factories with arity_mode=arity_ps (ARITY_PS leaves).
 * DW-leaf advance (ARITY_1) uses the same wire format but isn't exposed
 * via this RPC — the DW advance path is driven internally by rotation. */
static struct command_result *json_factory_ps_advance(struct command *cmd,
						      const char *buf,
						      const jsmntok_t *params)
{
	const char *id_hex;
	uint32_t *leaf_side_p;
	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_req("leaf_side", param_u32, &leaf_side_p),
		   NULL))
		return command_param_failed();

	/* Parse instance_id hex */
	uint8_t instance_id[32];
	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD,
			"instance_id must be 64 hex chars");
	for (int i = 0; i < 32; i++) {
		unsigned int b;
		if (sscanf(id_hex + i*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
				"instance_id not hex");
		instance_id[i] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD,
			"factory %s not found", id_hex);
	if (!fi->is_lsp)
		return command_fail(cmd, LIGHTNINGD,
			"factory-ps-advance is LSP-only");
	/* Gate on ceremony state, not lifecycle. A just-created factory
	 * stays in lifecycle=INIT until its funding TX confirms; PS
	 * advance is purely off-chain so it's valid as soon as the tree
	 * is signed (ceremony=COMPLETE) and up until close starts. */
	if (fi->ceremony != CEREMONY_COMPLETE &&
	    fi->ceremony != CEREMONY_ROTATE_COMPLETE &&
	    fi->ceremony != CEREMONY_REVOKED)
		return command_fail(cmd, LIGHTNINGD,
			"factory not in signed state (ceremony=%d)",
			fi->ceremony);
	if (factory_is_closed(fi->lifecycle))
		return command_fail(cmd, LIGHTNINGD,
			"factory is closed (lifecycle=%d)", fi->lifecycle);
	if (fi->rotation_in_progress)
		return command_fail(cmd, LIGHTNINGD,
			"factory rotation in progress — retry after completion");
	if (ss_effective_arity(fi) != FACTORY_ARITY_PS)
		return command_fail(cmd, LIGHTNINGD,
			"factory arity is not ARITY_PS (got %d)",
			(int)ss_effective_arity(fi));
	if (fi->ps_pending_leaf != -1)
		return command_fail(cmd, LIGHTNINGD,
			"another PS advance in flight on leaf %d",
			fi->ps_pending_leaf);

	factory_t *f = (factory_t *)fi->lib_factory;
	if (!f)
		return command_fail(cmd, LIGHTNINGD,
			"factory_t not initialized (ceremony incomplete?)");

	uint32_t leaf_side = *leaf_side_p;
	if ((int)leaf_side < 0 || (int)leaf_side >= f->n_leaf_nodes)
		return command_fail(cmd, LIGHTNINGD,
			"leaf_side %u out of range [0,%d)",
			leaf_side, f->n_leaf_nodes);

	size_t node_idx = f->leaf_node_indices[leaf_side];
	factory_node_t *node = &f->nodes[node_idx];
	if (!node->is_ps_leaf)
		return command_fail(cmd, LIGHTNINGD,
			"leaf_side %u is not a PS leaf", leaf_side);

	/* Step 1: Advance leaf state + rebuild unsigned TX.
	 * Upstream caller contract (test_factory_ps_dust_limit): rc=0 means
	 * the next chain TX's channel output would fall below the dust limit;
	 * ps_chain_len is already incremented — caller MUST NOT persist or
	 * broadcast. Surface as an error without touching state. */
	int rc = factory_advance_leaf_unsigned(f, (int)leaf_side);
	if (rc == 0) {
		plugin_log(plugin_handle, LOG_INFORM,
			"SS_METRIC event=ps_exhausted iid=%s leaf=%u "
			"chain_len=%d reason=dust_limit",
			id_hex, leaf_side, node->ps_chain_len);
		return command_fail(cmd, LIGHTNINGD,
			"PS leaf %u exhausted (dust limit); factory migration "
			"required", leaf_side);
	}
	if (rc < 0)
		return command_fail(cmd, LIGHTNINGD,
			"factory_advance_leaf_unsigned failed (rc=%d)", rc);

	/* Step 2: init signing session for this node */
	if (!factory_session_init_node(f, node_idx))
		return command_fail(cmd, LIGHTNINGD,
			"session_init_node failed");

	/* Step 3: find LSP's signer slot (participant 0) */
	int lsp_slot = factory_find_signer_slot(f, node_idx, 0);
	if (lsp_slot < 0)
		return command_fail(cmd, LIGHTNINGD,
			"LSP not a signer on node %zu", node_idx);

	/* Step 4: generate LSP secnonce + pubnonce */
	secp256k1_musig_secnonce *lsp_secnonce =
		calloc(1, sizeof(secp256k1_musig_secnonce));
	if (!lsp_secnonce)
		return command_fail(cmd, LIGHTNINGD, "OOM (secnonce)");

	secp256k1_musig_pubnonce lsp_pubnonce;
	secp256k1_pubkey lsp_pub;
	if (!secp256k1_ec_pubkey_create(global_secp_ctx, &lsp_pub,
					fi->our_seckey)) {
		free(lsp_secnonce);
		return command_fail(cmd, LIGHTNINGD, "LSP pubkey derive failed");
	}
	if (!musig_generate_nonce(global_secp_ctx, lsp_secnonce, &lsp_pubnonce,
				  fi->our_seckey, &lsp_pub,
				  &node->keyagg.cache)) {
		free(lsp_secnonce);
		return command_fail(cmd, LIGHTNINGD, "nonce gen failed");
	}
	if (!factory_session_set_nonce(f, node_idx, (size_t)lsp_slot,
				       &lsp_pubnonce)) {
		free(lsp_secnonce);
		return command_fail(cmd, LIGHTNINGD, "set_nonce failed");
	}

	/* Serialize LSP pubnonce for wire */
	uint8_t lsp_pubnonce_ser[66];
	musig_pubnonce_serialize(global_secp_ctx, lsp_pubnonce_ser,
				 &lsp_pubnonce);

	/* Stash pending state */
	fi->ps_pending_leaf = (int32_t)leaf_side;
	fi->ps_pending_node_idx = (uint32_t)node_idx;
	fi->ps_pending_secnonce = lsp_secnonce;
	fi->ps_pending_start_block = ss_state.current_blockheight;

	/* Step 5: send PROPOSE to the affected client */
	if ((size_t)leaf_side >= fi->n_clients) {
		ss_clear_ps_pending(fi);
		return command_fail(cmd, LIGHTNINGD,
			"leaf_side %u has no client mapping", leaf_side);
	}
	char client_hex[67];
	for (int j = 0; j < 33; j++)
		sprintf(client_hex + j*2, "%02x",
			fi->clients[leaf_side].node_id[j]);
	client_hex[66] = '\0';

	uint8_t payload[102];
	size_t plen = ss_leaf_advance_propose_build(payload, sizeof(payload),
						    fi->instance_id, leaf_side,
						    lsp_pubnonce_ser);
	if (plen == 0) {
		ss_clear_ps_pending(fi);
		return command_fail(cmd, LIGHTNINGD,
			"PROPOSE build failed (buffer)");
	}

	send_factory_msg(cmd, client_hex, SS_SUBMSG_LEAF_ADVANCE_PROPOSE,
			 payload, plen);

	/* Cache the PROPOSE payload + target client pid for reconnect
	 * resume. If the client drops between PROPOSE and PSIG, the
	 * peer_connected handler resends this payload so the ceremony
	 * doesn't wedge. Freed in ss_clear_ps_pending. */
	if (fi->cached_ps_propose_wire) {
		free(fi->cached_ps_propose_wire);
	}
	fi->cached_ps_propose_wire = malloc(plen);
	if (fi->cached_ps_propose_wire) {
		memcpy(fi->cached_ps_propose_wire, payload, plen);
		fi->cached_ps_propose_len = plen;
		memcpy(fi->cached_ps_propose_target_pid,
		       fi->clients[leaf_side].node_id, 33);
	}

	plugin_log(plugin_handle, LOG_INFORM,
		"SS_METRIC event=ps_advance_propose iid=%s leaf=%u "
		"chain_pos=%d",
		id_hex, leaf_side, node->ps_chain_len);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "leaf_side", leaf_side);
	json_add_u32(js, "chain_pos", (uint32_t)node->ps_chain_len);
	json_add_string(js, "status", "proposed");
	return command_finished(cmd, js);
}

/* factory-force-close RPC — broadcast signed DW tree for unilateral close.
 * Extracts signed txs from factory nodes and sends via sendrawtransaction. */
static struct command_result *json_factory_force_close(struct command *cmd,
						       const char *buf,
						       const jsmntok_t *params)
{
	const char *id_hex;
	factory_instance_t *fi;
	uint8_t instance_id[32];

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id length");

	for (int j = 0; j < 32; j++) {
		unsigned int b;
		sscanf(id_hex + j*2, "%02x", &b);
		instance_id[j] = (uint8_t)b;
	}

	fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	factory_t *factory = (factory_t *)fi->lib_factory;
	if (!factory)
		return command_fail(cmd, LIGHTNINGD, "No lib_factory handle");

	/* Extract and broadcast signed transactions.
	 * DW tree: kickoff first, then state nodes in order. */
	size_t broadcast_count = 0;
	for (size_t ni = 0; ni < factory->n_nodes; ni++) {
		if (!factory->nodes[ni].is_signed) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "force-close: node %zu not signed, skipping",
				   ni);
			continue;
		}

		/* Tier 2.6: for PS leaves, broadcast chain[0..N-1] from
		 * datastore before the factory_t's current chain[N] signed_tx.
		 * Each chain TX spends the previous one's channel output, so
		 * ordering matters for mempool acceptance. */
		if (factory->nodes[ni].is_ps_leaf &&
		    factory->nodes[ni].ps_chain_len > 0) {
			int current_pos = factory->nodes[ni].ps_chain_len;
			for (int cp = 0; cp < current_pos; cp++) {
				/* Task #84: PS chain replay disabled. The
				 * legacy datastore key is gone but wallet.db
				 * doesn't yet store PS chain entries. PS leaves
				 * will not force-close their chain correctly
				 * across restart until the migration lands. */
				u8 *pdata = NULL;
				if (!pdata) {
					plugin_log(plugin_handle, LOG_UNUSUAL,
						"force-close: PS chain[%d] replay "
						"disabled (Task #84 follow-up) for "
						"leaf node %zu",
						cp, ni);
					continue;
				}
				size_t plen = 0;
				uint8_t etxid[32];
				uint64_t eamt;
				uint8_t *etx = NULL;
				size_t etx_len = 0;
				if (!ss_persist_deserialize_ps_chain_entry(
					pdata, plen, etxid, &eamt,
					&etx, &etx_len) || !etx || etx_len == 0) {
					free(etx);
					continue;
				}
				char *etx_hex = tal_arr(cmd, char, etx_len * 2 + 1);
				for (size_t h = 0; h < etx_len; h++)
					sprintf(etx_hex + h*2, "%02x", etx[h]);
				plugin_log(plugin_handle, LOG_INFORM,
					"force-close: PS chain[%d] for leaf "
					"node %zu (%zu bytes)",
					cp, ni, etx_len);
				ss_broadcast_factory_tx(cmd, fi, etx_hex,
							FACTORY_TX_STATE);
				free(etx);
				broadcast_count++;
			}
		}

		tx_buf_t *stx = &factory->nodes[ni].signed_tx;
		if (!stx->data || stx->len == 0)
			continue;

		/* Convert to hex for sendrawtransaction */
		char *tx_hex = tal_arr(cmd, char, stx->len * 2 + 1);
		for (size_t h = 0; h < stx->len; h++)
			sprintf(tx_hex + h*2, "%02x", stx->data[h]);

		/* Store txid for breach monitoring */
		char txid_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(txid_hex + j*2, "%02x",
				factory->nodes[ni].txid[31 - j]);

		plugin_log(plugin_handle, LOG_INFORM,
			   "force-close: node %zu "
			   "(%s, %zu bytes, txid=%s)",
			   ni,
			   factory->nodes[ni].type == 0 ? "kickoff" : "state",
			   stx->len, txid_hex);

		/* Broadcast via classified wrapper — each broadcast gets its
		 * own aux_command so replies survive this RPC's lifetime and
		 * the classifier can refine lifecycle on -25/-26/-27 replies. */
		ss_broadcast_factory_tx(cmd, fi, tx_hex,
					ni == 0 ? FACTORY_TX_KICKOFF
						: FACTORY_TX_STATE);

		/* Phase 3c2.5d coverage fix: register for CPFP monitoring
		 * here too. Phase 3c2.5d wired registration at block_added's
		 * DYING cascade and at breach_utxo_checked, but NOT at this
		 * direct operator-triggered site. When operator calls
		 * factory-force-close, kickoff/state TXs get broadcast but
		 * no block_added auto-fires in a test harness — so CPFP
		 * monitoring would never start. Register explicitly here. */
		{
			tx_buf_t *ntx = &factory->nodes[ni].signed_tx;
			int anchor_vout =
				ss_find_p2a_vout(ntx->data, ntx->len);
			if (anchor_vout >= 0) {
				uint8_t tx_txid[32];
				struct sha256 h1, h2;
				sha256(&h1, ntx->data, ntx->len);
				sha256(&h2, &h1, sizeof(h1));
				memcpy(tx_txid, &h2, 32);
				uint64_t value = factory->nodes[ni].n_outputs > 0
					? factory->nodes[ni].outputs[0].amount_sats
					: fi->funding_amount_sats;
				ss_register_pending_cpfp(fi,
					ni == 0 ? CPFP_PARENT_KICKOFF
						: CPFP_PARENT_STATE,
					tx_txid, (uint32_t)anchor_vout,
					value, fi->expiry_block,
					ss_state.current_blockheight);
			}
		}

		plugin_log(plugin_handle, LOG_INFORM,
			   "force-close: broadcast node %zu (txid=%s)",
			   ni, txid_hex);
		broadcast_count++;
	}

	fi->lifecycle = FACTORY_LIFECYCLE_DYING;

	/* Force-close all LN channels in this factory */
	for (size_t ch = 0; ch < fi->n_channels; ch++) {
		char cid_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(cid_hex + j*2, "%02x",
				fi->channels[ch].channel_id[j]);
		struct out_req *creq = jsonrpc_request_start(
			cmd, "close",
			rpc_done, rpc_err, fi);
		json_add_string(creq->js, "id", cid_hex);
		json_add_u32(creq->js, "unilateraltimeout", 1);
		send_outreq(creq);
		plugin_log(plugin_handle, LOG_INFORM,
			   "force-close: closing channel %zu", ch);
	}

	plugin_log(plugin_handle, LOG_INFORM,
		   "force-close: %zu signed transactions ready",
		   broadcast_count);

	/* Store signed TX data for cascade rebroadcast on each block.
	 * Child nodes fail if parent isn't confirmed yet — block_added
	 * will retry. */
	fi->rotation_in_progress = false; /* reuse flag for cascade */

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u64(js, "n_signed_txs", broadcast_count);
	json_add_string(js, "status", "force_close_broadcast");
	json_add_string(js, "note",
		"DW tree nodes broadcast in order. Child nodes may fail "
		"until parent confirms. Re-run force-close or wait for "
		"block_added to retry automatically.");

	/* Include raw txs for manual broadcast */
	json_array_start(js, "transactions");
	for (size_t ni = 0; ni < factory->n_nodes; ni++) {
		if (!factory->nodes[ni].is_signed) continue;
		tx_buf_t *stx = &factory->nodes[ni].signed_tx;
		if (!stx->data || stx->len == 0) continue;

		char *tx_hex = tal_arr(cmd, char, stx->len * 2 + 1);
		for (size_t h = 0; h < stx->len; h++)
			sprintf(tx_hex + h*2, "%02x", stx->data[h]);

		char txid_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(txid_hex + j*2, "%02x",
				factory->nodes[ni].txid[31 - j]);

		json_object_start(js, NULL);
		json_add_u32(js, "node_idx", ni);
		json_add_string(js, "type",
			factory->nodes[ni].type == 0 ? "kickoff" : "state");
		json_add_string(js, "txid", txid_hex);
		json_add_string(js, "raw_tx", tx_hex);
		json_add_u64(js, "tx_len", stx->len);
		json_object_end(js);
	}
	json_array_end(js);
	return command_finished(cmd, js);
}

/* factory-close-departed RPC — use extracted keys to cooperatively
 * close a departed client's channel. After key turnover, the LSP
 * holds both signing keys and can produce a valid cooperative close
 * without the departed client being online. */
static struct command_result *json_factory_close_departed(struct command *cmd,
							   const char *buf,
							   const jsmntok_t *params)
{
	const char *id_hex;
	u32 *client_idx;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_req("client_idx", param_u32, &client_idx),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id length");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		sscanf(id_hex + j*2, "%02x", &b);
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");
	if (!fi->is_lsp)
		return command_fail(cmd, LIGHTNINGD, "Only LSP can close departed");
	if (*client_idx >= fi->n_clients)
		return command_fail(cmd, LIGHTNINGD, "Invalid client_idx");
	if (!fi->client_departed[*client_idx])
		return command_fail(cmd, LIGHTNINGD,
			"Client %u has not departed (no extracted key)",
			*client_idx);

	/* We have the departed client's secret key. Build a cooperative
	 * close: sign with both our key and theirs. */
	factory_t *factory = (factory_t *)fi->lib_factory;
	if (!factory)
		return command_fail(cmd, LIGHTNINGD, "No lib_factory handle");

	/* Find the leaf node for this client */
	int leaf_idx = factory_find_leaf_for_client(factory,
						    (int)(*client_idx + 1));
	if (leaf_idx < 0)
		return command_fail(cmd, LIGHTNINGD,
			"No leaf found for client %u", *client_idx);

	/* Create keypair from extracted key for signing */
	secp256k1_keypair departed_kp;
	if (!secp256k1_keypair_create(global_secp_ctx, &departed_kp,
				      fi->extracted_keys[*client_idx]))
		return command_fail(cmd, LIGHTNINGD,
			"Bad extracted key for client %u", *client_idx);

	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-close-departed: client %u, leaf_idx=%d, "
		   "signing with extracted key",
		   *client_idx, leaf_idx);

	/* Forget the channel from CLN (no commitment broadcast needed —
	 * the factory protocol handles fund recovery) */
	for (size_t ch = 0; ch < fi->n_channels; ch++) {
		if (fi->channels[ch].leaf_index == leaf_idx) {
			char cid_hex[65];
			for (int j = 0; j < 32; j++)
				sprintf(cid_hex + j*2, "%02x",
					fi->channels[ch].channel_id[j]);
			char peer_nid[67];
			for (int j = 0; j < 33; j++)
				sprintf(peer_nid + j*2, "%02x",
					fi->clients[*client_idx].node_id[j]);
			peer_nid[66] = '\0';
			struct out_req *creq = jsonrpc_request_start(
				cmd, "dev-forget-channel",
				rpc_done, rpc_err, fi);
			json_add_string(creq->js, "id", peer_nid);
			json_add_string(creq->js, "channel_id", cid_hex);
			send_outreq(creq);
			plugin_log(plugin_handle, LOG_INFORM,
				   "factory-close-departed: forgetting "
				   "channel %zu for departed client %u",
				   ch, *client_idx);
		}
	}

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "client_idx", *client_idx);
	json_add_u32(js, "leaf_index", leaf_idx);
	json_add_bool(js, "key_available", true);
	json_add_string(js, "status", "departed_channel_forgotten");
	return command_finished(cmd, js);
}

/* factory-close-departed registered in commands[] array below */

/* Phase 2a: spending-TX identification.
 *
 * When Phase 1 detects the factory root spent via checkutxo, we want
 * more than just "something happened." The classifier below walks
 * recent blocks looking for the specific TX that spent our funding
 * outpoint, then matches the spending TX's txid against our own
 * signed artifacts to decide whether this was a self-initiated close
 * (closed_by = SELF, lifecycle upgrades to CLOSED_UNILATERAL) or
 * something we didn't drive (closed_by = COUNTERPARTY, lifecycle
 * remains CLOSED_EXTERNALLY; Phase 2b will further distinguish
 * counterparty-normal from breach via tree reconstruction).
 *
 * Scan mechanics: getblockhash(height) → getblock(hash, 2), iterate
 * txs, check each vin for (funding_txid, funding_outnum). Scan walks
 * backwards from first_noticed_block for up to scan_window blocks.
 * Missing the window just leaves the factory in CLOSED_EXTERNALLY
 * with closed_by = UNKNOWN — safe default, operator can re-trigger
 * with a wider window via factory-scan-external-close. */

struct spending_tx_scan_ctx {
	factory_instance_t *fi;
	uint32_t scan_height;        /* block currently being examined */
	uint32_t scan_remaining;     /* blocks left to check after this one */
};

static struct command_result *scan_tx_blockhash_cb(struct command *cmd,
						   const char *method,
						   const char *buf,
						   const jsmntok_t *result,
						   void *arg);
static struct command_result *scan_tx_block_cb(struct command *cmd,
					       const char *method,
					       const char *buf,
					       const jsmntok_t *result,
					       void *arg);
static struct command_result *scan_tx_rpc_err(struct command *cmd,
					      const char *method,
					      const char *buf,
					      const jsmntok_t *result,
					      void *arg);

/* Send a getblockhash request for ctx->scan_height; callback walks the
 * block, decrements scan_remaining, or stops on match. */
static void request_blockhash_for_scan(struct command *cmd,
				       struct spending_tx_scan_ctx *ctx)
{
	struct out_req *req = jsonrpc_request_start(cmd, "getblockhash",
		scan_tx_blockhash_cb, scan_tx_rpc_err, ctx);
	json_add_u32(req->js, "height", ctx->scan_height);
	send_outreq(req);
}

/* Classify a factory based on the spending TX we just identified.
 *
 * Phase 2b rewrite. Order of tests:
 *   1. spending_txid == dist_signed_txid → CLOSED_COOPERATIVE
 *   2. spending_txid == kickoff txid (stable across epochs) → factory-exit
 *      was initiated by counterparty (lifecycle was ACTIVE when Phase 1
 *      fired, so it wasn't us). Use witness_sig to resolve the epoch:
 *        - matches current lib_factory kickoff sig → CLOSED_UNILATERAL
 *        - matches a past epoch's stored sig → CLOSED_BREACHED
 *          (breach_epoch populated for Phase 3's penalty pathway)
 *        - no match (or no witness_sig available) → CLOSED_UNILATERAL
 *          with breach_epoch = UINT32_MAX; best-effort, Phase 3 may
 *          refine via state-TX observation
 *   3. else → CLOSED_EXTERNALLY (genuine external)
 *
 * Must be called after fi->spending_txid is populated. witness_sig may
 * be NULL (or all-zero) if not extractable from the spending TX —
 * classifier degrades gracefully to txid-only matching.
 */
static void ss_classify_spending_tx(factory_instance_t *fi,
				    const uint8_t *witness_sig /* 64 bytes or NULL */)
{
	char txid_hex[65];
	for (int j = 0; j < 32; j++)
		sprintf(txid_hex + j*2, "%02x", fi->spending_txid[31-j]);
	txid_hex[64] = '\0';

	/* Test 1: cooperative close match. */
	bool any_dist = false;
	for (int b = 0; b < 32; b++)
		if (fi->dist_signed_txid[b]) { any_dist = true; break; }
	if (any_dist && memcmp(fi->spending_txid,
			       fi->dist_signed_txid, 32) == 0) {
		fi->closed_by = CLOSED_BY_UNKNOWN; /* coop — either side could have broadcast */
		fi->lifecycle = FACTORY_LIFECYCLE_CLOSED_COOPERATIVE;
		plugin_log(plugin_handle, LOG_INFORM,
			   "Classifier: factory root spent by cooperative "
			   "distribution TX %s → CLOSED_COOPERATIVE.",
			   txid_hex);
		return;
	}

	/* Test 2: kickoff-txid match (stable across epochs). */
	factory_t *f = (factory_t *)fi->lib_factory;
	bool kickoff_match = false;
	if (f && f->n_nodes > 0 &&
	    memcmp(fi->spending_txid, f->nodes[0].txid, 32) == 0)
		kickoff_match = true;

	if (kickoff_match) {
		fi->closed_by = CLOSED_BY_COUNTERPARTY; /* we didn't initiate — lifecycle was ACTIVE */

		/* Test 2a: witness available → try to identify the epoch. */
		bool have_sig = false;
		if (witness_sig) {
			for (int b = 0; b < 64; b++)
				if (witness_sig[b]) { have_sig = true; break; }
		}

		if (have_sig) {
			/* Compare to current-epoch live sig. */
			uint8_t cur_sig[64]; bool cur_ok = false;
			if (f && f->nodes[0].signed_tx.data
			    && f->nodes[0].signed_tx.len > 0) {
				uint8_t tmp_txid[32];
				bool hw = false;
				if (ss_parse_tx(f->nodes[0].signed_tx.data,
						f->nodes[0].signed_tx.len,
						tmp_txid, cur_sig, &hw)
				    && hw) {
					bool any = false;
					for (int b = 0; b < 64; b++)
						if (cur_sig[b]) { any = true; break; }
					cur_ok = any;
				}
			}
			if (cur_ok && memcmp(witness_sig, cur_sig, 64) == 0) {
				fi->lifecycle = FACTORY_LIFECYCLE_CLOSED_UNILATERAL;
				fi->breach_epoch = UINT32_MAX;
				plugin_log(plugin_handle, LOG_INFORM,
					   "Classifier: factory root spent by "
					   "kickoff at CURRENT epoch %u → "
					   "CLOSED_UNILATERAL (counterparty "
					   "normal exit).",
					   fi->epoch);
				return;
			}

			/* Compare to stored past-epoch sigs — any match is
			 * a breach at that epoch. */
			for (size_t i = 0; i < fi->n_history_kickoff_sigs; i++) {
				if (memcmp(witness_sig,
					   fi->history_kickoff_sigs[i], 64) == 0) {
					fi->lifecycle = FACTORY_LIFECYCLE_CLOSED_BREACHED;
					fi->breach_epoch =
						fi->history_kickoff_epochs[i];
					plugin_log(plugin_handle, LOG_BROKEN,
						   "BREACH CLASSIFIED: factory "
						   "root spent by kickoff from "
						   "REVOKED epoch %u (current %u). "
						   "CLOSED_BREACHED. Phase 3 will "
						   "broadcast penalty TXs when "
						   "the leaf state TXs confirm.",
						   fi->breach_epoch, fi->epoch);
					/* Phase 5c structured marker. */
					char biid[65];
					for (int b = 0; b < 32; b++)
						sprintf(biid + b*2, "%02x",
							fi->instance_id[b]);
					biid[64] = '\0';
					plugin_log(plugin_handle, LOG_INFORM,
						   "SS_METRIC event=factory_breached "
						   "iid=%s breach_epoch=%u current_epoch=%u",
						   biid, fi->breach_epoch, fi->epoch);
					return;
				}
			}

			/* Witness extraction succeeded but matches no known
			 * epoch. Possibilities: factory was rotated before
			 * Phase 2b shipped (no history cached); ambiguous
			 * pre-fix state. Label as UNILATERAL but flag
			 * breach_epoch as unknown. */
			fi->lifecycle = FACTORY_LIFECYCLE_CLOSED_UNILATERAL;
			fi->breach_epoch = UINT32_MAX;
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "Classifier: kickoff published, witness sig "
				   "doesn't match current or any cached past "
				   "epoch. Factory likely rotated before Phase 2b "
				   "shipped. Labeling CLOSED_UNILATERAL without "
				   "epoch; Phase 3 may refine via state-TX "
				   "observation.");
			return;
		}

		/* No witness available (couldn't extract). */
		fi->lifecycle = FACTORY_LIFECYCLE_CLOSED_UNILATERAL;
		fi->breach_epoch = UINT32_MAX;
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "Classifier: kickoff published but witness sig "
			   "unavailable — can't distinguish current epoch "
			   "from breach. Labeling CLOSED_UNILATERAL without "
			   "epoch. Re-run factory-scan-external-close or "
			   "wait for Phase 3 state-TX observation.");
		return;
	}

	/* Test 3: no match to any of our artifacts. Leave lifecycle at
	 * Phase 1's CLOSED_EXTERNALLY; note closed_by as counterparty
	 * since Phase 1 only fired because lifecycle was ACTIVE. */
	fi->closed_by = CLOSED_BY_COUNTERPARTY;
	plugin_log(plugin_handle, LOG_INFORM,
		   "Classifier: factory root spent by TX %s matching neither "
		   "coop dist TX nor our kickoff. CLOSED_EXTERNALLY stands.",
		   txid_hex);
}

/* Got the blockhash for ctx->scan_height; fetch the block with tx detail. */
static struct command_result *scan_tx_blockhash_cb(struct command *cmd,
						    const char *method,
						    const char *buf,
						    const jsmntok_t *result,
						    void *arg)
{
	struct spending_tx_scan_ctx *ctx = (struct spending_tx_scan_ctx *)arg;

	/* getblockhash returns the hash as a bare string result. */
	const char *hash_str = NULL;
	if (result && result->type == JSMN_STRING) {
		hash_str = buf + result->start;
	}
	if (!hash_str)
		return notification_handled(cmd);

	int hash_len = result->end - result->start;
	char *hash_copy = tal_arr(cmd, char, hash_len + 1);
	memcpy(hash_copy, hash_str, hash_len);
	hash_copy[hash_len] = '\0';

	struct out_req *req = jsonrpc_request_start(cmd, "getblock",
		scan_tx_block_cb, scan_tx_rpc_err, ctx);
	json_add_string(req->js, "blockhash", hash_copy);
	json_add_u32(req->js, "verbosity", 2);
	send_outreq(req);
	return notification_handled(cmd);
}

/* Walk the block's transactions looking for one that spends our funding
 * outpoint. If found, record the spending txid and classify. Else step
 * back one block and continue, bounded by ctx->scan_remaining. */
static struct command_result *scan_tx_block_cb(struct command *cmd,
					       const char *method,
					       const char *buf,
					       const jsmntok_t *result,
					       void *arg)
{
	struct spending_tx_scan_ctx *ctx = (struct spending_tx_scan_ctx *)arg;
	factory_instance_t *fi = ctx->fi;

	/* Build the display-order hex of our funding_txid once for matching. */
	char want_txid_hex[65];
	for (int j = 0; j < 32; j++)
		sprintf(want_txid_hex + j*2, "%02x", fi->funding_txid[31-j]);
	want_txid_hex[64] = '\0';

	const jsmntok_t *tx_array = json_get_member(buf, result, "tx");
	if (!tx_array || tx_array->type != JSMN_ARRAY) {
		/* Can't parse; step back. */
		goto next_block;
	}

	const jsmntok_t *tx_tok;
	size_t ti;
	json_for_each_arr(ti, tx_tok, tx_array) {
		const jsmntok_t *vin_array = json_get_member(buf, tx_tok, "vin");
		if (!vin_array || vin_array->type != JSMN_ARRAY) continue;

		const jsmntok_t *vin_tok;
		size_t vi;
		json_for_each_arr(vi, vin_tok, vin_array) {
			const jsmntok_t *txid_tok = json_get_member(buf, vin_tok, "txid");
			const jsmntok_t *vout_tok = json_get_member(buf, vin_tok, "vout");
			if (!txid_tok || !vout_tok) continue;

			/* Match vout */
			u32 v;
			if (!json_to_u32(buf, vout_tok, &v)) continue;
			if (v != fi->funding_outnum) continue;

			/* Match txid (string compare). */
			int txid_len = txid_tok->end - txid_tok->start;
			if (txid_len != 64) continue;
			if (memcmp(buf + txid_tok->start, want_txid_hex, 64) != 0)
				continue;

			/* Matched! Extract this TX's txid. */
			const jsmntok_t *spending_txid_tok =
				json_get_member(buf, tx_tok, "txid");
			if (!spending_txid_tok
			    || spending_txid_tok->end - spending_txid_tok->start != 64)
				continue;

			/* Convert display hex → internal little-endian bytes. */
			for (int j = 0; j < 32; j++) {
				unsigned int b;
				const char *h = buf + spending_txid_tok->start + j*2;
				if (sscanf(h, "%02x", &b) != 1) goto next_block;
				fi->spending_txid[31 - j] = (uint8_t)b;
			}

			/* Phase 2b: extract the first witness stack item of
			 * the matched input. For key-path P2TR spend of the
			 * factory root, this is the 64-byte Schnorr sig —
			 * used by the classifier to identify the epoch. */
			uint8_t witness_sig[64];
			memset(witness_sig, 0, 64);
			bool have_witness_sig = false;
			const jsmntok_t *witness_arr =
				json_get_member(buf, vin_tok, "txinwitness");
			if (witness_arr && witness_arr->type == JSMN_ARRAY
			    && witness_arr->size > 0) {
				const jsmntok_t *first_item =
					witness_arr + 1; /* first array element */
				int item_hex_len =
					first_item->end - first_item->start;
				if (item_hex_len == 128 /* 64 bytes hex */) {
					bool ok = true;
					for (int k = 0; k < 64; k++) {
						unsigned int b;
						if (sscanf(buf
							   + first_item->start
							   + k*2,
							   "%02x", &b) != 1) {
							ok = false; break;
						}
						witness_sig[k] = (uint8_t)b;
					}
					if (ok) have_witness_sig = true;
				}
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "Scan: found spending TX for factory root at "
				   "block %u — classifying (witness %s).",
				   ctx->scan_height,
				   have_witness_sig ? "present" : "absent");
			ss_classify_spending_tx(fi,
				have_witness_sig ? witness_sig : NULL);
			ss_save_factory(cmd, fi);
			return notification_handled(cmd);
		}
	}

next_block:
	if (ctx->scan_height == 0 || ctx->scan_remaining == 0) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "Scan: spending TX for factory root not found within "
			   "window (scanned down through block %u). Leaving "
			   "lifecycle at CLOSED_EXTERNALLY with "
			   "closed_by=UNKNOWN. Operator can widen the window "
			   "via factory-scan-external-close.",
			   ctx->scan_height);
		return notification_handled(cmd);
	}
	ctx->scan_height--;
	ctx->scan_remaining--;
	request_blockhash_for_scan(cmd, ctx);
	return notification_handled(cmd);
}

/* Error path: transient bitcoind/RPC failures abort the scan but don't
 * poison the factory. Operator can retry. */
static struct command_result *scan_tx_rpc_err(struct command *cmd,
					      const char *method,
					      const char *buf,
					      const jsmntok_t *result,
					      void *arg)
{
	(void)method; (void)buf; (void)result; (void)arg;
	plugin_log(plugin_handle, LOG_UNUSUAL,
		   "Scan: RPC error during spending-TX scan; aborting. Retry "
		   "via factory-scan-external-close.");
	return notification_handled(cmd);
}

/* Entry point for Phase 2a spending-TX scan. Safe to call multiple times;
 * subsequent runs overwrite the previous classification output. */
static void ss_launch_spending_tx_scan(struct command *cmd,
				       factory_instance_t *fi,
				       uint32_t window)
{
	/* Needs real funding info and a cached blockheight to walk from. */
	bool has_funding = false;
	for (int b = 0; b < 32; b++)
		if (fi->funding_txid[b] != 0) { has_funding = true; break; }
	if (!has_funding) return;
	if (ss_state.current_blockheight == 0) return;

	struct spending_tx_scan_ctx *ctx = tal(cmd, struct spending_tx_scan_ctx);
	ctx->fi = fi;
	/* Start from the block the heartbeat first noticed the spend
	 * (preferred — narrower window) or the current height if Phase 1
	 * didn't record one (e.g., operator-triggered scan on an old
	 * factory). */
	ctx->scan_height = fi->first_noticed_block
		? fi->first_noticed_block
		: ss_state.current_blockheight;
	ctx->scan_remaining = window;
	request_blockhash_for_scan(cmd, ctx);
}

/* Breach scan: callback after checkutxo returns for a factory's
 * root funding UTXO. If the UTXO is spent, attempt penalty TXs. */
struct breach_scan_ctx {
	factory_instance_t *fi;
	size_t factory_idx;
};

static struct command_result *breach_utxo_checked(struct command *cmd,
						   const char *method,
						   const char *buf,
						   const jsmntok_t *result,
						   void *arg);
static struct command_result *breach_scan_rpc_err(struct command *cmd,
						  const char *method,
						  const char *buf,
						  const jsmntok_t *result,
						  void *arg);

/* Launch a single-shot checkutxo scan on a factory's funding UTXO.
 * Returns without sending if the factory has no real funding txid
 * (pre-funding-pending factories) or hasn't rotated yet. Used both
 * by the per-block handler and by ss_catchup_breach_scan at startup
 * so a breach that happened while the plugin was offline is caught
 * on the next block tick even if CLN doesn't replay block_added
 * notifications for the missed interval. */
static void ss_launch_breach_scan(struct command *cmd,
				  factory_instance_t *fi,
				  size_t factory_idx)
{
	/* Phase 3 architectural decision: chain-watching is delegated to
	 * the standalone superscalar_watchtower binary (see SuperScalar
	 * source tree). This function previously called CLN's getblockhash
	 * + getblock RPCs, both of which were removed in recent CLN
	 * versions. Rather than reimplementing block scanning in the
	 * plugin, the integration pattern is:
	 *
	 *   plugin = factory ceremony coordinator + Lightning wire
	 *   superscalar_watchtower = chain watching + penalty broadcast
	 *
	 * Phase 4 (pre-mainnet hardening): writer hook exporting per-epoch
	 * state-root txids to a SuperScalar-compatible SQLite DB. See
	 * PROTOCOL_NOTES.md section 10.
	 *
	 * Phase 6+ (architectural cleanup): full library embed via
	 * libsuperscalar's watchtower module + chain_backend adapter
	 * for CLN's bcli RPCs. */
	(void)cmd; (void)fi; (void)factory_idx;
	return;

	bool has_real_funding = false;
	for (int fb = 0; fb < 32; fb++) {
		if (fi->funding_txid[fb] != 0) {
			has_real_funding = true;
			break;
		}
	}
	/* Pre-Phase-1 this returned early for fi->epoch == 0 because the
	 * function existed solely to drive breach burn-tx construction,
	 * which is a no-op before any rotation. The function now also
	 * drives Phase-1 external-close detection (lifecycle transition
	 * to CLOSED_EXTERNALLY), which applies to fresh factories too —
	 * an LSP or client could have their factory root spent before the
	 * first rotation. Keep only the has_real_funding gate. The breach
	 * loop inside breach_utxo_checked already no-ops when there are no
	 * revoked epochs. */
	if (!has_real_funding)
		return;

	char ftxid_hex[65];
	for (int j = 0; j < 32; j++)
		sprintf(ftxid_hex + j*2, "%02x", fi->funding_txid[31-j]);
	ftxid_hex[64] = '\0';

	/* Phase 3a: spawn an aux_command so the checkutxo reply callback
	 * survives the parent's lifetime. The original `cmd` here is
	 * usually a notification-handler cmd (block_added) which the
	 * libplugin framework cleans up as soon as notification_handled()
	 * runs — well before our async checkutxo reply arrives. The reply
	 * then orphans ("JSON reply with unknown id" in logs) and
	 * breach_utxo_checked never fires, so the lifecycle transition
	 * to CLOSED_EXTERNALLY never happens. aux_command() creates a
	 * sibling cmd that lives until we explicitly free it via
	 * aux_command_done() in the callback. This is the canonical
	 * libplugin pattern for "I want my reply to survive my parent."
	 *
	 * tal-allocate the breach_scan_ctx on the aux cmd so it gets
	 * freed with the aux cmd. */
	struct command *acmd = aux_command(cmd);
	struct breach_scan_ctx *bctx = tal(acmd, struct breach_scan_ctx);
	bctx->fi = fi;
	bctx->factory_idx = factory_idx;

	struct out_req *req = jsonrpc_request_start(acmd,
		"checkutxo", breach_utxo_checked, breach_scan_rpc_err, bctx);
	json_add_string(req->js, "txid", ftxid_hex);
	json_add_u32(req->js, "vout", fi->funding_outnum);
	send_outreq(req);
}

/* Phase 3a: aux-cmd-aware error handler for the breach scan path. The
 * generic rpc_err() returns command_still_pending which is fine for the
 * notification-cmd lifetime model but leaks the aux cmd we created in
 * ss_launch_breach_scan. Use aux_command_done so the framework reclaims
 * the cmd + bctx (tal-allocated on it) cleanly. */
static struct command_result *breach_scan_rpc_err(struct command *cmd,
						  const char *method,
						  const char *buf,
						  const jsmntok_t *result,
						  void *arg)
{
	(void)arg;
	const jsmntok_t *msg_tok = json_get_member(buf, result, "message");
	if (msg_tok) {
		const char *errmsg = json_strdup(cmd, buf, msg_tok);
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "Breach scan RPC %s failed: %s — aux cmd freed",
			   method, errmsg ? errmsg : "(null)");
	} else {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "Breach scan RPC %s failed (no message) — aux cmd freed",
			   method);
	}
	return aux_command_done(cmd);
}

/* One-shot breach scan across every loaded factory. Called from init
 * right after ss_load_factories so we don't rely on block_added
 * notifications covering the interval we were offline. */
static void ss_catchup_breach_scan(struct command *cmd)
{
	size_t scanned = 0;
	for (size_t i = 0; i < ss_state.n_factories; i++) {
		factory_instance_t *fi = ss_state.factories[i];
		if (!fi) continue;
		/* Phase 3a: skip terminal-closed factories only. Pre-3a the
		 * gate was ACTIVE || DYING, but the 9 signet zombies that
		 * motivated this work were all in INIT (their ceremonies
		 * never completed before the recovery tool swept their
		 * roots). INIT factories with real funding need observation
		 * too — the inner gate in breach_utxo_checked still filters
		 * specific lifecycles for state transitions. */
		if (fi->lifecycle == FACTORY_LIFECYCLE_EXPIRED
		    || fi->lifecycle == FACTORY_LIFECYCLE_CLOSED_EXTERNALLY)
			continue;
		ss_launch_breach_scan(cmd, fi, i);
		scanned++;
	}
	if (scanned > 0) {
		plugin_log(plugin_handle, LOG_INFORM,
			   "Startup catch-up: launched breach scan on %zu "
			   "factor%s", scanned,
			   scanned == 1 ? "y" : "ies");
	}
}

/* ============================================================
 * Phase 3b: layered signal interpretation.
 *
 * Three orthogonal evidence sources combine in ss_apply_signals():
 *   - SIGNAL_UTXO_SPENT          (heartbeat)
 *   - SIGNAL_BROADCAST_MISSING   (sendrawtransaction → -25)
 *   - SIGNAL_BROADCAST_KNOWN     (sendrawtransaction → -27/-26)
 *   - SIGNAL_DIST_TXID_MATCHED   (spending tx == dist_signed_txid)
 *   - SIGNAL_KICKOFF_TXID_MATCHED(spending tx == kickoff txid)
 *   - SIGNAL_WITNESS_CURRENT_MATCH/PAST_MATCH  (witness sig match)
 *   - SIGNAL_STATE_TX_MATCH      (downstream state-TX match)
 *
 * Sources may fire in any order. ss_apply_signals reads the bitmask
 * AND state_tx_match_epoch / breach_epoch / dist match results, then
 * derives a single canonical lifecycle decision. Idempotent — re-
 * running with new evidence can only refine, never downgrade.
 * ============================================================ */

/* Set lifecycle + closed_by + breach_epoch from the union of signals.
 * Called whenever a new signal is set on fi->signals_observed. Persists. */
static void ss_apply_signals(struct command *cmd, factory_instance_t *fi)
{
	uint16_t s = fi->signals_observed;

	/* Skip if already in a more-specific terminal state — we don't
	 * downgrade. CLOSED_EXTERNALLY is the weakest closed-* label;
	 * we'll happily upgrade away from it but won't move backwards. */
	bool can_refine = !factory_is_closed(fi->lifecycle)
		|| fi->lifecycle == FACTORY_LIFECYCLE_CLOSED_EXTERNALLY;
	if (!can_refine) return;

	factory_lifecycle_t new_lifecycle = fi->lifecycle;
	uint8_t new_closed_by = fi->closed_by;

	if (s & SIGNAL_DIST_TXID_MATCHED) {
		new_lifecycle = FACTORY_LIFECYCLE_CLOSED_COOPERATIVE;
		new_closed_by = CLOSED_BY_UNKNOWN;
	} else if (s & SIGNAL_WITNESS_PAST_MATCH) {
		/* Strongest breach signal: explicit witness match to past
		 * epoch. breach_epoch already populated by the path that
		 * set this bit. */
		new_lifecycle = FACTORY_LIFECYCLE_CLOSED_BREACHED;
		new_closed_by = CLOSED_BY_COUNTERPARTY;
	} else if (s & SIGNAL_STATE_TX_MATCH) {
		/* Downstream scan found a state TX. state_tx_match_epoch
		 * tells us which epoch. Match against current_epoch tells
		 * us whether normal-exit or breach. */
		if (fi->state_tx_match_epoch == fi->epoch) {
			new_lifecycle = FACTORY_LIFECYCLE_CLOSED_UNILATERAL;
			new_closed_by = CLOSED_BY_COUNTERPARTY;
		} else {
			new_lifecycle = FACTORY_LIFECYCLE_CLOSED_BREACHED;
			new_closed_by = CLOSED_BY_COUNTERPARTY;
			fi->breach_epoch = fi->state_tx_match_epoch;
		}
	} else if (s & SIGNAL_WITNESS_CURRENT_MATCH) {
		new_lifecycle = FACTORY_LIFECYCLE_CLOSED_UNILATERAL;
		new_closed_by = CLOSED_BY_COUNTERPARTY;
	} else if (s & SIGNAL_BROADCAST_KNOWN) {
		/* "Already in mempool/blockchain" on a kickoff broadcast:
		 * someone broadcast a kickoff. Without finer signals we
		 * can only label as CLOSED_UNILATERAL with epoch unknown.
		 * Phase 2b's witness path or downstream scan will refine. */
		new_lifecycle = FACTORY_LIFECYCLE_CLOSED_UNILATERAL;
		new_closed_by = CLOSED_BY_COUNTERPARTY;
	} else if ((s & SIGNAL_UTXO_SPENT) || (s & SIGNAL_BROADCAST_MISSING)) {
		/* Root spent but we have no specific match — either external
		 * sweep (recovery tool, HSM-lost) or coop/breach we couldn't
		 * resolve. Phase 2a's spending-TX scan continues working;
		 * any later signal will refine via this same function. */
		new_lifecycle = FACTORY_LIFECYCLE_CLOSED_EXTERNALLY;
		new_closed_by = CLOSED_BY_COUNTERPARTY;
	} else {
		/* No closed-* signals fired; nothing to do. */
		return;
	}

	if (new_lifecycle == fi->lifecycle && new_closed_by == fi->closed_by)
		return;

	char iid_hex[65];
	for (int j = 0; j < 32; j++)
		sprintf(iid_hex + j*2, "%02x", fi->instance_id[j]);
	iid_hex[64] = '\0';
	plugin_log(plugin_handle, LOG_INFORM,
		   "ss_apply_signals: factory %s signals=0x%02x → lifecycle "
		   "%d (was %d), closed_by %d (was %d), breach_epoch %u",
		   iid_hex, s, (int)new_lifecycle, (int)fi->lifecycle,
		   (int)new_closed_by, (int)fi->closed_by, fi->breach_epoch);

	fi->lifecycle = new_lifecycle;
	fi->closed_by = new_closed_by;
	if (cmd) ss_save_factory(cmd, fi);
}

/* Phase 3b: broadcast-reply hook context. */
struct broadcast_reply_ctx {
	factory_instance_t *fi;
	int kind; /* factory_tx_kind_t values */
};

static const char *factory_tx_kind_name(int k)
{
	switch (k) {
	case FACTORY_TX_KICKOFF: return "kickoff";
	case FACTORY_TX_STATE:   return "state";
	case FACTORY_TX_BURN:    return "burn";
	case FACTORY_TX_DIST:    return "dist";
	default: return "unknown";
	}
}

/* Reply callback for ss_broadcast_factory_tx. Reads the result for
 * specific bitcoind error codes that tell us about chain state, sets
 * the appropriate signal on the factory, and runs ss_apply_signals to
 * update lifecycle. */
static struct command_result *
broadcast_reply_classified(struct command *cmd,
			   const char *method,
			   const char *buf,
			   const jsmntok_t *result,
			   void *arg)
{
	struct broadcast_reply_ctx *bc =
		(struct broadcast_reply_ctx *)arg;
	factory_instance_t *fi = bc->fi;

	const jsmntok_t *succ_tok = json_get_member(buf, result, "success");
	bool success = false;
	if (succ_tok) json_to_bool(buf, succ_tok, &success);

	const jsmntok_t *errmsg_tok = json_get_member(buf, result, "errmsg");
	const char *errmsg = errmsg_tok ? buf + errmsg_tok->start : NULL;

	if (success) {
		/* Our broadcast was accepted to mempool. No new signal —
		 * we initiated, lifecycle is presumably already DYING.
		 * Just log for the audit trail. */
		plugin_log(plugin_handle, LOG_DBG,
			   "broadcast_reply: %s TX accepted",
			   factory_tx_kind_name(bc->kind));
		return aux_command_done(cmd);
	}

	/* Parse known error patterns. errmsg looks like:
	 *   "error code: -25\nerror message:\nbad-txns-inputs-missingorspent"
	 */
	uint16_t signal_to_set = 0;
	const char *what = "unknown";
	if (errmsg) {
		if (strstr(errmsg, "missingorspent")) {
			signal_to_set = SIGNAL_BROADCAST_MISSING;
			what = "missingorspent";
		} else if (strstr(errmsg, "already in")
			   || strstr(errmsg, "already in utxo set")
			   || strstr(errmsg, "already known")) {
			/* "Transaction outputs already in utxo set" is the
			 * code -27 message we see in production logs. */
			signal_to_set = SIGNAL_BROADCAST_KNOWN;
			what = "already-known";
		}
	}

	if (signal_to_set && bc->kind == FACTORY_TX_KICKOFF) {
		fi->signals_observed |= signal_to_set;
		char iid_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(iid_hex + j*2, "%02x", fi->instance_id[j]);
		iid_hex[64] = '\0';
		plugin_log(plugin_handle, LOG_INFORM,
			   "broadcast_reply: factory %s kickoff broadcast "
			   "→ %s (signal 0x%02x set), running classifier",
			   iid_hex, what, signal_to_set);
		ss_apply_signals(cmd, fi);
	} else if (signal_to_set) {
		plugin_log(plugin_handle, LOG_DBG,
			   "broadcast_reply: %s TX %s — informational only",
			   factory_tx_kind_name(bc->kind), what);
	} else {
		plugin_log(plugin_handle, LOG_DBG,
			   "broadcast_reply: %s TX failed (no recognized "
			   "error pattern): %s",
			   factory_tx_kind_name(bc->kind),
			   errmsg ? errmsg : "(no errmsg)");
	}

	return aux_command_done(cmd);
}

/* Wrapper around sendrawtransaction that classifies the reply for
 * factory-related TXs. Use this instead of raw sendrawtransaction for
 * any kickoff/state/burn/dist broadcast we want to learn from. */
static void ss_broadcast_factory_tx(struct command *cmd,
				    factory_instance_t *fi,
				    const char *tx_hex,
				    int kind)
{
	struct command *acmd = aux_command(cmd);
	struct broadcast_reply_ctx *bc = tal(acmd, struct broadcast_reply_ctx);
	bc->fi = fi;
	bc->kind = kind;

	struct out_req *req = jsonrpc_request_start(acmd,
		"sendrawtransaction",
		broadcast_reply_classified,
		broadcast_reply_classified, /* same handler for errors */
		bc);
	json_add_string(req->js, "tx", tx_hex);
	json_add_bool(req->js, "allowhighfees", true);
	send_outreq(req);
}

/* Phase 3b: downstream state-TX scan. After observing the kickoff
 * spent (root UTXO consumed), scan recent blocks for the state TX
 * that spends the kickoff's tree-root output. Match against the
 * per-epoch state_root_txid cache to identify the epoch. */
struct state_tx_scan_ctx {
	factory_instance_t *fi;
	uint8_t kickoff_txid[32];
	uint32_t scan_height;
	uint32_t scan_remaining;
};

static struct command_result *state_scan_blockhash_cb(struct command *cmd,
						       const char *method,
						       const char *buf,
						       const jsmntok_t *result,
						       void *arg);
static struct command_result *state_scan_block_cb(struct command *cmd,
						   const char *method,
						   const char *buf,
						   const jsmntok_t *result,
						   void *arg);

static void request_blockhash_for_state_scan(struct command *cmd,
					     struct state_tx_scan_ctx *ctx)
{
	struct out_req *req = jsonrpc_request_start(cmd, "getblockhash",
		state_scan_blockhash_cb, breach_scan_rpc_err, ctx);
	json_add_u32(req->js, "height", ctx->scan_height);
	send_outreq(req);
}

static struct command_result *state_scan_blockhash_cb(struct command *cmd,
						       const char *method,
						       const char *buf,
						       const jsmntok_t *result,
						       void *arg)
{
	struct state_tx_scan_ctx *ctx = (struct state_tx_scan_ctx *)arg;
	if (!result || result->type != JSMN_STRING)
		return aux_command_done(cmd);
	int hash_len = result->end - result->start;
	char *hash = tal_arr(cmd, char, hash_len + 1);
	memcpy(hash, buf + result->start, hash_len);
	hash[hash_len] = '\0';

	struct out_req *req = jsonrpc_request_start(cmd, "getblock",
		state_scan_block_cb, breach_scan_rpc_err, ctx);
	json_add_string(req->js, "blockhash", hash);
	json_add_u32(req->js, "verbosity", 2);
	send_outreq(req);
	return command_still_pending(cmd);
}

static struct command_result *state_scan_block_cb(struct command *cmd,
						   const char *method,
						   const char *buf,
						   const jsmntok_t *result,
						   void *arg)
{
	struct state_tx_scan_ctx *ctx = (struct state_tx_scan_ctx *)arg;
	factory_instance_t *fi = ctx->fi;

	/* We're looking for a TX whose vin includes
	 * (kickoff_txid, vout=0). Build the display-order hex of our
	 * kickoff_txid for string compare. */
	char want_hex[65];
	for (int j = 0; j < 32; j++)
		sprintf(want_hex + j*2, "%02x", ctx->kickoff_txid[31-j]);
	want_hex[64] = '\0';

	const jsmntok_t *txs = json_get_member(buf, result, "tx");
	if (!txs || txs->type != JSMN_ARRAY) goto next;

	const jsmntok_t *tx_tok;
	size_t ti;
	json_for_each_arr(ti, tx_tok, txs) {
		const jsmntok_t *vins = json_get_member(buf, tx_tok, "vin");
		if (!vins || vins->type != JSMN_ARRAY) continue;
		const jsmntok_t *vin_tok;
		size_t vi;
		json_for_each_arr(vi, vin_tok, vins) {
			const jsmntok_t *txid_tok =
				json_get_member(buf, vin_tok, "txid");
			if (!txid_tok
			    || txid_tok->end - txid_tok->start != 64)
				continue;
			if (memcmp(buf + txid_tok->start, want_hex, 64) != 0)
				continue;

			/* Found a TX spending our kickoff. Get its txid. */
			const jsmntok_t *spending_txid_tok =
				json_get_member(buf, tx_tok, "txid");
			if (!spending_txid_tok) continue;
			uint8_t spending_txid[32];
			for (int j = 0; j < 32; j++) {
				unsigned int b;
				if (sscanf(buf + spending_txid_tok->start
					   + j*2, "%02x", &b) != 1)
					goto next;
				spending_txid[31-j] = (uint8_t)b;
			}

			/* Match against per-epoch state-root TXID cache. */
			for (size_t i = 0; i < fi->n_history_kickoff_sigs; i++) {
				if (memcmp(spending_txid,
					   fi->history_state_root_txids[i], 32) == 0) {
					uint32_t prev_match_epoch =
						fi->state_tx_match_epoch;
					fi->state_tx_match_epoch =
						fi->history_kickoff_epochs[i];
					fi->signals_observed |=
						SIGNAL_STATE_TX_MATCH;
					plugin_log(plugin_handle, LOG_INFORM,
						"State-TX scan: kickoff "
						"output spent at epoch %u "
						"(current %u). Setting "
						"SIGNAL_STATE_TX_MATCH.",
						fi->state_tx_match_epoch,
						fi->epoch);
					ss_apply_signals(cmd, fi);

					/* Phase 4b2: if the newly-matched epoch
					 * differs from what we had before AND
					 * it's a revoked epoch (not current),
					 * rebuild the breach burns against the
					 * new state TX. This is the RBF auto-
					 * rebuild path. */
					if (prev_match_epoch
					    != fi->state_tx_match_epoch
					    && fi->state_tx_match_epoch
					    != fi->epoch) {
						ss_rebuild_breach_burns(cmd,
							fi,
							fi->state_tx_match_epoch);
					}
					return aux_command_done(cmd);
				}
			}

			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "State-TX scan: kickoff output spent by "
				   "TX whose txid doesn't match any cached "
				   "per-epoch state root. Either pre-Phase-3b "
				   "rotation (unrecoverable) or genuine "
				   "external sweep.");
			return aux_command_done(cmd);
		}
	}

next:
	if (ctx->scan_height == 0 || ctx->scan_remaining == 0) {
		plugin_log(plugin_handle, LOG_DBG,
			   "State-TX scan: no spend of kickoff output found "
			   "in scan window.");
		return aux_command_done(cmd);
	}
	ctx->scan_height--;
	ctx->scan_remaining--;
	request_blockhash_for_state_scan(cmd, ctx);
	return command_still_pending(cmd);
}

/* Entry point for the downstream state-TX scan. Caller passes the
 * kickoff txid (the parent of the state TX we're searching for). */
static void ss_launch_state_tx_scan(struct command *cmd,
				    factory_instance_t *fi,
				    const uint8_t *kickoff_txid,
				    uint32_t window)
{
	/* Phase 3 architectural decision: chain-watching delegated to
	 * superscalar_watchtower. See ss_launch_breach_scan for the full
	 * reasoning + Phase 4/6 roadmap. */
	(void)cmd; (void)fi; (void)kickoff_txid; (void)window;
	return;
	if (ss_state.current_blockheight == 0) return;

	struct command *acmd = aux_command(cmd);
	struct state_tx_scan_ctx *ctx =
		tal(acmd, struct state_tx_scan_ctx);
	ctx->fi = fi;
	memcpy(ctx->kickoff_txid, kickoff_txid, 32);
	ctx->scan_height = fi->first_noticed_block
		? fi->first_noticed_block
		: ss_state.current_blockheight;
	ctx->scan_remaining = window;
	request_blockhash_for_state_scan(acmd, ctx);
}

/* ============================================================
 * Phase 3c (with 3c-redux simplification): penalty pathway.
 *
 * When the classifier fires CLOSED_BREACHED, the broadcast sites in
 * breach_utxo_checked send a burn TX (factory_build_burn_tx). The
 * penalty is RECORDED here as pending_penalty_t and the per-block
 * scheduler (ss_penalty_scheduler_tick) just rebroadcasts it every
 * block until confirmation:
 *   - PENDING/BROADCAST: rebroadcast burn TX, idempotent on bitcoind
 *   - CONFIRMED: stop, set SIGNAL_PENALTY_CONFIRMED (via mark RPC)
 *   - REPLACED: lost the race (CSV + grace passed without confirm)
 *   - STALE: source UTXO replaced via RBF (Phase 4b)
 *
 * Phase 3c-redux note: the original Phase 3c integrated upstream
 * htlc_fee_bump.c for RBF-style feerate scheduling. This was
 * misapplied — burn TXs are 100%-fee by construction (output is
 * OP_RETURN with 0 sats; entire L-stock value becomes miner fee), so
 * "feerate" doesn't apply in the htlc_fee_bump sense. The simplified
 * scheduler just rebroadcasts; the 100% fee guarantees next-block
 * confirmation barring catastrophic mempool conditions.
 *
 * htlc_fee_bump.c stays linked because Phase 3c2 (CPFP-via-anchor for
 * dist/state/kickoff TXs) will use it for the CHILD's fee scheduling
 * — that IS a real fee-bump scenario (the parent is pre-signed and
 * non-RBF-able; the CPFP child carries the bump fee).
 *
 * Reorg resilience: if a previously-confirmed penalty txid disappears
 * from the chain (Phase 4e ss_penalty_reorg_check), we reset
 * confirmed_block=0 and the scheduler resumes rebroadcasting.
 * ============================================================ */

/* Default CSV delay on L-stock outputs — upstream SuperScalar uses
 * CSV=144 (~1 day) on leaf revocation outputs by default. This is the
 * deadline window: counterparty can claim freely after CSV unlocks. */
#define LSTOCK_CSV_DELAY_DEFAULT 144

/* Rough vsize of a key-path-spend burn TX (1 input, 1 output, schnorr
 * witness). 110 vbytes is a conservative estimate for the classic
 * L-stock burn. Overestimating just slightly inflates fee rates — safe. */
#define LSTOCK_BURN_VSIZE_DEFAULT 120

/* Record a fresh penalty broadcast against a revoked L-stock output.
 * Caller has already sent the tx via ss_broadcast_factory_tx. This
 * function only registers it for the scheduler. Idempotent by
 * (epoch, leaf_index) — re-adding just updates the txid and
 * broadcast timestamps. */
static void ss_register_pending_penalty(factory_instance_t *fi,
					uint32_t epoch,
					int leaf_index,
					const uint8_t *burn_txid,
					uint64_t lstock_sats,
					uint32_t csv_unlock_block,
					uint32_t tx_vsize,
					uint32_t current_block)
{
	/* Dedup: find existing entry for (epoch, leaf_index). */
	pending_penalty_t *pp = NULL;
	for (size_t i = 0; i < fi->n_pending_penalties; i++) {
		if (fi->pending_penalties[i].epoch == epoch
		    && fi->pending_penalties[i].leaf_index == leaf_index) {
			pp = &fi->pending_penalties[i];
			break;
		}
	}

	if (!pp) {
		if (fi->n_pending_penalties >= MAX_PENDING_PENALTIES) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "pending_penalty: cap reached (%d) — "
				   "oldest entries will not be re-bumped",
				   MAX_PENDING_PENALTIES);
			return;
		}
		pp = &fi->pending_penalties[fi->n_pending_penalties++];
		memset(pp, 0, sizeof(*pp));
		pp->epoch = epoch;
		pp->leaf_index = leaf_index;
		pp->lstock_sats = lstock_sats;
		pp->csv_unlock_block = csv_unlock_block;
		pp->tx_vsize = tx_vsize;
		pp->first_broadcast_block = current_block;
	}

	memcpy(pp->burn_txid, burn_txid, 32);
	pp->last_broadcast_block = current_block;
	pp->state = PENALTY_STATE_BROADCAST;

	plugin_log(plugin_handle, LOG_INFORM,
		   "pending_penalty registered: epoch=%u leaf=%d "
		   "lstock=%"PRIu64" sats csv_unlock=%u vsize=%u",
		   epoch, leaf_index, lstock_sats, csv_unlock_block,
		   tx_vsize);

	/* Phase 5c structured marker. Emitted once per (epoch, leaf)
	 * pair on first broadcast registration (not on duplicate bumps —
	 * the dedup branch above returns before reaching here). */
	char iid_hex[65];
	for (int b = 0; b < 32; b++)
		sprintf(iid_hex + b*2, "%02x", fi->instance_id[b]);
	iid_hex[64] = '\0';
	plugin_log(plugin_handle, LOG_INFORM,
		   "SS_METRIC event=breach_burn_broadcast iid=%s "
		   "epoch=%u leaf=%d lstock_sats=%"PRIu64" block=%u",
		   iid_hex, epoch, leaf_index, lstock_sats, current_block);
}

/* Phase 3c-redux: grace blocks past CSV after which we mark a
 * still-unconfirmed burn as REPLACED. CSV is when counterparty CAN
 * claim; we give a small buffer for our 100%-fee burn to land before
 * conceding. ~6 blocks (~1 hour) is generous: a 100%-fee TX confirms
 * in 1 block barring extreme mempool backpressure. */
#define BURN_TX_GRACE_BLOCKS 6

/* Phase 3c-redux: per-block burn-TX scheduler. SIMPLIFIED from the
 * original Phase 3c htlc_fee_bump-based RBF logic. Burn TXs are
 * 100%-fee-by-construction — factory_build_burn_tx outputs OP_RETURN
 * with 0 sats, so the entire L-stock value (e.g., 100k sats) becomes
 * miner fee. There is no fee to "bump"; miners are maximally
 * incentivized to mine these immediately. The original RBF math
 * (htlc_fee_bump_should_bump, urgency window, 25% min-bump) doesn't
 * apply — that mechanism is for HTLC sweep TXs whose fee is a small
 * fraction of HTLC value.
 *
 * What this scheduler actually does:
 *   - PENDING/BROADCAST entries: rebroadcast burn TX every block via
 *     ss_broadcast_factory_tx. Idempotent on bitcoind's side
 *     (already-known reply handled by the broadcast classifier).
 *   - CONFIRMED/REPLACED/STALE: skip (terminal-ish).
 *   - Past CSV + grace without confirm: mark REPLACED (we lost the
 *     race; counterparty can claim the L-stock outputs).
 *
 * pp->last_feerate / pp->tx_vsize remain in the struct as diagnostic
 * fields written at registration time but no longer drive scheduling.
 * (Kept for persist v12 backward compat — see Phase 3c-redux.)
 *
 * Returns count of broadcasts triggered. */
static int ss_penalty_scheduler_tick(struct command *cmd,
				     factory_instance_t *fi,
				     uint32_t current_block)
{
	int bumps = 0;
	bool dirty = false;
	for (size_t i = 0; i < fi->n_pending_penalties; i++) {
		pending_penalty_t *pp = &fi->pending_penalties[i];
		if (pp->state == PENALTY_STATE_CONFIRMED
		    || pp->state == PENALTY_STATE_REPLACED
		    || pp->state == PENALTY_STATE_STALE)
			continue;

		/* Past CSV + grace and still not confirmed → we lost. */
		if (pp->csv_unlock_block > 0
		    && current_block >= pp->csv_unlock_block
				        + BURN_TX_GRACE_BLOCKS) {
			pp->state = PENALTY_STATE_REPLACED;
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "PENALTY EXPIRED: epoch=%u leaf=%d CSV at "
				   "block %u + %u grace passed without our "
				   "100%%-fee burn confirming. Counterparty "
				   "can now claim the revoked output.",
				   pp->epoch, pp->leaf_index,
				   pp->csv_unlock_block,
				   BURN_TX_GRACE_BLOCKS);
			dirty = true;
			continue;
		}

		/* Don't churn — only one rebroadcast per block. */
		if (pp->last_broadcast_block == current_block)
			continue;

		factory_t *f = (factory_t *)fi->lib_factory;
		if (!f || pp->leaf_index < 0
		    || (size_t)pp->leaf_index >= f->n_nodes)
			continue;
		factory_node_t *leaf = &f->nodes[pp->leaf_index];
		if (leaf->n_outputs == 0)
			continue;
		uint32_t lstock_vout = (uint32_t)(leaf->n_outputs - 1);
		uint64_t lstock_amt = leaf->outputs[lstock_vout].amount_sats;

		tx_buf_t burn_tx;
		tx_buf_init(&burn_tx, 256);
		if (factory_build_burn_tx(f, &burn_tx, leaf, leaf->txid,
					  lstock_vout, lstock_amt,
					  pp->epoch)) {
			char *burn_hex = tal_arr(cmd, char,
				burn_tx.len * 2 + 1);
			for (size_t h = 0; h < burn_tx.len; h++)
				sprintf(burn_hex + h*2, "%02x",
					burn_tx.data[h]);
			ss_broadcast_factory_tx(cmd, fi, burn_hex,
						FACTORY_TX_BURN);
			pp->last_broadcast_block = current_block;
			bumps++;
			dirty = true;
			plugin_log(plugin_handle, LOG_DBG,
				   "penalty_scheduler: rebroadcast burn "
				   "epoch=%u leaf=%d at block %u",
				   pp->epoch, pp->leaf_index, current_block);
		}
		tx_buf_free(&burn_tx);
	}
	if (dirty)
		ss_save_factory(cmd, fi);
	return bumps;
}

/* ============================================================
 * Phase 4e: reorg re-evaluation.
 *
 * Algorithm ported from upstream watchtower.c:watchtower_on_reorg
 * (see feedback_reuse_superscalar_upstream). Upstream takes a new_tip
 * and old_tip, walks every entry with penalty_broadcast==1 + a stored
 * penalty_txid, and resets that pair if the TX is neither confirmed
 * nor in mempool. Stored txids that reorg out get re-queued.
 *
 * Our adaptation: iterate pending_penalty_t entries in CONFIRMED state,
 * issue getrawtransaction(verbose=true) per entry. If the reply errors
 * (TX unknown to bitcoind) OR reports confirmations==0 (evicted to
 * mempool only), reset confirmed_block and flip state back to
 * PENALTY_STATE_BROADCAST so the scheduler re-bumps on the next tick.
 *
 * Auto-detection of reorgs is deferred (Phase 4e2) — CLN doesn't emit
 * a block_disconnected notification by default and the minimum-viable
 * path is operator- or dev-triggered invocation. Phase 4e lands the
 * algorithm; wiring the trigger source is follow-up.
 * ============================================================ */

struct reorg_check_ctx {
	factory_instance_t *fi;
	size_t penalty_idx;
};

static struct command_result *
reorg_check_gettx_reply(struct command *cmd,
			const char *method UNUSED,
			const char *buf,
			const jsmntok_t *result,
			void *arg)
{
	struct reorg_check_ctx *ctx = (struct reorg_check_ctx *)arg;
	factory_instance_t *fi = ctx->fi;
	if (ctx->penalty_idx >= fi->n_pending_penalties)
		return aux_command_done(cmd);
	pending_penalty_t *pp = &fi->pending_penalties[ctx->penalty_idx];

	bool tx_gone = false;
	const char *why = "unknown";

	/* The error path has result == NULL (jsonrpc error dispatched
	 * straight to the error cb). Here we share the same callback for
	 * both success and error, so either NULL result or an explicit
	 * "code"/"message" member signals bitcoind didn't find the tx. */
	if (!result) {
		tx_gone = true;
		why = "rpc_error";
	} else {
		const jsmntok_t *err_tok =
			json_get_member(buf, result, "code");
		if (err_tok) {
			tx_gone = true;
			why = "tx_unknown";
		} else {
			/* Verbose getrawtransaction returns a "confirmations"
			 * field (present and >=1 = in chain). Missing or 0 =
			 * mempool-only (reorg-evicted). */
			const jsmntok_t *confs_tok =
				json_get_member(buf, result, "confirmations");
			if (!confs_tok) {
				tx_gone = true;
				why = "no_confirmations_field";
			} else {
				u32 n_confs;
				if (!json_to_u32(buf, confs_tok, &n_confs)) {
					tx_gone = true;
					why = "confirmations_parse_fail";
				} else if (n_confs == 0) {
					tx_gone = true;
					why = "mempool_only";
				}
			}
		}
	}

	if (tx_gone && pp->state == PENALTY_STATE_CONFIRMED) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "REORG RE-EVAL: penalty epoch=%u leaf=%d no longer "
			   "confirmed on chain (%s) — resetting state to "
			   "BROADCAST. Scheduler will re-bump next tick.",
			   pp->epoch, pp->leaf_index, why);
		pp->confirmed_block = 0;
		pp->state = PENALTY_STATE_BROADCAST;
		ss_save_factory(cmd, fi);
	}
	return aux_command_done(cmd);
}

/* For each CONFIRMED pending penalty, fire off a getrawtransaction
 * probe via aux_command (reply may outlive parent). Callbacks flip
 * state back to BROADCAST if the TX is no longer on chain. */
static int ss_penalty_reorg_check(struct command *cmd,
				  factory_instance_t *fi)
{
	int probes = 0;
	for (size_t i = 0; i < fi->n_pending_penalties; i++) {
		pending_penalty_t *pp = &fi->pending_penalties[i];
		if (pp->state != PENALTY_STATE_CONFIRMED)
			continue;

		struct command *acmd = aux_command(cmd);
		struct reorg_check_ctx *rctx =
			tal(acmd, struct reorg_check_ctx);
		rctx->fi = fi;
		rctx->penalty_idx = i;

		char txid_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(txid_hex + j*2, "%02x",
				pp->burn_txid[31-j]);
		txid_hex[64] = '\0';

		struct out_req *req = jsonrpc_request_start(acmd,
			"getrawtransaction",
			reorg_check_gettx_reply,
			reorg_check_gettx_reply,
			rctx);
		json_add_string(req->js, "txid", txid_hex);
		json_add_bool(req->js, "verbose", true);
		send_outreq(req);
		probes++;
	}
	return probes;
}

/* Legacy stub name kept for the existing block_added call site. Wires
 * through to the real impl. The block_added path is conservative about
 * calling this — we don't want to eagerly mark every confirmed penalty
 * stale in environments where bitcoind rejects getrawtransaction for
 * non-chain TXs (test fixtures with synthetic burn_txid). Callers must
 * ensure they're running against a real chain or are OK with the check
 * flipping penalties back to BROADCAST. */
static void ss_penalty_reorg_check_stub(factory_instance_t *fi)
{
	/* Synchronous no-op wrapper retained to preserve the existing
	 * block_added call site's signature. The real async check lives
	 * in ss_penalty_reorg_check (takes a command*); production
	 * trigger is via the factory-reorg-check / dev-factory-trigger-
	 * reorg-check RPCs. Auto-wiring to block_added is deferred until
	 * we either (a) get a block_disconnected notification subscription
	 * working or (b) track (height, blockhash) per penalty so we can
	 * detect the reorg without eagerly probing. */
	(void)fi;
}

/* Phase 4b2: rebuild and broadcast breach burns for a specific revoked
 * epoch. Extracted from breach_utxo_checked so we can re-run just the
 * burn-construction path when the state-TX scan finds a new epoch
 * (e.g. after counterparty RBF'd a previously-targeted state TX).
 *
 * Walks fi->breach_data[] for matching epoch + has_revocation, then
 * iterates every leaf node, builds factory_build_burn_tx, broadcasts
 * via ss_broadcast_factory_tx, registers a fresh pending_penalty_t.
 *
 * Returns count of burns broadcast. */
static int ss_rebuild_breach_burns(struct command *cmd,
				   factory_instance_t *fi,
				   uint32_t target_epoch)
{
	factory_t *f = (factory_t *)fi->lib_factory;
	if (!f)
		return 0;

	int n_broadcast = 0;
	for (size_t bi = 0; bi < fi->n_breach_epochs; bi++) {
		epoch_breach_data_t *bd = &fi->breach_data[bi];
		if (bd->epoch != target_epoch)
			continue;
		if (!bd->has_revocation)
			continue;
		if (bd->epoch >= fi->epoch)
			continue;  /* current epoch — not a breach */

		for (int ls = 0; ls < f->n_leaf_nodes; ls++) {
			size_t leaf_idx = f->leaf_node_indices[ls];
			if (leaf_idx >= f->n_nodes) continue;
			factory_node_t *leaf = &f->nodes[leaf_idx];
			if (leaf->n_outputs == 0) continue;

			uint32_t lstock_vout =
				(uint32_t)(leaf->n_outputs - 1);
			uint64_t lstock_amt =
				leaf->outputs[lstock_vout].amount_sats;

			tx_buf_t burn_tx;
			tx_buf_init(&burn_tx, 256);
			if (factory_build_burn_tx(f, &burn_tx, leaf, leaf->txid,
						  lstock_vout, lstock_amt,
						  bd->epoch)) {
				char *burn_hex = tal_arr(cmd, char,
					burn_tx.len * 2 + 1);
				for (size_t h = 0; h < burn_tx.len; h++)
					sprintf(burn_hex + h*2, "%02x",
						burn_tx.data[h]);
				ss_broadcast_factory_tx(cmd, fi, burn_hex,
							FACTORY_TX_BURN);

				uint8_t burn_txid[32];
				struct sha256 h1, h2;
				sha256(&h1, burn_tx.data, burn_tx.len);
				sha256(&h2, &h1, sizeof(h1));
				memcpy(burn_txid, &h2, 32);
				uint32_t csv_unlock =
					ss_state.current_blockheight
					+ LSTOCK_CSV_DELAY_DEFAULT;
				ss_register_pending_penalty(fi, bd->epoch,
					(int)leaf_idx, burn_txid,
					lstock_amt, csv_unlock,
					(uint32_t)burn_tx.len,
					ss_state.current_blockheight);
				n_broadcast++;

				plugin_log(plugin_handle, LOG_UNUSUAL,
					"Phase 4b2 rebuild: broadcast burn for "
					"epoch=%u leaf=%zu amt=%"PRIu64
					" (RBF-triggered replacement)",
					bd->epoch, leaf_idx, lstock_amt);
			}
			tx_buf_free(&burn_tx);
		}
	}
	return n_broadcast;
}

/* ============================================================
 * Phase 4b: RBF / mempool-race detection.
 *
 * Scenario: counterparty publishes state TX A, we build burn against
 * A's L-stock output, broadcast it. Before our burn confirms, they
 * RBF replace A with state TX B (different epoch or fee). Our burn
 * now references a dead outpoint and will never confirm.
 *
 * Detection: for each pending_penalty in BROADCAST or PENDING state,
 * gettxout the source UTXO. If null AND our burn hasn't confirmed,
 * the source TX got replaced — flip state to PENALTY_STATE_STALE.
 *
 * V1 (this PR): detection + state flag + operator visibility. Auto-
 * rebuild against the new outpoint is V2 — needs the state-TX scanner
 * to find the replacement first, then ss_register_pending_penalty
 * with the new (epoch, leaf, source). For now, operators see "stale"
 * in factory-list and can manually trigger factory-scan-external-
 * close + factory-check-breach to drive the rebuild.
 *
 * Algorithm parallel to Phase 4e reorg_check, but checks the SOURCE
 * UTXO our burn spends, not the burn TXID itself.
 * ============================================================ */

struct source_check_ctx {
	factory_instance_t *fi;
	size_t penalty_idx;
};

static struct command_result *
source_check_gettxout_reply(struct command *cmd,
			    const char *method UNUSED,
			    const char *buf,
			    const jsmntok_t *result,
			    void *arg)
{
	struct source_check_ctx *ctx = (struct source_check_ctx *)arg;
	factory_instance_t *fi = ctx->fi;
	if (ctx->penalty_idx >= fi->n_pending_penalties)
		return aux_command_done(cmd);
	pending_penalty_t *pp = &fi->pending_penalties[ctx->penalty_idx];

	/* Re-check state — caller may have raced. We only act on
	 * BROADCAST/PENDING. CONFIRMED/REPLACED/STALE are terminal-ish. */
	if (pp->state != PENALTY_STATE_BROADCAST
	    && pp->state != PENALTY_STATE_PENDING)
		return aux_command_done(cmd);

	/* Plugin's checkutxo wraps gettxout. The result has an "exists"
	 * boolean. true = source UTXO present; false = spent or never
	 * existed. For our purposes, false on a previously-broadcastable
	 * source means the state TX was RBF'd or the leaf TX confirmed
	 * AND was already swept (the latter is the "we won" case but our
	 * confirmed_block would be set, gating us out above). */
	bool source_present = false;
	if (result) {
		const jsmntok_t *exists = json_get_member(buf, result,
							  "exists");
		if (exists)
			json_to_bool(buf, exists, &source_present);
	}

	if (!source_present) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "RBF DETECTED: penalty epoch=%u leaf=%d source "
			   "UTXO no longer exists. State TX likely RBF'd; "
			   "marking penalty STALE. Auto-rebuild via state-TX "
			   "scan (Phase 4b2).",
			   pp->epoch, pp->leaf_index);
		pp->state = PENALTY_STATE_STALE;
		ss_save_factory(cmd, fi);

		/* Phase 4b2: kick off a state-TX scan from the kickoff
		 * output so state_scan_block_cb can identify any replacement
		 * state TX. When it finds one at a revoked epoch, it sets
		 * SIGNAL_STATE_TX_MATCH + state_tx_match_epoch. The classifier
		 * in ss_apply_signals then latches CLOSED_BREACHED with the
		 * updated breach_epoch, and state_scan_block_cb invokes
		 * ss_rebuild_breach_burn to construct a fresh penalty. */
		factory_t *f = (factory_t *)fi->lib_factory;
		if (f && f->n_nodes > 0) {
			static const uint8_t zero32[32] = {0};
			if (memcmp(f->nodes[0].txid, zero32, 32) != 0)
				ss_launch_state_tx_scan(cmd, fi,
					f->nodes[0].txid, 144);
		}
	}
	return aux_command_done(cmd);
}

/* For each PENDING/BROADCAST pending penalty, fire off a checkutxo
 * probe on the source UTXO via aux_command. Returns probes issued. */
static int ss_penalty_source_check(struct command *cmd,
				   factory_instance_t *fi)
{
	int probes = 0;
	factory_t *f = (factory_t *)fi->lib_factory;
	if (!f)
		return 0;

	for (size_t i = 0; i < fi->n_pending_penalties; i++) {
		pending_penalty_t *pp = &fi->pending_penalties[i];
		if (pp->state != PENALTY_STATE_BROADCAST
		    && pp->state != PENALTY_STATE_PENDING)
			continue;
		if (pp->leaf_index < 0
		    || (size_t)pp->leaf_index >= f->n_nodes)
			continue;

		factory_node_t *leaf = &f->nodes[pp->leaf_index];
		if (leaf->n_outputs == 0)
			continue;
		uint32_t lstock_vout = (uint32_t)(leaf->n_outputs - 1);

		struct command *acmd = aux_command(cmd);
		struct source_check_ctx *sctx =
			tal(acmd, struct source_check_ctx);
		sctx->fi = fi;
		sctx->penalty_idx = i;

		char txid_hex[65];
		for (int j = 0; j < 32; j++)
			sprintf(txid_hex + j*2, "%02x", leaf->txid[31-j]);
		txid_hex[64] = '\0';

		struct out_req *req = jsonrpc_request_start(acmd,
			"checkutxo",
			source_check_gettxout_reply,
			source_check_gettxout_reply,
			sctx);
		json_add_string(req->js, "txid", txid_hex);
		json_add_u32(req->js, "vout", lstock_vout);
		send_outreq(req);
		probes++;
	}
	return probes;
}

/* ============================================================
 * Phase 3c2: CPFP-via-anchor scheduler.
 *
 * For pre-signed multi-party TXs (dist, state, kickoff) that carry
 * P2A anchor outputs (per upstream factory.c construction). When the
 * parent gets stuck in mempool, we CPFP-bump by spending the anchor
 * + a wallet UTXO in a child TX with high fee. Bitcoin Core 28+
 * package relay (BIP-431) carries the bump fee back to the parent.
 *
 * State machine:
 *   PENDING   — parent broadcast, child not yet built
 *   BROADCAST — child in mempool, awaiting parent confirm
 *   CONFIRMED — parent + child both confirmed (≥1 conf each)
 *   FAILED    — wallet had no suitable UTXO; will retry next block
 *   RESOLVED  — parent confirmed without our help (network bumped)
 *
 * V1 (this PR): state machine + scheduler + dev RPCs + persistence.
 *   ss_cpfp_scheduler_tick walks entries, decides "should we bump"
 *   via htlc_fee_bump_t, and LOGS the intended action. Actual TX
 *   construction + wallet integration is Phase 3c2.5.
 *
 * V2 (Phase 3c2.5): build the child TX with libwally PSBT, sign the
 *   wallet input via CLN signpsbt RPC, broadcast via
 *   ss_broadcast_factory_tx. References upstream watchtower.c:
 *   watchtower_build_cpfp_tx (lines 964-1080).
 *
 * ============================================================ */

/* Estimated vsize of CPFP child: P2A anchor input + 1 wallet input
 * (taproot keypath) + 1 P2TR change output. Matches upstream's
 * WATCHTOWER_CPFP_CHILD_VSIZE = 264. */
#define CPFP_CHILD_VSIZE_DEFAULT 264

/* Blocks a parent must remain unconfirmed before we trigger a CPFP.
 * Conservative — most parents confirm within 1-3 blocks at correct
 * sign-time feerate. Only fire CPFP when we're past that. */
#define CPFP_TRIGGER_THRESHOLD_BLOCKS 6

/* Absolute ceiling on per-CPFP bump fee (sats). Prevents scheduler
 * runaway: htlc_fee_bump's linear-escalation near deadline can
 * budget very aggressively if parent_value_at_stake is large (e.g.
 * 25% of a 1M-sat factory = 250k sat). Hard cap here caps wallet
 * exposure per bump. Upstream has the same mechanism via
 * wt->max_bump_fee_sat (watchtower.c line 919). */
#define CPFP_MAX_BUMP_FEE_CEILING_SAT 50000

/* Scan a serialized Bitcoin TX for a P2A (Pay-to-Anchor per BIP-431)
 * output and return its vout. Returns -1 if no P2A output present
 * (e.g. factory fee was sub-1-sat/vB and anchor was skipped by
 * factory_build_*'s fee_should_use_anchor() gate).
 *
 * Parses just enough TX structure to walk outputs: version (4) +
 * optional witness marker/flag + input count + each input (outpoint
 * + scriptSig + sequence) + output count + each output (value +
 * scriptPubKey). We stop after the output loop; witness + locktime
 * aren't needed for output-script inspection.
 *
 * P2A magic: 0x51 0x02 0x4e 0x73 (OP_1 OP_PUSHBYTES_2 0x4e73) — the
 * constant BIP-431 script shape. */
static int ss_find_p2a_vout(const uint8_t *tx, size_t len)
{
	if (!tx || len < 10) return -1;
	size_t p = 4; /* skip nVersion */

	/* Optional segwit marker + flag: 0x00 0x01 */
	if (p + 2 <= len && tx[p] == 0x00 && tx[p+1] == 0x01)
		p += 2;

	/* Input count (varint — assume < 0xfd for our factory TXs which
	 * have 1 input). If varint prefix 0xfd/0xfe/0xff, bail: either
	 * malformed or too exotic to bother with. */
	if (p >= len) return -1;
	uint8_t vi = tx[p];
	if (vi >= 0xfd) return -1;
	size_t n_in = vi;
	p += 1;

	for (size_t i = 0; i < n_in; i++) {
		/* outpoint (36) + scriptSig varint + script + sequence (4) */
		if (p + 36 > len) return -1;
		p += 36;
		if (p >= len) return -1;
		uint8_t s_vi = tx[p];
		if (s_vi >= 0xfd) return -1;
		p += 1;
		p += s_vi;
		if (p + 4 > len) return -1;
		p += 4;
	}

	/* Output count varint. Again assume < 0xfd. */
	if (p >= len) return -1;
	uint8_t o_vi = tx[p];
	if (o_vi >= 0xfd) return -1;
	size_t n_out = o_vi;
	p += 1;

	for (size_t j = 0; j < n_out; j++) {
		/* 8-byte value, scriptPubKey varint, scriptPubKey. */
		if (p + 8 > len) return -1;
		p += 8;
		if (p >= len) return -1;
		uint8_t spk_vi = tx[p];
		if (spk_vi >= 0xfd) return -1;
		p += 1;
		if (p + spk_vi > len) return -1;

		/* Check for P2A: 4 bytes, 0x51 0x02 0x4e 0x73. */
		if (spk_vi == 4
		    && tx[p] == 0x51 && tx[p+1] == 0x02
		    && tx[p+2] == 0x4e && tx[p+3] == 0x73)
			return (int)j;

		p += spk_vi;
	}
	return -1;
}

static const char *cpfp_state_name(uint8_t s)
{
	switch (s) {
	case CPFP_STATE_PENDING:   return "pending";
	case CPFP_STATE_BROADCAST: return "broadcast";
	case CPFP_STATE_CONFIRMED: return "confirmed";
	case CPFP_STATE_FAILED:    return "failed";
	case CPFP_STATE_RESOLVED:  return "resolved";
	default:                   return "unknown";
	}
}

static const char *cpfp_parent_kind_name(uint8_t k)
{
	switch (k) {
	case CPFP_PARENT_DIST:    return "dist";
	case CPFP_PARENT_STATE:   return "state";
	case CPFP_PARENT_KICKOFF: return "kickoff";
	default:                  return "unknown";
	}
}

/* Register a parent TX with anchor for CPFP monitoring. Dedup by
 * parent_txid. Called from dist/state/kickoff broadcast sites. */
static void ss_register_pending_cpfp(factory_instance_t *fi,
				     uint8_t parent_kind,
				     const uint8_t *parent_txid,
				     uint32_t anchor_vout,
				     uint64_t value_at_stake,
				     uint32_t deadline_block,
				     uint32_t current_block)
{
	for (size_t i = 0; i < fi->n_pending_cpfps; i++) {
		pending_cpfp_t *e = &fi->pending_cpfps[i];
		if (memcmp(e->parent_txid, parent_txid, 32) == 0) {
			/* Already tracking; refresh deadline if caller knows
			 * better. Don't reset state — preserve any
			 * already-broadcast child. */
			if (deadline_block > e->deadline_block)
				e->deadline_block = deadline_block;
			return;
		}
	}

	if (fi->n_pending_cpfps >= MAX_PENDING_CPFPS) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "pending_cpfp: cap reached (%d) — parent not "
			   "tracked for CPFP",
			   MAX_PENDING_CPFPS);
		return;
	}

	pending_cpfp_t *pc = &fi->pending_cpfps[fi->n_pending_cpfps++];
	memset(pc, 0, sizeof(*pc));
	pc->parent_kind = parent_kind;
	pc->state = CPFP_STATE_PENDING;
	memcpy(pc->parent_txid, parent_txid, 32);
	pc->parent_vout_anchor = anchor_vout;
	pc->parent_value_at_stake = value_at_stake;
	pc->parent_broadcast_block = current_block;
	pc->deadline_block = deadline_block;

	plugin_log(plugin_handle, LOG_INFORM,
		   "pending_cpfp registered: kind=%s anchor_vout=%u "
		   "stake=%"PRIu64" deadline=%u",
		   cpfp_parent_kind_name(parent_kind), anchor_vout,
		   value_at_stake, deadline_block);
}

/* Per-block CPFP scheduler tick. Walks pending_cpfps and for each
 * entry where the parent is stuck > CPFP_TRIGGER_THRESHOLD_BLOCKS,
 * computes the target feerate via htlc_fee_bump and (in V2) builds
 * + broadcasts a CPFP child. V1 logs the intent. Returns intended-
 * bump count. */
static int ss_cpfp_scheduler_tick(struct command *cmd,
				  factory_instance_t *fi,
				  uint32_t current_block)
{
	int intents = 0;
	bool dirty = false;

	for (size_t i = 0; i < fi->n_pending_cpfps; i++) {
		pending_cpfp_t *pc = &fi->pending_cpfps[i];
		if (pc->state == CPFP_STATE_CONFIRMED
		    || pc->state == CPFP_STATE_RESOLVED)
			continue;

		/* Parent confirmed without us? V2 will check via getrawtx;
		 * for V1, rely on dev RPC to mark this. */
		if (pc->parent_confirmed_block > 0
		    && pc->state != CPFP_STATE_BROADCAST) {
			pc->state = CPFP_STATE_RESOLVED;
			plugin_log(plugin_handle, LOG_INFORM,
				   "cpfp: parent kind=%s confirmed at block %u "
				   "without our help (RESOLVED)",
				   cpfp_parent_kind_name(pc->parent_kind),
				   pc->parent_confirmed_block);
			dirty = true;
			continue;
		}

		/* Not yet stuck enough to warrant CPFP. */
		if (current_block < pc->parent_broadcast_block
		                    + CPFP_TRIGGER_THRESHOLD_BLOCKS)
			continue;

		/* Compute target feerate via htlc_fee_bump. Budget is 25%
		 * of value_at_stake (defensive — anchor CPFP is cheap). */
		htlc_fee_bump_t fb;
		htlc_fee_bump_init(&fb,
				   pc->parent_broadcast_block,
				   pc->deadline_block ? pc->deadline_block
				                      : current_block + 144,
				   pc->parent_value_at_stake,
				   25, /* budget pct */
				   CPFP_CHILD_VSIZE_DEFAULT,
				   1000);
		fb.last_feerate = pc->cpfp_last_feerate;
		fb.last_bump_block = pc->cpfp_broadcast_block;

		/* Phase 3c2.5d: clamp budget to absolute ceiling (defense
		 * against runaway escalation near deadline). */
		if (fb.budget_sat > CPFP_MAX_BUMP_FEE_CEILING_SAT)
			fb.budget_sat = CPFP_MAX_BUMP_FEE_CEILING_SAT;

		if (!htlc_fee_bump_should_bump(&fb, current_block))
			continue;

		uint64_t target_feerate =
			htlc_fee_bump_calc_feerate(&fb, current_block);

		plugin_log(plugin_handle, LOG_INFORM,
			   "cpfp_scheduler: BUMP kind=%s parent_vout=%u "
			   "target_feerate=%"PRIu64" sat/kvB last=%"PRIu64
			   " sat/kvB blocks_remaining=%u — building child",
			   cpfp_parent_kind_name(pc->parent_kind),
			   pc->parent_vout_anchor,
			   target_feerate, pc->cpfp_last_feerate,
			   htlc_fee_bump_blocks_remaining(&fb, current_block));

		/* Phase 3c2.5d: kick off the async build → sign → send
		 * chain. The tick itself returns immediately; the chain
		 * updates pc->state via scheduler_cpfp_* callbacks. Each
		 * CPFP uses its own aux_command so replies outlive the
		 * notification cmd that invoked the tick. */
		ss_scheduler_launch_cpfp(cmd, fi, i, target_feerate);
		intents++;
	}

	if (dirty)
		ss_save_factory(cmd, fi);
	return intents;
}

/* ============================================================
 * Phase 3c2.5a: Wallet integration helpers.
 *
 * Async helpers for the CPFP-via-anchor pipeline. v1 provides the two
 * wallet-facing primitives needed by Phase 3c2.5b (PSBT construction):
 *
 *   ss_pick_wallet_utxo  — listfunds → pick smallest confirmed UTXO
 *                          whose amount >= min_amount_sat. Invokes the
 *                          caller's done_cb with (txid, vout, amount,
 *                          scriptpubkey_hex, address).
 *   ss_get_change_p2tr   — newaddr p2tr → the returned bech32m
 *                          address. Caller decodes to scriptPubKey in
 *                          3c2.5b.
 *
 * Both helpers are caller-lifetime-safe: they chain jsonrpc_request_start
 * on the cmd passed in. If caller is an RPC handler, that cmd lives
 * through command_finished; done_cb calls command_finished on the
 * ORIGINAL cmd. If caller is a scheduler/notification handler, caller
 * is expected to aux_command-wrap BEFORE invoking and pass the aux cmd
 * as both the helper parent and the done-cb's target.
 *
 * UTXO selection policy: smallest-viable. Picking the smallest UTXO
 * >= min_amount minimizes wallet lock-up (we free the smallest coin
 * that fits rather than e.g. our biggest). Matches typical wallet
 * coin-selection heuristics.
 *
 * Race note: between listfunds and signpsbt there's a small window
 * where another CLN operation could consume the chosen UTXO. Phase
 * 3c2.5b will add reserveinputs to close this. v1 accepts the race
 * for scaffolding simplicity.
 * ============================================================ */

/* Caller-provided done callback signature. Return the command_result
 * the caller wants propagated (typically command_finished from a
 * json_stream). Must NOT keep references to txid_hex/spk_hex/address
 * beyond the call — they're tal'd on tmpctx and will be freed. */
typedef struct command_result *
(*utxo_pick_done_cb)(struct command *cmd,
		     void *arg,
		     const char *txid_hex,
		     uint32_t vout,
		     uint64_t amount_sat,
		     const char *spk_hex,
		     const char *address);

/* Caller-provided failure callback. Return the command_result the
 * caller wants propagated. Reason is stable for tests to switch on:
 * "no_confirmed_utxo", "rpc_error", "listfunds_parse",
 * "listfunds_field_missing", "listfunds_vout_parse". */
typedef struct command_result *
(*utxo_pick_fail_cb)(struct command *cmd,
		     void *arg,
		     const char *reason);

struct utxo_pick_ctx {
	uint64_t min_amount_sat;
	utxo_pick_done_cb done_cb;
	utxo_pick_fail_cb fail_cb;
	void *arg;
};

static struct command_result *
utxo_pick_listfunds_reply(struct command *cmd,
			  const char *method UNUSED,
			  const char *buf,
			  const jsmntok_t *result,
			  void *arg)
{
	struct utxo_pick_ctx *ctx = (struct utxo_pick_ctx *)arg;

	const jsmntok_t *outputs =
		json_get_member(buf, result, "outputs");
	if (!outputs || outputs->type != JSMN_ARRAY)
		return ctx->fail_cb(cmd, ctx->arg, "listfunds_parse");

	/* Iterate, track smallest-viable. Fields we care about:
	 *   txid, output (= vout), amount_msat, scriptpubkey, address,
	 *   status (= "confirmed"), reserved (= false). */
	const jsmntok_t *best = NULL;
	uint64_t best_amount = UINT64_MAX;

	const jsmntok_t *t;
	size_t i;
	json_for_each_arr(i, t, outputs) {
		const jsmntok_t *status_tok =
			json_get_member(buf, t, "status");
		const jsmntok_t *reserved_tok =
			json_get_member(buf, t, "reserved");
		const jsmntok_t *amt_tok =
			json_get_member(buf, t, "amount_msat");
		if (!status_tok || !reserved_tok || !amt_tok) continue;

		/* Reject non-confirmed. */
		if (!json_tok_streq(buf, status_tok, "confirmed"))
			continue;

		/* Reject reserved. CLN emits true/false as JSON booleans. */
		bool reserved_flag;
		if (!json_to_bool(buf, reserved_tok, &reserved_flag))
			continue;
		if (reserved_flag)
			continue;

		u64 amt_msat;
		if (!json_to_u64(buf, amt_tok, &amt_msat))
			continue;
		uint64_t amt_sat = amt_msat / 1000;
		if (amt_sat < ctx->min_amount_sat)
			continue;

		if (amt_sat < best_amount) {
			best_amount = amt_sat;
			best = t;
		}
	}

	if (!best)
		return ctx->fail_cb(cmd, ctx->arg, "no_confirmed_utxo");

	const jsmntok_t *txid_tok = json_get_member(buf, best, "txid");
	const jsmntok_t *vout_tok = json_get_member(buf, best, "output");
	const jsmntok_t *spk_tok =
		json_get_member(buf, best, "scriptpubkey");
	const jsmntok_t *addr_tok = json_get_member(buf, best, "address");
	if (!txid_tok || !vout_tok || !spk_tok || !addr_tok)
		return ctx->fail_cb(cmd, ctx->arg,
				    "listfunds_field_missing");

	char *txid_hex = json_strdup(tmpctx, buf, txid_tok);
	char *spk_hex = json_strdup(tmpctx, buf, spk_tok);
	char *addr = json_strdup(tmpctx, buf, addr_tok);
	u32 vout_u32;
	if (!json_to_u32(buf, vout_tok, &vout_u32))
		return ctx->fail_cb(cmd, ctx->arg, "listfunds_vout_parse");

	return ctx->done_cb(cmd, ctx->arg, txid_hex, vout_u32, best_amount,
			    spk_hex, addr);
}

static struct command_result *
utxo_pick_listfunds_err(struct command *cmd,
			const char *method UNUSED,
			const char *buf UNUSED,
			const jsmntok_t *result UNUSED,
			void *arg)
{
	struct utxo_pick_ctx *ctx = (struct utxo_pick_ctx *)arg;
	return ctx->fail_cb(cmd, ctx->arg, "rpc_error");
}

/* Kick off the listfunds → pick pipeline. done_cb fires on success with
 * the chosen UTXO's fields; fail_cb on any failure (RPC error, no viable
 * UTXO, parse error). Exactly one of the two callbacks will fire. */
static void ss_pick_wallet_utxo(struct command *cmd,
				uint64_t min_amount_sat,
				utxo_pick_done_cb done_cb,
				utxo_pick_fail_cb fail_cb,
				void *arg)
{
	struct utxo_pick_ctx *ctx = tal(cmd, struct utxo_pick_ctx);
	ctx->min_amount_sat = min_amount_sat;
	ctx->done_cb = done_cb;
	ctx->fail_cb = fail_cb;
	ctx->arg = arg;

	struct out_req *req = jsonrpc_request_start(cmd, "listfunds",
		utxo_pick_listfunds_reply,
		utxo_pick_listfunds_err,
		ctx);
	/* listfunds has a "spent" boolean param (optional) — default
	 * false, which excludes spent UTXOs. No other params we need. */
	send_outreq(req);
}

/* === change-address helper === */

typedef struct command_result *
(*change_addr_done_cb)(struct command *cmd,
		       void *arg,
		       const char *address);

typedef struct command_result *
(*change_addr_fail_cb)(struct command *cmd,
		       void *arg,
		       const char *reason);

struct change_addr_ctx {
	change_addr_done_cb done_cb;
	change_addr_fail_cb fail_cb;
	void *arg;
};

static struct command_result *
change_addr_newaddr_reply(struct command *cmd,
			  const char *method UNUSED,
			  const char *buf,
			  const jsmntok_t *result,
			  void *arg)
{
	struct change_addr_ctx *ctx = (struct change_addr_ctx *)arg;
	const jsmntok_t *p2tr_tok = json_get_member(buf, result, "p2tr");
	if (!p2tr_tok)
		return ctx->fail_cb(cmd, ctx->arg, "newaddr_parse");
	char *addr = json_strdup(tmpctx, buf, p2tr_tok);
	return ctx->done_cb(cmd, ctx->arg, addr);
}

static struct command_result *
change_addr_newaddr_err(struct command *cmd,
			const char *method UNUSED,
			const char *buf UNUSED,
			const jsmntok_t *result UNUSED,
			void *arg)
{
	struct change_addr_ctx *ctx = (struct change_addr_ctx *)arg;
	return ctx->fail_cb(cmd, ctx->arg, "rpc_error");
}

/* Request a fresh P2TR change address. CLN's newaddr p2tr returns a
 * bech32m address; Phase 3c2.5b will decode it to the 34-byte
 * scriptPubKey (OP_1 OP_PUSHBYTES_32 <x-only>). */
static void ss_get_change_p2tr(struct command *cmd,
			       change_addr_done_cb done_cb,
			       change_addr_fail_cb fail_cb,
			       void *arg)
{
	struct change_addr_ctx *ctx = tal(cmd, struct change_addr_ctx);
	ctx->done_cb = done_cb;
	ctx->fail_cb = fail_cb;
	ctx->arg = arg;

	struct out_req *req = jsonrpc_request_start(cmd, "newaddr",
		change_addr_newaddr_reply,
		change_addr_newaddr_err,
		ctx);
	json_add_string(req->js, "addresstype", "p2tr");
	send_outreq(req);
}

/* ============================================================
 * Phase 3c2.5b: CPFP child PSBT construction.
 *
 * Composes the Phase 3c2.5a helpers (pick_wallet_utxo +
 * get_change_p2tr) and builds an unsigned PSBT shaped for CPFP
 * against a pre-signed parent TX with P2A anchor:
 *
 *   vin[0]: parent_txid:anchor_vout  (P2A, 240 sats, anyone-can-spend)
 *   vin[1]: wallet_utxo              (CLN wallet, signed by 3c2.5c)
 *   vout[0]: change (P2TR to LSP wallet)
 *
 * Witness UTXOs are populated on both inputs so signpsbt has amounts
 * to sign against. Signing + finalization + broadcast happens in
 * Phase 3c2.5c.
 *
 * Fee math: CPFP_CHILD_VSIZE_DEFAULT (264 vbytes) × target_feerate_kvb
 * / 1000. Phase 3c2.5c will tie target_feerate to htlc_fee_bump's
 * linear schedule.
 * ============================================================ */

/* BIP-431 Pay-to-Anchor scriptPubKey: OP_1 OP_PUSHBYTES_2 0x4e73.
 * Matches upstream channel.h:P2A_SPK. */
static const uint8_t CPFP_P2A_SPK[4] = {0x51, 0x02, 0x4e, 0x73};
#define CPFP_P2A_SPK_LEN 4

/* Standard P2A anchor amount on SuperScalar-built dist/state/kickoff
 * TXs. Matches upstream factory.c ANCHOR_OUTPUT_AMOUNT. */
#define CPFP_ANCHOR_AMOUNT_SAT 240

/* Dust limit for P2TR outputs (Bitcoin Core 28+). Change below this
 * is rolled into fee instead of creating a dust output. */
#define CPFP_CHANGE_DUST_LIMIT_SAT 294

/* Build an unsigned CPFP child PSBT. Returns base64 string on success
 * (tal-allocated on ctx), NULL on failure. Failure modes: insufficient
 * wallet input to cover fee, change below dust, address decode error. */
static char *ss_build_cpfp_child_psbt(
	const tal_t *ctx,
	const uint8_t *parent_txid,     /* 32 bytes, internal byte order */
	uint32_t anchor_vout,
	const uint8_t *wallet_txid,     /* 32 bytes, internal byte order */
	uint32_t wallet_vout,
	uint64_t wallet_amount_sat,
	const uint8_t *wallet_spk,      /* wallet UTXO's scriptPubKey */
	size_t wallet_spk_len,
	const char *change_address,     /* bech32m P2TR */
	uint64_t target_feerate_sat_per_kvb,
	const char **err_out)
{
	*err_out = NULL;

	/* Fee estimate: vsize × feerate / 1000. Round up. */
	uint64_t fee_sat = (target_feerate_sat_per_kvb
			    * CPFP_CHILD_VSIZE_DEFAULT + 999) / 1000;

	uint64_t total_in = (uint64_t)CPFP_ANCHOR_AMOUNT_SAT
			    + wallet_amount_sat;
	if (total_in <= fee_sat) {
		*err_out = "wallet_insufficient";
		return NULL;
	}
	uint64_t change_sat = total_in - fee_sat;
	if (change_sat < CPFP_CHANGE_DUST_LIMIT_SAT) {
		*err_out = "change_dust";
		return NULL;
	}

	/* Decode change address via CLN's chainparams-aware decoder. */
	u8 *change_spk = NULL;
	if (!decode_scriptpubkey_from_addr(ctx, chainparams,
					    change_address, &change_spk)) {
		*err_out = "change_addr_decode";
		return NULL;
	}

	/* Create empty PSBT with nLockTime=0. */
	struct wally_psbt *psbt = create_psbt(ctx, 0, 0, 0);
	if (!psbt) {
		*err_out = "psbt_create";
		return NULL;
	}

	/* Input 0: anchor from parent. sequence=0xFFFFFFFE (RBF signal). */
	struct bitcoin_outpoint anchor_op;
	memcpy(&anchor_op.txid, parent_txid, 32);
	anchor_op.n = anchor_vout;
	struct wally_psbt_input *anchor_in =
		psbt_append_input(psbt, &anchor_op, 0xFFFFFFFE,
				  NULL, NULL, NULL);
	if (!anchor_in) {
		*err_out = "psbt_append_anchor";
		return NULL;
	}
	/* CLN's psbt_input_set_wit_utxo derives length from tal_count —
	 * pass a tal_arr copy rather than the static const. */
	u8 *anchor_spk_tal = tal_dup_arr(psbt, u8, CPFP_P2A_SPK,
					 CPFP_P2A_SPK_LEN, 0);
	psbt_input_set_wit_utxo(psbt, 0, anchor_spk_tal,
				AMOUNT_SAT(CPFP_ANCHOR_AMOUNT_SAT));

	/* Input 1: wallet UTXO. */
	struct bitcoin_outpoint wallet_op;
	memcpy(&wallet_op.txid, wallet_txid, 32);
	wallet_op.n = wallet_vout;
	struct wally_psbt_input *wallet_in =
		psbt_append_input(psbt, &wallet_op, 0xFFFFFFFE,
				  NULL, NULL, NULL);
	if (!wallet_in) {
		*err_out = "psbt_append_wallet";
		return NULL;
	}
	u8 *wallet_spk_tal = tal_dup_arr(psbt, u8, wallet_spk,
					 wallet_spk_len, 0);
	psbt_input_set_wit_utxo(psbt, 1, wallet_spk_tal,
				AMOUNT_SAT(wallet_amount_sat));

	/* Output 0: P2TR change back to wallet. */
	psbt_append_output(psbt, change_spk, AMOUNT_SAT(change_sat));

	/* Encode to base64. fmt_wally_psbt returns tal-allocated. */
	char *b64 = fmt_wally_psbt(ctx, psbt);
	if (!b64) {
		*err_out = "psbt_encode";
		return NULL;
	}
	return b64;
}

/* Decode a hex-encoded txid string into internal byte order (reversed
 * from display). Returns true on success, false on malformed input. */
static bool ss_hex_txid_to_internal(const char *hex, uint8_t *out32)
{
	if (strlen(hex) != 64) return false;
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(hex + j*2, "%02x", &b) != 1)
			return false;
		out32[31 - j] = (uint8_t)b;
	}
	return true;
}

/* Decode a hex string into bytes. Caller provides buffer of len/2
 * bytes. Returns true on success, false on malformed/odd-length. */
static bool ss_hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
	size_t hex_len = strlen(hex);
	if (hex_len != out_len * 2) return false;
	for (size_t j = 0; j < out_len; j++) {
		unsigned int b;
		if (sscanf(hex + j*2, "%02x", &b) != 1)
			return false;
		out[j] = (uint8_t)b;
	}
	return true;
}

/* Async wrapper: chain pick_wallet_utxo → get_change_p2tr → build PSBT
 * → invoke caller's done_cb with the base64 PSBT. Caller supplies the
 * parent_txid + anchor_vout + target_feerate; we fetch everything else
 * from the wallet. */

typedef struct command_result *
(*cpfp_build_done_cb)(struct command *cmd,
		      void *arg,
		      const char *psbt_b64,
		      const char *wallet_txid_hex,
		      uint32_t wallet_vout,
		      uint64_t wallet_amount_sat,
		      const char *change_address);

typedef struct command_result *
(*cpfp_build_fail_cb)(struct command *cmd,
		      void *arg,
		      const char *reason);

struct cpfp_build_ctx {
	uint8_t parent_txid[32];  /* internal BE */
	uint32_t anchor_vout;
	uint64_t target_feerate_sat_per_kvb;

	/* Filled in as the async chain progresses. */
	uint8_t wallet_txid_be[32];
	char *wallet_txid_hex;
	uint32_t wallet_vout;
	uint64_t wallet_amount_sat;
	uint8_t *wallet_spk;
	size_t wallet_spk_len;

	cpfp_build_done_cb done_cb;
	cpfp_build_fail_cb fail_cb;
	void *arg;
};

static struct command_result *
cpfp_build_change_addr_done(struct command *cmd,
			    void *arg,
			    const char *address);

static struct command_result *
cpfp_build_change_addr_fail(struct command *cmd,
			    void *arg,
			    const char *reason)
{
	struct cpfp_build_ctx *ctx = (struct cpfp_build_ctx *)arg;
	return ctx->fail_cb(cmd, ctx->arg, reason);
}

static struct command_result *
cpfp_build_utxo_done(struct command *cmd,
		     void *arg,
		     const char *txid_hex,
		     uint32_t vout,
		     uint64_t amount_sat,
		     const char *spk_hex,
		     const char *address UNUSED)
{
	struct cpfp_build_ctx *ctx = (struct cpfp_build_ctx *)arg;

	if (!ss_hex_txid_to_internal(txid_hex, ctx->wallet_txid_be))
		return ctx->fail_cb(cmd, ctx->arg, "wallet_txid_parse");

	ctx->wallet_txid_hex = tal_strdup(ctx, txid_hex);
	ctx->wallet_vout = vout;
	ctx->wallet_amount_sat = amount_sat;

	size_t spk_bytes_len = strlen(spk_hex) / 2;
	ctx->wallet_spk = tal_arr(ctx, uint8_t, spk_bytes_len);
	if (!ss_hex_to_bytes(spk_hex, ctx->wallet_spk, spk_bytes_len))
		return ctx->fail_cb(cmd, ctx->arg, "wallet_spk_parse");
	ctx->wallet_spk_len = spk_bytes_len;

	/* Next step: get a change address. */
	ss_get_change_p2tr(cmd,
			   cpfp_build_change_addr_done,
			   cpfp_build_change_addr_fail,
			   ctx);
	return command_still_pending(cmd);
}

static struct command_result *
cpfp_build_utxo_fail(struct command *cmd,
		     void *arg,
		     const char *reason)
{
	struct cpfp_build_ctx *ctx = (struct cpfp_build_ctx *)arg;
	return ctx->fail_cb(cmd, ctx->arg, reason);
}

static struct command_result *
cpfp_build_change_addr_done(struct command *cmd,
			    void *arg,
			    const char *address)
{
	struct cpfp_build_ctx *ctx = (struct cpfp_build_ctx *)arg;

	const char *err = NULL;
	char *psbt_b64 = ss_build_cpfp_child_psbt(
		ctx,
		ctx->parent_txid, ctx->anchor_vout,
		ctx->wallet_txid_be, ctx->wallet_vout,
		ctx->wallet_amount_sat,
		ctx->wallet_spk, ctx->wallet_spk_len,
		address,
		ctx->target_feerate_sat_per_kvb,
		&err);
	if (!psbt_b64)
		return ctx->fail_cb(cmd, ctx->arg,
				    err ? err : "psbt_build_unknown");

	return ctx->done_cb(cmd, ctx->arg, psbt_b64,
			    ctx->wallet_txid_hex,
			    ctx->wallet_vout,
			    ctx->wallet_amount_sat,
			    address);
}

/* Public entry: async-build an unsigned CPFP child PSBT. Requires the
 * LSP wallet to have a spendable UTXO >= bump_fee + dust. */
static void ss_build_cpfp_child(struct command *cmd,
				const uint8_t *parent_txid,
				uint32_t anchor_vout,
				uint64_t target_feerate_sat_per_kvb,
				cpfp_build_done_cb done_cb,
				cpfp_build_fail_cb fail_cb,
				void *arg)
{
	struct cpfp_build_ctx *ctx = tal(cmd, struct cpfp_build_ctx);
	memcpy(ctx->parent_txid, parent_txid, 32);
	ctx->anchor_vout = anchor_vout;
	ctx->target_feerate_sat_per_kvb = target_feerate_sat_per_kvb;
	ctx->wallet_spk = NULL;
	ctx->wallet_spk_len = 0;
	ctx->wallet_txid_hex = NULL;
	ctx->done_cb = done_cb;
	ctx->fail_cb = fail_cb;
	ctx->arg = arg;

	/* Pick UTXO sized for: bump_fee + generous dust margin. */
	uint64_t bump_fee = (target_feerate_sat_per_kvb
			     * CPFP_CHILD_VSIZE_DEFAULT + 999) / 1000;
	uint64_t min_amount = bump_fee + CPFP_CHANGE_DUST_LIMIT_SAT
			      + CPFP_ANCHOR_AMOUNT_SAT;
	/* Subtract anchor contribution: it covers some of the fee. */
	if (min_amount > CPFP_ANCHOR_AMOUNT_SAT)
		min_amount -= CPFP_ANCHOR_AMOUNT_SAT;

	ss_pick_wallet_utxo(cmd, min_amount,
			    cpfp_build_utxo_done,
			    cpfp_build_utxo_fail,
			    ctx);
}

/* ============================================================
 * Phase 3c2.5c: sign + send the CPFP child.
 *
 * Async chain on top of 3c2.5b's ss_build_cpfp_child:
 *
 *   1. reserveinputs psbt        — lock the wallet UTXO (closes the
 *                                  race window between listfunds and
 *                                  signpsbt)
 *   2. signpsbt psbt             — CLN signs the wallet input
 *   3. sendpsbt signed_psbt      — finalize + extract + broadcast
 *
 * The P2A anchor input is anyone-can-spend per BIP-431. sendpsbt's
 * finalization should handle it (empty witness). If sendpsbt errors
 * because it can't finalize the anchor input, the fail_cb reports
 * "sendpsbt_failed" and operator investigates — at which point we'd
 * add explicit libwally final_scriptwitness population before
 * sendpsbt as a v2 fix.
 *
 * On any failure after reservation, we fire unreserveinputs to free
 * the wallet UTXO. On success, done_cb is invoked with the final
 * child's txid (extracted from sendpsbt's response).
 * ============================================================ */

typedef struct command_result *
(*cpfp_send_done_cb)(struct command *cmd,
		     void *arg,
		     const char *child_txid_hex);

typedef struct command_result *
(*cpfp_send_fail_cb)(struct command *cmd,
		     void *arg,
		     const char *reason);

struct cpfp_send_ctx {
	/* Preserved across the async chain. */
	char *signed_psbt;          /* set after signpsbt reply */

	cpfp_send_done_cb done_cb;
	cpfp_send_fail_cb fail_cb;
	void *arg;
};

/* Unreserve on error — fire-and-forget, we don't block the fail_cb
 * on it completing. The reserved UTXO auto-frees after
 * reserved_to_block anyway (~72 blocks from reserveinputs default). */
static struct command_result *
cpfp_send_unreserve_noop(struct command *cmd UNUSED,
			 const char *method UNUSED,
			 const char *buf UNUSED,
			 const jsmntok_t *result UNUSED,
			 void *arg UNUSED)
{
	return command_still_pending(cmd);
}

static void cpfp_send_best_effort_unreserve(struct command *cmd,
					    const char *psbt_b64)
{
	struct out_req *req = jsonrpc_request_start(cmd,
		"unreserveinputs",
		cpfp_send_unreserve_noop,
		cpfp_send_unreserve_noop,
		NULL);
	json_add_string(req->js, "psbt", psbt_b64);
	send_outreq(req);
}

static struct command_result *
cpfp_send_sendpsbt_reply(struct command *cmd,
			 const char *method UNUSED,
			 const char *buf,
			 const jsmntok_t *result,
			 void *arg)
{
	struct cpfp_send_ctx *ctx = (struct cpfp_send_ctx *)arg;

	const jsmntok_t *txid_tok = json_get_member(buf, result, "txid");
	if (!txid_tok) {
		/* sendpsbt should always return txid on success; absence
		 * means something's off. Unreserve and report. */
		cpfp_send_best_effort_unreserve(cmd, ctx->signed_psbt);
		return ctx->fail_cb(cmd, ctx->arg, "sendpsbt_no_txid");
	}
	char *txid = json_strdup(tmpctx, buf, txid_tok);
	return ctx->done_cb(cmd, ctx->arg, txid);
}

static struct command_result *
cpfp_send_sendpsbt_err(struct command *cmd,
		       const char *method UNUSED,
		       const char *buf UNUSED,
		       const jsmntok_t *result UNUSED,
		       void *arg)
{
	struct cpfp_send_ctx *ctx = (struct cpfp_send_ctx *)arg;
	cpfp_send_best_effort_unreserve(cmd, ctx->signed_psbt);
	return ctx->fail_cb(cmd, ctx->arg, "sendpsbt_failed");
}

static struct command_result *
cpfp_send_signpsbt_reply(struct command *cmd,
			 const char *method UNUSED,
			 const char *buf,
			 const jsmntok_t *result,
			 void *arg)
{
	struct cpfp_send_ctx *ctx = (struct cpfp_send_ctx *)arg;

	const jsmntok_t *signed_tok =
		json_get_member(buf, result, "signed_psbt");
	if (!signed_tok)
		return ctx->fail_cb(cmd, ctx->arg, "signpsbt_no_result");

	ctx->signed_psbt = json_strdup(ctx, buf, signed_tok);

	struct out_req *req = jsonrpc_request_start(cmd, "sendpsbt",
		cpfp_send_sendpsbt_reply,
		cpfp_send_sendpsbt_err,
		ctx);
	json_add_string(req->js, "psbt", ctx->signed_psbt);
	send_outreq(req);
	return command_still_pending(cmd);
}

static struct command_result *
cpfp_send_signpsbt_err(struct command *cmd,
		       const char *method UNUSED,
		       const char *buf UNUSED,
		       const jsmntok_t *result UNUSED,
		       void *arg)
{
	struct cpfp_send_ctx *ctx = (struct cpfp_send_ctx *)arg;
	/* signpsbt can fail if CLN doesn't own the input (shouldn't
	 * happen — we got the UTXO from listfunds). Unreserve the
	 * UTXO (reserveinputs already ran) and surface the failure. */
	(void)ctx;  /* ctx->signed_psbt not yet populated */
	return ctx->fail_cb(cmd, ctx->arg, "signpsbt_failed");
}

static struct command_result *
cpfp_send_reserve_reply(struct command *cmd,
			const char *method UNUSED,
			const char *buf UNUSED,
			const jsmntok_t *result UNUSED,
			void *arg)
{
	struct cpfp_send_ctx *ctx = (struct cpfp_send_ctx *)arg;

	/* reserveinputs returns reservation details; we don't inspect —
	 * just proceed to signpsbt. */
	struct out_req *req = jsonrpc_request_start(cmd, "signpsbt",
		cpfp_send_signpsbt_reply,
		cpfp_send_signpsbt_err,
		ctx);
	json_add_string(req->js, "psbt", ctx->signed_psbt);
	send_outreq(req);
	return command_still_pending(cmd);
}

static struct command_result *
cpfp_send_reserve_err(struct command *cmd,
		      const char *method UNUSED,
		      const char *buf UNUSED,
		      const jsmntok_t *result UNUSED,
		      void *arg)
{
	struct cpfp_send_ctx *ctx = (struct cpfp_send_ctx *)arg;
	return ctx->fail_cb(cmd, ctx->arg, "reserve_failed");
}

/* Public: sign + send a CPFP child built by ss_build_cpfp_child.
 * Takes ownership of psbt_b64 (tal-reparents into ctx).
 *
 * done_cb fires on successful broadcast with child_txid_hex. fail_cb
 * on any failure — wallet UTXO is released (best-effort) before
 * fail_cb invokes. Exactly one of done/fail fires per call. */
static void ss_cpfp_sign_and_send(struct command *cmd,
				  const char *psbt_b64,
				  cpfp_send_done_cb done_cb,
				  cpfp_send_fail_cb fail_cb,
				  void *arg)
{
	struct cpfp_send_ctx *ctx = tal(cmd, struct cpfp_send_ctx);
	ctx->signed_psbt = tal_strdup(ctx, psbt_b64);
	ctx->done_cb = done_cb;
	ctx->fail_cb = fail_cb;
	ctx->arg = arg;

	struct out_req *req = jsonrpc_request_start(cmd, "reserveinputs",
		cpfp_send_reserve_reply,
		cpfp_send_reserve_err,
		ctx);
	json_add_string(req->js, "psbt", ctx->signed_psbt);
	send_outreq(req);
}

/* ============================================================
 * Phase 3c2.5d: scheduler → CPFP integration.
 *
 * ss_scheduler_launch_cpfp is the glue that ss_cpfp_scheduler_tick
 * calls when htlc_fee_bump decides it's time to bump a pending parent.
 * Fires the async build → sign → send chain on an aux_command (so
 * callbacks survive the block_added notification's cmd lifetime),
 * then updates the pending_cpfp_t on success or failure.
 *
 * Defensive: the pc_idx captured at launch time could be stale if
 * pending_cpfps[] is concurrently modified. Done callback
 * cross-checks parent_txid match before writing to the entry.
 * ============================================================ */

struct scheduler_cpfp_ctx {
	factory_instance_t *fi;
	size_t pc_idx;
	uint8_t parent_txid_snap[32]; /* captured for staleness check */
	uint64_t target_feerate;
};

/* Find entry matching parent_txid — guards against pc_idx going
 * stale between launch and async callback. */
static pending_cpfp_t *
scheduler_cpfp_lookup(factory_instance_t *fi,
		      const uint8_t parent_txid[32])
{
	for (size_t i = 0; i < fi->n_pending_cpfps; i++) {
		if (memcmp(fi->pending_cpfps[i].parent_txid,
			   parent_txid, 32) == 0)
			return &fi->pending_cpfps[i];
	}
	return NULL;
}

static struct command_result *
scheduler_cpfp_sent(struct command *cmd,
		    void *arg,
		    const char *child_txid_hex)
{
	struct scheduler_cpfp_ctx *sctx =
		(struct scheduler_cpfp_ctx *)arg;
	pending_cpfp_t *pc = scheduler_cpfp_lookup(sctx->fi,
						   sctx->parent_txid_snap);
	if (!pc) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "cpfp_scheduler: pending entry vanished during "
			   "broadcast (child_txid=%s). Ignoring.",
			   child_txid_hex);
		return aux_command_done(cmd);
	}

	/* Store child txid in internal byte order. */
	ss_hex_txid_to_internal(child_txid_hex, pc->cpfp_txid);
	pc->cpfp_broadcast_block = ss_state.current_blockheight;
	pc->cpfp_last_feerate = sctx->target_feerate;
	pc->state = CPFP_STATE_BROADCAST;
	ss_save_factory(cmd, sctx->fi);

	plugin_log(plugin_handle, LOG_INFORM,
		   "cpfp_scheduler: child broadcast (txid=%s feerate=%"PRIu64
		   " sat/kvB). Parent should pull in via package relay.",
		   child_txid_hex, sctx->target_feerate);
	return aux_command_done(cmd);
}

static struct command_result *
scheduler_cpfp_send_failed(struct command *cmd,
			   void *arg,
			   const char *reason)
{
	struct scheduler_cpfp_ctx *sctx =
		(struct scheduler_cpfp_ctx *)arg;
	pending_cpfp_t *pc = scheduler_cpfp_lookup(sctx->fi,
						   sctx->parent_txid_snap);
	if (pc) {
		pc->state = CPFP_STATE_FAILED;
		ss_save_factory(cmd, sctx->fi);
	}
	plugin_log(plugin_handle, LOG_UNUSUAL,
		   "cpfp_scheduler: send failed (%s). Next tick will retry "
		   "if parent still unconfirmed.", reason);
	/* Reset FAILED back to PENDING on next tick so we can retry:
	 * the failure might have been transient (reserveinputs race,
	 * temporary bitcoind backpressure). But don't do it here —
	 * the tick's own can_bump check will handle state transition. */
	return aux_command_done(cmd);
}

static struct command_result *
scheduler_cpfp_built(struct command *cmd,
		     void *arg,
		     const char *psbt_b64,
		     const char *wallet_txid_hex UNUSED,
		     uint32_t wallet_vout UNUSED,
		     uint64_t wallet_amount_sat UNUSED,
		     const char *change_address UNUSED)
{
	struct scheduler_cpfp_ctx *sctx =
		(struct scheduler_cpfp_ctx *)arg;
	ss_cpfp_sign_and_send(cmd, psbt_b64,
			      scheduler_cpfp_sent,
			      scheduler_cpfp_send_failed,
			      sctx);
	return command_still_pending(cmd);
}

static struct command_result *
scheduler_cpfp_build_failed(struct command *cmd,
			    void *arg,
			    const char *reason)
{
	struct scheduler_cpfp_ctx *sctx =
		(struct scheduler_cpfp_ctx *)arg;
	pending_cpfp_t *pc = scheduler_cpfp_lookup(sctx->fi,
						   sctx->parent_txid_snap);
	if (pc) {
		pc->state = CPFP_STATE_FAILED;
		ss_save_factory(cmd, sctx->fi);
	}
	plugin_log(plugin_handle, LOG_UNUSUAL,
		   "cpfp_scheduler: build failed (%s). Retry on next tick "
		   "if parent still unconfirmed.", reason);
	return aux_command_done(cmd);
}

/* Kick off a CPFP via the Phase 3c2.5b/c async chain. The aux_command
 * wrap ensures reply callbacks outlive the block_added notification
 * that invoked ss_cpfp_scheduler_tick. */
static void ss_scheduler_launch_cpfp(struct command *cmd,
				     factory_instance_t *fi,
				     size_t pc_idx,
				     uint64_t target_feerate)
{
	pending_cpfp_t *pc = &fi->pending_cpfps[pc_idx];
	struct command *acmd = aux_command(cmd);
	struct scheduler_cpfp_ctx *sctx =
		tal(acmd, struct scheduler_cpfp_ctx);
	sctx->fi = fi;
	sctx->pc_idx = pc_idx;
	memcpy(sctx->parent_txid_snap, pc->parent_txid, 32);
	sctx->target_feerate = target_feerate;

	ss_build_cpfp_child(acmd,
			    pc->parent_txid,
			    pc->parent_vout_anchor,
			    target_feerate,
			    scheduler_cpfp_built,
			    scheduler_cpfp_build_failed,
			    sctx);
}

/* ============================================================
 * Phase 4d: CSV claim scheduler.
 *
 * Algorithm ported from upstream sweeper.c:sweeper_check (see
 * feedback_reuse_superscalar_upstream). Walks the pending_sweeps
 * array every block and advances entries through the state machine:
 *
 *   PENDING   — source TX not yet confirmed; check confs, record
 *               confirmed_block when >=1
 *   READY     — source confirmed AND CSV window expired; log that
 *               the entry is ready for sweep TX construction
 *   BROADCAST — (Phase 4d2) a sweep TX has been sent; check its
 *               confirmations
 *   CONFIRMED — sweep tx has >=3 confs; entry is done
 *
 * Phase 4d v1 landed the scaffolding: it logs PENDING→READY
 * transitions. Actual sweep-TX construction + broadcast is deferred
 * to 4d2 when we identify concrete leaf-output sweep cases.
 * ============================================================ */

/* Minimum confirmations before we consider a sweep done. Matches
 * upstream sweeper.c's 3-conf threshold. */
#define SWEEP_CONFIRM_THRESHOLD 3

/* Phase 4d3: FAILED → READY retry gate. After a broadcast rejection
 * (bitcoind -25 missing inputs, mempool conflict, etc.) we cool down
 * for a few blocks, then retry. Retry count is stored in
 * pending_sweep_t.reserved[0] so persistence layout is unchanged.
 * Three attempts before we give up and leave state FAILED for
 * operator attention. */
#define SS_SWEEP_RETRY_DELAY_BLOCKS 6
#define SS_SWEEP_MAX_RETRIES 3

/* Register a new pending sweep. Dedup by (source_txid, source_vout).
 * Called from the post-close paths (Phase 4d2 entry points) when we
 * identify an output that will mature after a CSV window. */
static void ss_register_pending_sweep(factory_instance_t *fi,
				      uint8_t type,
				      const uint8_t *source_txid,
				      uint32_t source_vout,
				      uint64_t amount_sats,
				      uint32_t csv_delay)
{
	/* Dedup. */
	for (size_t i = 0; i < fi->n_pending_sweeps; i++) {
		pending_sweep_t *existing = &fi->pending_sweeps[i];
		if (memcmp(existing->source_txid, source_txid, 32) == 0
		    && existing->source_vout == source_vout) {
			/* Already tracking; refresh the amount/csv in case
			 * caller learned new info. */
			existing->amount_sats = amount_sats;
			existing->csv_delay = csv_delay;
			return;
		}
	}

	if (fi->n_pending_sweeps >= MAX_PENDING_SWEEPS) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "pending_sweep: cap reached (%d) — sweep not tracked",
			   MAX_PENDING_SWEEPS);
		return;
	}

	pending_sweep_t *ps = &fi->pending_sweeps[fi->n_pending_sweeps++];
	memset(ps, 0, sizeof(*ps));
	ps->type = type;
	ps->state = SWEEP_STATE_PENDING;
	memcpy(ps->source_txid, source_txid, 32);
	ps->source_vout = source_vout;
	ps->amount_sats = amount_sats;
	ps->csv_delay = csv_delay;

	plugin_log(plugin_handle, LOG_INFORM,
		   "pending_sweep registered: type=%u vout=%u amount=%"PRIu64
		   " csv_delay=%u", type, source_vout, amount_sats, csv_delay);
}

static const char *sweep_state_name(uint8_t s)
{
	switch (s) {
	case SWEEP_STATE_PENDING:   return "pending";
	case SWEEP_STATE_READY:     return "ready";
	case SWEEP_STATE_BROADCAST: return "broadcast";
	case SWEEP_STATE_CONFIRMED: return "confirmed";
	case SWEEP_STATE_FAILED:    return "failed";
	default:                    return "unknown";
	}
}

static const char *sweep_type_name(uint8_t t)
{
	switch (t) {
	case SWEEP_TYPE_FACTORY_LSTOCK:  return "factory_lstock";
	case SWEEP_TYPE_FACTORY_LEAF:    return "factory_leaf";
	case SWEEP_TYPE_FACTORY_TIMEOUT: return "factory_timeout";
	default:                         return "unknown";
	}
}

/* Per-block sweep scheduler tick. Pure state-machine advancement for
 * v1 — transitions that require actual block confirmations (PENDING →
 * READY when source confirms, BROADCAST → CONFIRMED when sweep has
 * threshold confs) are driven by caller-supplied current_block +
 * future dev/operator RPCs that inject confirmations. Real chain
 * integration (getrawtransaction, checkutxo) for these transitions
 * lives in Phase 4d2.
 *
 * Returns the number of state transitions observed. */
static int ss_sweep_scheduler_tick(struct command *cmd,
				   factory_instance_t *fi,
				   uint32_t current_block)
{
	int transitions = 0;
	bool dirty = false;

	for (size_t i = 0; i < fi->n_pending_sweeps; i++) {
		pending_sweep_t *ps = &fi->pending_sweeps[i];

		/* PENDING → READY when source has confirmed_block set AND
		 * CSV window has elapsed. confirmed_block gets populated by
		 * Phase 4d2 chain-observation hooks or the dev RPC. */
		if (ps->state == SWEEP_STATE_PENDING
		    && ps->confirmed_block > 0) {
			uint32_t mature_at = ps->confirmed_block + ps->csv_delay;
			if (current_block >= mature_at) {
				ps->state = SWEEP_STATE_READY;
				plugin_log(plugin_handle, LOG_INFORM,
					   "sweep: entry %zu type=%s vout=%u "
					   "amount=%"PRIu64" csv=%u now READY "
					   "(confirmed_at=%u, current=%u)",
					   i, sweep_type_name(ps->type),
					   ps->source_vout, ps->amount_sats,
					   ps->csv_delay,
					   ps->confirmed_block, current_block);
				transitions++;
				dirty = true;
			}
		}

		/* BROADCAST → CONFIRMED when sweep_confirmed_block has been
		 * stamped by the confirm-observation hook (4d2 or the dev
		 * RPC). Upstream requires >=3 confs; we honor that. */
		if (ps->state == SWEEP_STATE_BROADCAST
		    && ps->sweep_confirmed_block > 0
		    && current_block >= ps->sweep_confirmed_block
		    + SWEEP_CONFIRM_THRESHOLD - 1) {
			ps->state = SWEEP_STATE_CONFIRMED;
			plugin_log(plugin_handle, LOG_INFORM,
				   "sweep: entry %zu type=%s CONFIRMED "
				   "(sweep confirmed_at=%u, current=%u)",
				   i, sweep_type_name(ps->type),
				   ps->sweep_confirmed_block, current_block);
			/* Phase 5c structured marker. */
			char iid_hex[65];
			for (int b = 0; b < 32; b++)
				sprintf(iid_hex + b*2, "%02x",
					fi->instance_id[b]);
			iid_hex[64] = '\0';
			plugin_log(plugin_handle, LOG_INFORM,
				   "SS_METRIC event=sweep_confirmed iid=%s "
				   "type=%s vout=%u block=%u",
				   iid_hex, sweep_type_name(ps->type),
				   ps->source_vout,
				   ps->sweep_confirmed_block);
			transitions++;
			dirty = true;
		}

		/* Phase 4d3: FAILED → READY retry. A sweep that failed at
		 * broadcast time gets up to SS_SWEEP_MAX_RETRIES attempts,
		 * spaced SS_SWEEP_RETRY_DELAY_BLOCKS apart. retry_count
		 * lives in reserved[0] so on-disk layout is unchanged;
		 * broadcast_block marks when the failure was observed (set
		 * eagerly at kickoff). */
		if (ps->state == SWEEP_STATE_FAILED
		    && ps->reserved[0] < SS_SWEEP_MAX_RETRIES
		    && ps->broadcast_block > 0
		    && current_block >= ps->broadcast_block
		    + SS_SWEEP_RETRY_DELAY_BLOCKS) {
			ps->reserved[0]++;
			ps->state = SWEEP_STATE_READY;
			memset(ps->sweep_txid, 0, 32);
			/* Clear broadcast_block so the next failure starts a
			 * fresh retry window, not retry cascades from the
			 * same block. */
			ps->broadcast_block = 0;
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "sweep: entry %zu type=%s RETRY %u/%u "
				   "(FAILED → READY, next kickoff at block %u)",
				   i, sweep_type_name(ps->type),
				   ps->reserved[0], SS_SWEEP_MAX_RETRIES,
				   current_block);
			transitions++;
			dirty = true;
		}
	}

	if (dirty)
		ss_save_factory(cmd, fi);
	return transitions;
}

/* ============================================================
 * Phase 4d2: READY → BROADCAST orchestration.
 *
 * When the scheduler advances a pending_sweep to READY, we must
 * construct, sign, and broadcast a sweep TX that moves the source
 * UTXO to a CLN-wallet P2TR address. The sweep destinations produced
 * by our plugin (distribution TX per-party outputs, timeout-spend
 * outputs) are all plain P2TR key-path outputs whose internal key is
 * our derive_factory_seckey(instance_id, our_participant_idx). The
 * build + sign runs in sweep_builder.c; this block handles the async
 * dance (newaddr → build → sendrawtransaction → state update).
 *
 * Guards:
 *   - A single READY entry kicks off at most once per tick. On entry,
 *     state flips to BROADCAST eagerly with sweep_txid computed from
 *     the signed TX bytes. The state flip prevents re-kickoff if the
 *     scheduler fires again mid-broadcast.
 *   - On broadcast error: state demotes to FAILED so the operator
 *     can inspect via factory-list. A dev RPC path can clear FAILED
 *     back to READY to retry; normal automatic retry is out of scope
 *     for v1 (Phase 4d3 could add it).
 * ============================================================ */

#define SS_SWEEP_DEFAULT_FEERATE_KVB 1500

struct ss_sweep_kickoff_ctx {
	uint8_t instance_id[32];
	uint8_t source_txid[32];
	uint32_t source_vout;
	uint8_t sweep_txid[32];     /* computed pre-broadcast, for logging */
	uint64_t amount_sats;
};

/* Re-find a pending_sweep via (instance_id, source_txid, source_vout)
 * after an async hop. The factory_instance_t pointer may still be
 * valid, but asserting via lookup guards against mid-flight teardowns. */
static pending_sweep_t *ss_sweep_lookup(const uint8_t *instance_id,
					 const uint8_t *source_txid,
					 uint32_t source_vout,
					 factory_instance_t **fi_out)
{
	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi) return NULL;
	for (size_t i = 0; i < fi->n_pending_sweeps; i++) {
		pending_sweep_t *ps = &fi->pending_sweeps[i];
		if (memcmp(ps->source_txid, source_txid, 32) == 0
		    && ps->source_vout == source_vout) {
			if (fi_out) *fi_out = fi;
			return ps;
		}
	}
	return NULL;
}

static struct command_result *
ss_sweep_broadcast_reply(struct command *cmd,
			 const char *method UNUSED,
			 const char *buf,
			 const jsmntok_t *result,
			 void *arg)
{
	struct ss_sweep_kickoff_ctx *ctx = (struct ss_sweep_kickoff_ctx *)arg;
	factory_instance_t *fi = NULL;
	pending_sweep_t *ps = ss_sweep_lookup(ctx->instance_id,
					      ctx->source_txid,
					      ctx->source_vout, &fi);

	if (!ps) {
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "sweep: broadcast reply for unknown entry — "
			   "likely torn down mid-flight");
		return aux_command_done(cmd);
	}

	/* CLN's bitcoin backend returns {"success": bool, "errmsg": "..."}
	 * for sendrawtransaction — NOT a JSON-RPC error object. */
	const jsmntok_t *succ_tok = result
		? json_get_member(buf, result, "success")
		: NULL;
	bool success = false;
	if (succ_tok) json_to_bool(buf, succ_tok, &success);

	char iid_hex[65];
	for (int b = 0; b < 32; b++)
		sprintf(iid_hex + b*2, "%02x", fi->instance_id[b]);
	iid_hex[64] = '\0';

	if (!success) {
		ps->state = SWEEP_STATE_FAILED;
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "sweep broadcast FAILED: type=%s vout=%u — "
			   "state demoted to FAILED for operator review",
			   sweep_type_name(ps->type), ps->source_vout);
		plugin_log(plugin_handle, LOG_INFORM,
			   "SS_METRIC event=sweep_failed iid=%s "
			   "type=%s vout=%u retry=%u",
			   iid_hex, sweep_type_name(ps->type),
			   ps->source_vout, ps->reserved[0]);
		ss_save_factory(cmd, fi);
	} else {
		ps->broadcast_block = ss_state.current_blockheight;
		plugin_log(plugin_handle, LOG_INFORM,
			   "sweep broadcast OK: type=%s vout=%u "
			   "amount=%"PRIu64" at block %u",
			   sweep_type_name(ps->type), ps->source_vout,
			   ps->amount_sats, ps->broadcast_block);
		plugin_log(plugin_handle, LOG_INFORM,
			   "SS_METRIC event=sweep_broadcast iid=%s "
			   "type=%s vout=%u amount=%"PRIu64" block=%u",
			   iid_hex, sweep_type_name(ps->type),
			   ps->source_vout, ps->amount_sats,
			   ps->broadcast_block);
		ss_save_factory(cmd, fi);
	}
	return aux_command_done(cmd);
}

static struct command_result *
ss_sweep_newaddr_reply(struct command *cmd,
		       const char *method UNUSED,
		       const char *buf,
		       const jsmntok_t *result,
		       void *arg)
{
	struct ss_sweep_kickoff_ctx *ctx = (struct ss_sweep_kickoff_ctx *)arg;
	factory_instance_t *fi = NULL;
	pending_sweep_t *ps = ss_sweep_lookup(ctx->instance_id,
					      ctx->source_txid,
					      ctx->source_vout, &fi);
	if (!ps) return aux_command_done(cmd);

	const jsmntok_t *p2tr_tok = json_get_member(buf, result, "p2tr");
	if (!p2tr_tok) {
		ps->state = SWEEP_STATE_FAILED;
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "sweep: newaddr returned no p2tr — state FAILED");
		ss_save_factory(cmd, fi);
		return aux_command_done(cmd);
	}
	char *addr = json_strdup(tmpctx, buf, p2tr_tok);

	u8 *dest_spk = NULL;
	if (!decode_scriptpubkey_from_addr(tmpctx, chainparams,
					    addr, &dest_spk) || !dest_spk) {
		ps->state = SWEEP_STATE_FAILED;
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "sweep: couldn't decode newaddr %s — state FAILED",
			   addr);
		ss_save_factory(cmd, fi);
		return aux_command_done(cmd);
	}
	size_t spk_len = tal_bytelen(dest_spk);

	/* Derive our factory secret for the source output. */
	uint8_t our_sec[32];
	derive_factory_seckey(our_sec, fi->instance_id,
			      fi->our_participant_idx);

	uint8_t sweep_txid_out[32];
	char *hex = ss_build_p2tr_keypath_sweep_hex(
		global_secp_ctx,
		ps->source_txid, ps->source_vout, ps->amount_sats,
		our_sec, dest_spk, spk_len,
		SS_SWEEP_DEFAULT_FEERATE_KVB, sweep_txid_out);
	memset(our_sec, 0, 32);

	if (!hex) {
		ps->state = SWEEP_STATE_FAILED;
		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "sweep: build_p2tr_keypath_sweep_hex failed "
			   "(uneconomical or sign error) — state FAILED");
		ss_save_factory(cmd, fi);
		return aux_command_done(cmd);
	}

	/* Commit the eager state flip. The broadcast reply will demote
	 * to FAILED if bitcoind rejects. Stamp broadcast_block here (not
	 * just in the success reply) so Phase 4d3's retry gate has a
	 * meaningful "when did this fail?" reference even when bitcoind
	 * rejects before the reply callback runs its normal path. */
	memcpy(ps->sweep_txid, sweep_txid_out, 32);
	memcpy(ctx->sweep_txid, sweep_txid_out, 32);
	ps->state = SWEEP_STATE_BROADCAST;
	ps->broadcast_block = ss_state.current_blockheight;
	ss_save_factory(cmd, fi);

	struct out_req *req = jsonrpc_request_start(cmd,
		"sendrawtransaction",
		ss_sweep_broadcast_reply,
		ss_sweep_broadcast_reply,
		ctx);
	json_add_string(req->js, "tx", hex);
	json_add_bool(req->js, "allowhighfees", true);
	send_outreq(req);
	free(hex);
	return command_still_pending(cmd);
}

/* Kick off a single READY sweep entry. Creates the async chain and
 * returns immediately. Caller should NOT have already modified ps
 * state.
 *
 * Guard: if source_txid is all-zero, this is a synthetic dev-injected
 * entry whose real broadcast would fail at bitcoind anyway (no such
 * UTXO). The older Phase 4d tests mark-broadcast these manually, so
 * we skip auto-kickoff to keep those tests green and avoid RPC noise. */
static void ss_sweep_kickoff_start(struct command *cmd,
				   factory_instance_t *fi,
				   pending_sweep_t *ps)
{
	bool all_zero = true;
	for (int i = 0; i < 32; i++) {
		if (ps->source_txid[i] != 0) { all_zero = false; break; }
	}
	if (all_zero) {
		plugin_log(plugin_handle, LOG_DBG,
			   "sweep kickoff skipped: synthetic source_txid");
		return;
	}
	struct command *acmd = aux_command(cmd);
	struct ss_sweep_kickoff_ctx *ctx = tal(acmd,
		struct ss_sweep_kickoff_ctx);
	memcpy(ctx->instance_id, fi->instance_id, 32);
	memcpy(ctx->source_txid, ps->source_txid, 32);
	ctx->source_vout = ps->source_vout;
	ctx->amount_sats = ps->amount_sats;
	memset(ctx->sweep_txid, 0, 32);

	plugin_log(plugin_handle, LOG_INFORM,
		   "sweep kickoff: type=%s vout=%u amount=%"PRIu64,
		   sweep_type_name(ps->type), ps->source_vout,
		   ps->amount_sats);

	struct out_req *req = jsonrpc_request_start(acmd, "newaddr",
		ss_sweep_newaddr_reply,
		ss_sweep_newaddr_reply, /* same handler on err; it checks
					 * for p2tr membership */
		ctx);
	json_add_string(req->js, "addresstype", "p2tr");
	send_outreq(req);
}

/* Fire kickoffs for every READY entry in the factory's pending_sweeps.
 * Called from the scheduler tick and from handle_block_added after
 * the tick runs. Cap at MAX_PENDING_SWEEPS — there is no rate limit
 * beyond that because the wallet/bitcoind can trivially handle a few
 * tiny sweep TXs at once. */
static void ss_sweep_kick_all_ready(struct command *cmd,
				    factory_instance_t *fi)
{
	for (size_t i = 0; i < fi->n_pending_sweeps; i++) {
		pending_sweep_t *ps = &fi->pending_sweeps[i];
		if (ps->state == SWEEP_STATE_READY)
			ss_sweep_kickoff_start(cmd, fi, ps);
	}
}

/* ============================================================
 * Phase 4d2: chain observation for source + sweep confirmations.
 *
 * Per-block probes of bitcoind via getrawtransaction verbose=true.
 * Reply populates the factory_instance_t entry's confirmed_block or
 * sweep_confirmed_block field. Scheduler tick then advances state on
 * subsequent blocks.
 *
 * Why polling instead of a notifier? CLN plugins don't get a direct
 * "tx confirmed" hook. We'd have to scan every new block for our
 * relevant txids. Polling via getrawtransaction per tracked txid is
 * O(pending_sweeps) RPCs per block — a handful per factory, cheap.
 * ============================================================ */

struct ss_sweep_probe_ctx {
	uint8_t instance_id[32];
	uint8_t probe_txid[32];
	uint32_t probe_vout;        /* used only for source probes */
	bool is_sweep_side;         /* false=source probe, true=sweep probe */
};

static struct command_result *
ss_sweep_probe_reply(struct command *cmd,
		     const char *method UNUSED,
		     const char *buf,
		     const jsmntok_t *result,
		     void *arg)
{
	struct ss_sweep_probe_ctx *ctx = (struct ss_sweep_probe_ctx *)arg;

	/* error reply = tx not found or not confirmed — normal on early
	 * blocks. Silent continue. */
	const jsmntok_t *code_tok = result
		? json_get_member(buf, result, "code")
		: NULL;
	if (code_tok)
		return aux_command_done(cmd);

	const jsmntok_t *conf_tok = json_get_member(buf, result, "confirmations");
	u32 confirmations = 0;
	if (conf_tok)
		json_to_u32(buf, conf_tok, &confirmations);

	if (confirmations < 1)
		return aux_command_done(cmd);

	/* We stamp confirmed_block = current_blockheight - (confs - 1).
	 * This avoids a second RPC round-trip; if the plugin's
	 * current_blockheight is slightly stale we stamp slightly low,
	 * which at worst delays the next-tick state transition by one
	 * block — harmless for sweep timing. */
	factory_instance_t *fi = ss_factory_find(&ss_state, ctx->instance_id);
	if (!fi)
		return aux_command_done(cmd);

	u32 stamped_block = (ss_state.current_blockheight >= confirmations)
		? ss_state.current_blockheight - (confirmations - 1)
		: 0;

	bool dirty = false;
	for (size_t i = 0; i < fi->n_pending_sweeps; i++) {
		pending_sweep_t *ps = &fi->pending_sweeps[i];
		if (ctx->is_sweep_side) {
			if (ps->state == SWEEP_STATE_BROADCAST
			    && memcmp(ps->sweep_txid, ctx->probe_txid, 32) == 0
			    && ps->sweep_confirmed_block == 0) {
				ps->sweep_confirmed_block = stamped_block;
				dirty = true;
				plugin_log(plugin_handle, LOG_INFORM,
					   "sweep: sweep_txid confirmed at "
					   "block %u (confs=%u)",
					   stamped_block, confirmations);
			}
		} else {
			if (ps->state == SWEEP_STATE_PENDING
			    && ps->source_vout == ctx->probe_vout
			    && memcmp(ps->source_txid, ctx->probe_txid, 32) == 0
			    && ps->confirmed_block == 0) {
				ps->confirmed_block = stamped_block;
				dirty = true;
				plugin_log(plugin_handle, LOG_INFORM,
					   "sweep: source confirmed at "
					   "block %u (confs=%u) — will "
					   "become READY at %u",
					   stamped_block, confirmations,
					   stamped_block + ps->csv_delay);
			}
		}
	}
	if (dirty)
		ss_save_factory(cmd, fi);
	return aux_command_done(cmd);
}

static void ss_sweep_probe_fire(struct command *cmd,
				factory_instance_t *fi,
				const uint8_t *probe_txid,
				uint32_t probe_vout,
				bool is_sweep_side)
{
	struct command *acmd = aux_command(cmd);
	struct ss_sweep_probe_ctx *ctx = tal(acmd, struct ss_sweep_probe_ctx);
	memcpy(ctx->instance_id, fi->instance_id, 32);
	memcpy(ctx->probe_txid, probe_txid, 32);
	ctx->probe_vout = probe_vout;
	ctx->is_sweep_side = is_sweep_side;

	char txhex[65];
	/* bitcoind getrawtransaction takes the hash in RPC byte-order
	 * (reversed from internal). */
	for (int k = 0; k < 32; k++)
		sprintf(txhex + k*2, "%02x", probe_txid[31 - k]);
	txhex[64] = '\0';

	struct out_req *req = jsonrpc_request_start(acmd, "getrawtransaction",
		ss_sweep_probe_reply,
		ss_sweep_probe_reply,
		ctx);
	json_add_string(req->js, "txid", txhex);
	json_add_bool(req->js, "verbose", true);
	send_outreq(req);
}

/* Probe all source_txids (for PENDING entries with confirmed_block=0)
 * and all sweep_txids (for BROADCAST entries with sweep_confirmed_block=0).
 * Called once per block per factory from handle_block_added. */
static void ss_sweep_probe_all(struct command *cmd, factory_instance_t *fi)
{
	for (size_t i = 0; i < fi->n_pending_sweeps; i++) {
		pending_sweep_t *ps = &fi->pending_sweeps[i];
		if (ps->state == SWEEP_STATE_PENDING && ps->confirmed_block == 0) {
			ss_sweep_probe_fire(cmd, fi, ps->source_txid,
					    ps->source_vout, false);
		} else if (ps->state == SWEEP_STATE_BROADCAST
			   && ps->sweep_confirmed_block == 0) {
			ss_sweep_probe_fire(cmd, fi, ps->sweep_txid, 0, true);
		}
	}
}

/* ============================================================
 * Phase 4d2: registration helpers for the 3 broadcast sites.
 *
 * Called right after ss_broadcast_factory_tx at the distribution TX
 * broadcast (both LSP + client) and timeout-spend broadcast (LSP
 * only — clients don't run that path). Each helper computes our
 * matching output vout + amount from the TX's output set.
 * ============================================================ */

/* Given a plugin-derived factory secret, compute the 34-byte P2TR
 * scriptPubKey (OP_1 OP_PUSHBYTES_32 <xonly>) that the output would
 * carry. Returns true on success. */
static bool ss_derive_our_factory_spk(const factory_instance_t *fi,
				      uint8_t out_spk34[34])
{
	uint8_t our_sec[32];
	derive_factory_seckey(our_sec, fi->instance_id,
			      fi->our_participant_idx);
	secp256k1_keypair kp;
	if (!secp256k1_keypair_create(global_secp_ctx, &kp, our_sec)) {
		memset(our_sec, 0, 32);
		return false;
	}
	memset(our_sec, 0, 32);
	secp256k1_xonly_pubkey xonly;
	int parity = 0;
	if (!secp256k1_keypair_xonly_pub(global_secp_ctx, &xonly, &parity, &kp)) {
		memset(&kp, 0, sizeof(kp));
		return false;
	}
	memset(&kp, 0, sizeof(kp));
	uint8_t ser[32];
	if (!secp256k1_xonly_pubkey_serialize(global_secp_ctx, ser, &xonly))
		return false;
	out_spk34[0] = 0x51;
	out_spk34[1] = 0x20;
	memcpy(out_spk34 + 2, ser, 32);
	return true;
}

/* Parse a raw serialized TX (as bytes) and extract outputs matching
 * `match_spk34`. On match, stuff the (vout, amount) into out_vout +
 * out_amount and return true for the first match. Minimal parser —
 * handles only legacy-format non-witness TX bytes, which is what
 * factory.c / timeout_spend emit BEFORE finalize_signed_tx adds
 * witness. Our registration sites call this on the signed tx hex —
 * we need to SKIP the witness marker/flag + witness data.
 *
 * Structure of a segwit-serialized TX:
 *   4 bytes nVersion
 *   1 byte marker (0x00) + 1 byte flag (0x01)   [segwit only]
 *   varint n_in
 *   for each input: 36 bytes outpoint + varint script + script + 4 bytes nSeq
 *   varint n_out
 *   for each output: 8 bytes amount + varint script + script
 *   [witness data — skip]
 *   4 bytes locktime
 *
 * Since we only need outputs, we parse up through the output section
 * and stop. If marker/flag = 0x00 0x01 we skip them; otherwise we
 * treat the first byte as n_in directly (legacy format). */
static bool ss_parse_tx_find_output(const uint8_t *tx, size_t tx_len,
				    const uint8_t *match_spk, size_t match_spk_len,
				    uint32_t *out_vout, uint64_t *out_amount)
{
	if (tx_len < 10) return false;
	size_t p = 4; /* skip nVersion */

	/* Segwit marker/flag? */
	if (p + 1 < tx_len && tx[p] == 0x00 && tx[p+1] == 0x01)
		p += 2;

	/* varint n_in */
	if (p >= tx_len) return false;
	uint64_t n_in;
	if (tx[p] < 0xfd) { n_in = tx[p]; p += 1; }
	else if (tx[p] == 0xfd) {
		if (p + 3 > tx_len) return false;
		n_in = tx[p+1] | (tx[p+2] << 8); p += 3;
	} else return false;

	for (uint64_t i = 0; i < n_in; i++) {
		if (p + 36 > tx_len) return false;
		p += 36; /* outpoint */
		if (p >= tx_len) return false;
		uint64_t scr_len;
		if (tx[p] < 0xfd) { scr_len = tx[p]; p += 1; }
		else if (tx[p] == 0xfd) {
			if (p + 3 > tx_len) return false;
			scr_len = tx[p+1] | (tx[p+2] << 8); p += 3;
		} else return false;
		if (p + scr_len + 4 > tx_len) return false;
		p += scr_len + 4; /* script + nSeq */
	}

	if (p >= tx_len) return false;
	uint64_t n_out;
	if (tx[p] < 0xfd) { n_out = tx[p]; p += 1; }
	else if (tx[p] == 0xfd) {
		if (p + 3 > tx_len) return false;
		n_out = tx[p+1] | (tx[p+2] << 8); p += 3;
	} else return false;

	for (uint64_t i = 0; i < n_out; i++) {
		if (p + 8 > tx_len) return false;
		uint64_t amount = 0;
		for (int b = 0; b < 8; b++)
			amount |= ((uint64_t)tx[p + b]) << (8 * b);
		p += 8;
		if (p >= tx_len) return false;
		uint64_t scr_len;
		if (tx[p] < 0xfd) { scr_len = tx[p]; p += 1; }
		else if (tx[p] == 0xfd) {
			if (p + 3 > tx_len) return false;
			scr_len = tx[p+1] | (tx[p+2] << 8); p += 3;
		} else return false;
		if (p + scr_len > tx_len) return false;
		if (scr_len == match_spk_len
		    && memcmp(tx + p, match_spk, match_spk_len) == 0) {
			if (out_vout) *out_vout = (uint32_t)i;
			if (out_amount) *out_amount = amount;
			return true;
		}
		p += scr_len;
	}
	return false;
}

/* Compute double-sha256 txid of a segwit TX. The txid is computed
 * over the NON-witness serialization. For a signed segwit TX we emit,
 * we need to strip marker/flag + witness data before hashing — but
 * simpler: callers already hold the unsigned txid from build_unsigned_tx_v
 * (see sweep_builder). For registration from ss_broadcast_factory_tx
 * sites we use bitcoin_txid-style computation directly over the bytes
 * after stripping marker/flag. Returns true on success. */
static bool ss_compute_txid_from_signed(const uint8_t *tx, size_t tx_len,
					 uint8_t out_txid[32])
{
	if (tx_len < 10) return false;
	/* Build a witness-stripped copy. */
	uint8_t *stripped = malloc(tx_len);
	if (!stripped) return false;
	size_t sp = 0;
	/* nVersion */
	memcpy(stripped + sp, tx, 4); sp += 4;
	size_t p = 4;

	bool is_segwit = (p + 1 < tx_len && tx[p] == 0x00 && tx[p+1] == 0x01);
	if (is_segwit) p += 2;

	/* Copy n_in + inputs. */
	if (p >= tx_len) { free(stripped); return false; }
	size_t in_start = p;
	uint64_t n_in;
	if (tx[p] < 0xfd) { n_in = tx[p]; p += 1; }
	else if (tx[p] == 0xfd) {
		if (p + 3 > tx_len) { free(stripped); return false; }
		n_in = tx[p+1] | (tx[p+2] << 8); p += 3;
	} else { free(stripped); return false; }
	for (uint64_t i = 0; i < n_in; i++) {
		if (p + 36 > tx_len) { free(stripped); return false; }
		p += 36;
		if (p >= tx_len) { free(stripped); return false; }
		uint64_t scr_len;
		if (tx[p] < 0xfd) { scr_len = tx[p]; p += 1; }
		else if (tx[p] == 0xfd) {
			if (p + 3 > tx_len) { free(stripped); return false; }
			scr_len = tx[p+1] | (tx[p+2] << 8); p += 3;
		} else { free(stripped); return false; }
		if (p + scr_len + 4 > tx_len) { free(stripped); return false; }
		p += scr_len + 4;
	}
	memcpy(stripped + sp, tx + in_start, p - in_start);
	sp += p - in_start;

	/* Copy n_out + outputs. */
	if (p >= tx_len) { free(stripped); return false; }
	size_t out_start = p;
	uint64_t n_out;
	if (tx[p] < 0xfd) { n_out = tx[p]; p += 1; }
	else if (tx[p] == 0xfd) {
		if (p + 3 > tx_len) { free(stripped); return false; }
		n_out = tx[p+1] | (tx[p+2] << 8); p += 3;
	} else { free(stripped); return false; }
	for (uint64_t i = 0; i < n_out; i++) {
		if (p + 8 > tx_len) { free(stripped); return false; }
		p += 8;
		if (p >= tx_len) { free(stripped); return false; }
		uint64_t scr_len;
		if (tx[p] < 0xfd) { scr_len = tx[p]; p += 1; }
		else if (tx[p] == 0xfd) {
			if (p + 3 > tx_len) { free(stripped); return false; }
			scr_len = tx[p+1] | (tx[p+2] << 8); p += 3;
		} else { free(stripped); return false; }
		if (p + scr_len > tx_len) { free(stripped); return false; }
		p += scr_len;
	}
	memcpy(stripped + sp, tx + out_start, p - out_start);
	sp += p - out_start;

	/* Skip witness data if segwit. Witness layout: for each input,
	 * varint n_stackitems, then each item as varint-length + data. */
	if (is_segwit) {
		for (uint64_t i = 0; i < n_in; i++) {
			if (p >= tx_len) { free(stripped); return false; }
			uint64_t n_items;
			if (tx[p] < 0xfd) { n_items = tx[p]; p += 1; }
			else if (tx[p] == 0xfd) {
				if (p + 3 > tx_len) { free(stripped); return false; }
				n_items = tx[p+1] | (tx[p+2] << 8); p += 3;
			} else { free(stripped); return false; }
			for (uint64_t j = 0; j < n_items; j++) {
				if (p >= tx_len) { free(stripped); return false; }
				uint64_t item_len;
				if (tx[p] < 0xfd) { item_len = tx[p]; p += 1; }
				else if (tx[p] == 0xfd) {
					if (p + 3 > tx_len) { free(stripped); return false; }
					item_len = tx[p+1] | (tx[p+2] << 8); p += 3;
				} else { free(stripped); return false; }
				if (p + item_len > tx_len) { free(stripped); return false; }
				p += item_len;
			}
		}
	}

	/* 4 bytes locktime. */
	if (p + 4 > tx_len) { free(stripped); return false; }
	memcpy(stripped + sp, tx + p, 4); sp += 4;

	struct sha256 h1, h2;
	sha256(&h1, stripped, sp);
	sha256(&h2, &h1, sizeof(h1));
	memcpy(out_txid, &h2, 32);
	free(stripped);
	return true;
}

/* Register a pending sweep for our output in a just-broadcast TX.
 * Walks the tx's output list for a match against our derived factory
 * spk. Silent no-op if our role produces no output in this TX. */
static void ss_register_sweep_from_tx(factory_instance_t *fi,
				      uint8_t type,
				      const uint8_t *tx_bytes,
				      size_t tx_len,
				      uint32_t csv_delay)
{
	uint8_t our_spk[34];
	if (!ss_derive_our_factory_spk(fi, our_spk))
		return;

	uint32_t vout;
	uint64_t amount;
	if (!ss_parse_tx_find_output(tx_bytes, tx_len, our_spk, 34,
				     &vout, &amount))
		return;

	uint8_t txid[32];
	if (!ss_compute_txid_from_signed(tx_bytes, tx_len, txid))
		return;

	ss_register_pending_sweep(fi, type, txid, vout, amount, csv_delay);
}

static struct command_result *breach_utxo_checked(struct command *cmd,
						   const char *method,
						   const char *buf,
						   const jsmntok_t *result,
						   void *arg)
{
	struct breach_scan_ctx *bctx = (struct breach_scan_ctx *)arg;
	factory_instance_t *fi = bctx->fi;

	const jsmntok_t *exists_tok = json_get_member(buf, result, "exists");
	if (!exists_tok)
		return aux_command_done(cmd);

	bool exists;
	json_to_bool(buf, exists_tok, &exists);

	if (!exists) {
		/* Funding UTXO has been spent. Could be:
		 *   (a) our own force-close / intentional exit — expected;
		 *       lifecycle is already DYING in that case
		 *   (b) a genuine breach (peer published an old kickoff
		 *       from a prior epoch, before we could advance)
		 *   (c) a cooperative close we didn't drive
		 *   (d) a manual external sweep (recovery tool, HSM-lost
		 *       recovery, operator intervention outside the plugin)
		 *
		 * Phase 1 distinguishes (a) from everything else via
		 * lifecycle: if the factory is still ACTIVE when the spend
		 * lands, we didn't initiate it — transition to
		 * CLOSED_EXTERNALLY. Phase 2 will classify (b/c/d) by
		 * inspecting the spending TX; for now CLOSED_EXTERNALLY is
		 * the safe default label for "root spent, not by us." The
		 * operator confirms via factory-confirm-closed before the
		 * record is reaped, so a misclassification at this layer
		 * costs a manual verification step, not funds.
		 *
		 * Breach burn-TX construction below continues independently
		 * — if we have revocation secrets for a past epoch, they
		 * should still go to mempool so that when the counterparty
		 * publishes a leaf-state TX from the revoked epoch we're
		 * ready to sweep its L-stock. The two concerns (lifecycle
		 * flag vs burn-tx assembly) are complementary, not mutually
		 * exclusive. */
		/* Phase 3b: feed the UTXO-spent signal into the unified
		 * classifier. apply_signals handles the lifecycle transition
		 * idempotently, so this path is safe to re-enter. The
		 * ancillary fields (closed_externally_at_block etc.) are set
		 * here because they're specific to THIS signal firing first
		 * — apply_signals only owns lifecycle + closed_by. */
		factory_lifecycle_t prior = fi->lifecycle;
		bool first_spent_observation =
			!(fi->signals_observed & SIGNAL_UTXO_SPENT);
		fi->signals_observed |= SIGNAL_UTXO_SPENT;

		if (first_spent_observation
		    && (prior == FACTORY_LIFECYCLE_ACTIVE
			|| prior == FACTORY_LIFECYCLE_INIT
			|| prior == FACTORY_LIFECYCLE_DYING)) {
			fi->closed_externally_at_block =
				ss_state.current_blockheight;
			fi->first_noticed_block =
				ss_state.current_blockheight;
			char iid_hex[65];
			for (int j = 0; j < 32; j++)
				sprintf(iid_hex + j*2, "%02x",
					fi->instance_id[j]);
			iid_hex[64] = '\0';
			plugin_log(plugin_handle, LOG_BROKEN,
				   "FACTORY ROOT SPENT: instance_id=%s "
				   "funding root spent at block %u (was in "
				   "lifecycle %d). Feeding SIGNAL_UTXO_SPENT "
				   "to classifier; Phase 2a spending-TX scan "
				   "and Phase 3b state-TX scan will refine.",
				   iid_hex, ss_state.current_blockheight,
				   (int)prior);

			ss_apply_signals(cmd, fi);
			ss_save_factory(cmd, fi);

			/* Phase 2a: identify the spending TX (match against
			 * our own dist/kickoff/state txids). 144-block window
			 * covers the common case where the heartbeat fires on
			 * the same or next block the spend confirmed. */
			ss_launch_spending_tx_scan(cmd, fi, 144);

			/* Phase 3b: downstream state-TX scan. If someone
			 * published a kickoff, the state TX spending its
			 * tree-root output should be in a nearby block.
			 * Matching against history_state_root_txids tells us
			 * which epoch — the strongest breach-vs-normal-exit
			 * signal we have. */
			factory_t *ftmp = (factory_t *)fi->lib_factory;
			if (ftmp && ftmp->n_nodes > 0)
				ss_launch_state_tx_scan(cmd, fi,
							ftmp->nodes[0].txid,
							144);
		} else if (first_spent_observation) {
			/* prior was EXPIRED/CLOSED_* — still record the
			 * signal + re-run classifier but don't stomp the
			 * ancillary block-tag fields. */
			ss_apply_signals(cmd, fi);
			ss_save_factory(cmd, fi);
		}

		/* Previously this loop called factory_build_burn_tx with
		 * (nodes[0].txid, 0) — the kickoff's output, which is NOT
		 * an L-stock output. L-stock outputs live on LEAF STATE
		 * nodes as the last output of each leaf. The burn TXs
		 * built with the wrong outpoint would never be valid even
		 * if broadcast. */
		factory_t *f = (factory_t *)fi->lib_factory;
		if (!f) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "BREACH ALERT: factory %zu funding UTXO spent "
				   "but no lib_factory loaded — cannot build "
				   "burn TXs. Check startup log for reload "
				   "failures.",
				   bctx->factory_idx);
			return aux_command_done(cmd);
		}

		plugin_log(plugin_handle, LOG_UNUSUAL,
			   "BREACH ALERT: factory %zu funding UTXO spent. "
			   "Attempting burn TXs for %zu revoked epochs across "
			   "%d leaf nodes...",
			   bctx->factory_idx, fi->n_breach_epochs,
			   f->n_leaf_nodes);

		size_t burn_count = 0;
		for (size_t bi = 0; bi < fi->n_breach_epochs; bi++) {
			epoch_breach_data_t *bd = &fi->breach_data[bi];
			if (!bd->has_revocation)
				continue;
			if (bd->epoch >= fi->epoch)
				continue; /* current epoch — not a breach */

			/* Iterate leaf state nodes. Each leaf's last output
			 * is its L-stock (see setup_leaf_outputs and
			 * setup_single_leaf_outputs in factory.c). For burn
			 * to be valid we need that leaf-state TX to be on
			 * chain with the txid we computed at signing time.
			 * If the breach is still only at the kickoff stage,
			 * the state TX isn't confirmed yet — the burn TX
			 * will stay in mempool until it is, or be rejected.
			 * Either way, broadcasting early is fine: bitcoind
			 * will hold it or reject it, and a second attempt
			 * on a later block will succeed. */
			for (int ls = 0; ls < f->n_leaf_nodes; ls++) {
				size_t leaf_idx = f->leaf_node_indices[ls];
				if (leaf_idx >= f->n_nodes) continue;
				factory_node_t *leaf = &f->nodes[leaf_idx];
				if (leaf->n_outputs == 0) continue;

				uint32_t lstock_vout =
					(uint32_t)(leaf->n_outputs - 1);
				uint64_t lstock_amt =
					leaf->outputs[lstock_vout].amount_sats;

				tx_buf_t burn_tx;
				tx_buf_init(&burn_tx, 256);
				if (factory_build_burn_tx(f, &burn_tx, leaf,
							  leaf->txid,
							  lstock_vout,
							  lstock_amt,
							  bd->epoch)) {
					char *burn_hex = tal_arr(cmd, char,
						burn_tx.len * 2 + 1);
					for (size_t h = 0; h < burn_tx.len; h++)
						sprintf(burn_hex + h*2, "%02x",
							burn_tx.data[h]);

					ss_broadcast_factory_tx(cmd, fi,
								burn_hex,
								FACTORY_TX_BURN);
					burn_count++;

					/* Phase 3c: register with the fee-bump
					 * scheduler so subsequent blocks
					 * re-evaluate and rebroadcast if stuck. */
					{
						uint8_t burn_txid[32];
						struct sha256 h1, h2;
						sha256(&h1, burn_tx.data,
						       burn_tx.len);
						sha256(&h2, &h1, sizeof(h1));
						memcpy(burn_txid, &h2, 32);
						uint32_t csv_unlock =
							ss_state.current_blockheight
							+ LSTOCK_CSV_DELAY_DEFAULT;
						ss_register_pending_penalty(
							fi, bd->epoch,
							(int)leaf_idx,
							burn_txid, lstock_amt,
							csv_unlock,
							(uint32_t)burn_tx.len,
							ss_state.current_blockheight);
					}

					plugin_log(plugin_handle, LOG_UNUSUAL,
						"Broadcast burn TX: leaf=%d "
						"epoch=%u amt=%"PRIu64" "
						"bytes=%zu",
						ls, bd->epoch, lstock_amt,
						burn_tx.len);
				}
				tx_buf_free(&burn_tx);
			}
		}

		if (burn_count == 0 && fi->n_breach_epochs > 0) {
			/* has_shachain must be true for burn TX construction;
			 * if the factory was reloaded without secrets this
			 * will silently fail. Log loudly so an operator can
			 * investigate. */
			plugin_log(plugin_handle, LOG_BROKEN,
				   "Breach detected but no burn TX could be "
				   "built for any leaf/epoch — check that "
				   "L-stock secrets were loaded for this "
				   "factory (has_shachain, n_revocation_secrets).");
		}

		/* Set factory to DYING so block_added will re-broadcast
		 * our latest signed state TXs (DW cascade). The newest
		 * state has the shortest timelock and will confirm first,
		 * invalidating the attacker's old state. */
		if (fi->lifecycle == FACTORY_LIFECYCLE_ACTIVE) {
			fi->lifecycle = FACTORY_LIFECYCLE_DYING;
			fi->rotation_in_progress = false;
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "BREACH RESPONSE: factory set to DYING — "
				   "will cascade latest state TXs");
		}

		/* Immediately broadcast our latest signed tree TXs to
		 * race the attacker's old state (shorter timelock wins). */
		for (size_t ni = 0; ni < f->n_nodes; ni++) {
			if (!f->nodes[ni].is_signed ||
			    !f->nodes[ni].signed_tx.data ||
			    f->nodes[ni].signed_tx.len == 0)
				continue;

			char *tx_hex = tal_arr(cmd, char,
				f->nodes[ni].signed_tx.len * 2 + 1);
			for (size_t h = 0; h < f->nodes[ni].signed_tx.len; h++)
				sprintf(tx_hex + h*2, "%02x",
					f->nodes[ni].signed_tx.data[h]);

			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "BREACH RESPONSE: broadcasting latest "
				   "state node %zu (%zu bytes)",
				   ni, f->nodes[ni].signed_tx.len);

			ss_broadcast_factory_tx(cmd, fi, tx_hex,
						ni == 0 ? FACTORY_TX_KICKOFF
							: FACTORY_TX_STATE);

			/* Phase 3c2.5d: register for CPFP if this TX has an
			 * anchor. Same pattern as handle_block_added DYING
			 * cascade — breach response is just another path to
			 * the same "broadcast tree nodes under duress" flow. */
			tx_buf_t *ntx = &f->nodes[ni].signed_tx;
			int anchor_vout_b =
				ss_find_p2a_vout(ntx->data, ntx->len);
			if (anchor_vout_b >= 0) {
				uint8_t tx_txid[32];
				struct sha256 h1, h2;
				sha256(&h1, ntx->data, ntx->len);
				sha256(&h2, &h1, sizeof(h1));
				memcpy(tx_txid, &h2, 32);
				uint64_t value = f->nodes[ni].n_outputs > 0
					? f->nodes[ni].outputs[0].amount_sats
					: fi->funding_amount_sats;
				ss_register_pending_cpfp(fi,
					ni == 0 ? CPFP_PARENT_KICKOFF
						: CPFP_PARENT_STATE,
					tx_txid, (uint32_t)anchor_vout_b,
					value, fi->expiry_block,
					ss_state.current_blockheight);
			}
		}
	}

	return aux_command_done(cmd);
}

/* Handle block_added notification — check for breach (old state on-chain).
 * For each factory with breach data, check if any old-epoch txids appeared. */
static struct command_result *handle_block_added(struct command *cmd,
						 const char *buf,
						 const jsmntok_t *params)
{
	/* Phase 3 architectural decision: per-block handling delegated to
	 * superscalar_watchtower (separate process). The plugin's role is
	 * factory ceremony coordination, not chain watching. See
	 * ss_launch_breach_scan for full architecture notes + Phase 4/6
	 * roadmap. */
	(void)buf; (void)params;
	return notification_handled(cmd);

	/* CLN's block_added notification sends fields flat:
	 *   {"hash": "...", "height": N}
	 * not nested under a "block" key. */
	const jsmntok_t *height_tok = json_get_member(buf, params, "height");
	if (height_tok) {
		u32 height;
		json_to_u32(buf, height_tok, &height);

		/* Phase 4e2: reorg auto-trigger. If the new tip is
		 * at or below the last height we observed, something
		 * reorganized. Invoke ss_penalty_reorg_check for
		 * every factory with confirmed penalties — the async
		 * getrawtransaction per confirmed burn will flip
		 * reorg-ed penalties back to BROADCAST so the
		 * scheduler rebroadcasts.
		 *
		 * Seed-skip: last_observed_blockheight == 0 means
		 * this is our first block_added; don't misread it
		 * as a regression. */
		if (ss_state.last_observed_blockheight > 0
		    && height <= ss_state.last_observed_blockheight) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "Phase 4e2: tip regression detected "
				   "(%u -> %u). Launching penalty "
				   "reorg-check for all factories with "
				   "confirmed penalties.",
				   ss_state.last_observed_blockheight,
				   height);
			for (size_t i = 0;
			     i < ss_state.n_factories; i++) {
				factory_instance_t *cfi =
					ss_state.factories[i];
				if (!cfi) continue;
				if (cfi->n_pending_penalties == 0)
					continue;
				ss_penalty_reorg_check(cmd, cfi);
			}
		}

		ss_state.current_blockheight = height;
		ss_state.last_observed_blockheight = height;
	}

	/* Check factory lifecycle warnings */
	for (size_t i = 0; i < ss_state.n_factories; i++) {
		factory_instance_t *fi = ss_state.factories[i];
		/* Phase 3a: skip terminal-closed only. See matching comment
		 * in ss_catchup_breach_scan — INIT factories with real
		 * funding need observation. The interior expiry/cascade
		 * blocks below already filter their own state requirements. */
		if (fi->lifecycle == FACTORY_LIFECYCLE_EXPIRED
		    || fi->lifecycle == FACTORY_LIFECYCLE_CLOSED_EXTERNALLY)
			continue;

		/* Tier 2.6: abandon stale in-flight PS advance ceremony.
		 * If PROPOSE was sent and PSIG never arrived within
		 * PS_PENDING_TIMEOUT_BLOCKS, clear state so the operator
		 * can retry. Frees the stashed secnonce. */
		if (fi->ps_pending_leaf != -1 &&
		    fi->ps_pending_start_block > 0 &&
		    ss_state.current_blockheight >
			fi->ps_pending_start_block + PS_PENDING_TIMEOUT_BLOCKS) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"SS_METRIC event=ps_advance_timeout "
				"leaf=%d started_at=%u current=%u",
				fi->ps_pending_leaf,
				fi->ps_pending_start_block,
				ss_state.current_blockheight);
			ss_clear_ps_pending(fi);
		}

		/* Task #151: client-side ceremony self-timeout. If the LSP
		 * went silent mid-ceremony and never sent CEREMONY_ABORT
		 * (legacy LSP, dropped message, or peer process died), the
		 * client would otherwise sit in PROPOSED/NONCES_COLLECTED/etc
		 * forever, showing as a phantom in-flight factory. After
		 * CEREMONY_TIMEOUT_BLOCKS without progress, terminalize from
		 * the client side -- this also broadcasts CEREMONY_ABORT
		 * back to the LSP via ss_terminalize_failed, which is a
		 * no-op on the LSP if it already moved on. */
		if (!fi->is_lsp
		    && fi->ceremony_started_block > 0
		    && (fi->ceremony == CEREMONY_PROPOSED
		        || fi->ceremony == CEREMONY_NONCES_COLLECTED
		        || fi->ceremony == CEREMONY_PSIGS_COLLECTED
		        || fi->ceremony == CEREMONY_FUNDING_PENDING
		        || fi->ceremony == CEREMONY_ROTATING)
		    && ss_state.current_blockheight >
			fi->ceremony_started_block + CEREMONY_TIMEOUT_BLOCKS) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"SS_METRIC event=client_ceremony_timeout "
				"iid=%02x%02x%02x%02x ceremony=%d "
				"started_at=%u current=%u",
				fi->instance_id[0], fi->instance_id[1],
				fi->instance_id[2], fi->instance_id[3],
				(int)fi->ceremony,
				fi->ceremony_started_block,
				ss_state.current_blockheight);
			ss_terminalize_failed(cmd, fi,
				SS_CEREMONY_ABORT_DEADLINE_PASSED);
		}

		/* Phase 3c3: lazy retrofit — catch factories whose lib_factory
		 * was constructed without fee-estimator wiring (persistence
		 * reload, mid-ceremony rebuild paths). Free when already
		 * wired. */
		ss_ensure_factory_fee_wired(fi);

		if (ss_factory_should_close(fi, ss_state.current_blockheight)) {
			if (fi->lifecycle == FACTORY_LIFECYCLE_ACTIVE) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "FACTORY EXPIRED: factory %zu expired "
					   "at block %u (current: %u)",
					   i, fi->expiry_block,
					   ss_state.current_blockheight);
				fi->lifecycle = FACTORY_LIFECYCLE_DYING;
			}

			/* Broadcast signed distribution TX (nLockTime fallback).
			 * After expiry, this TX is valid and sends each client
			 * their funds without LSP cooperation. */
			if (fi->dist_signed_tx && fi->dist_signed_tx_len > 0) {
				char *dist_hex = tal_arr(cmd, char,
					fi->dist_signed_tx_len * 2 + 1);
				for (size_t h = 0; h < fi->dist_signed_tx_len; h++)
					sprintf(dist_hex + h*2, "%02x",
						fi->dist_signed_tx[h]);
				ss_broadcast_factory_tx(cmd, fi, dist_hex,
							FACTORY_TX_DIST);
				plugin_log(plugin_handle, LOG_INFORM,
					   "Broadcasting distribution TX "
					   "(%zu bytes) — client fallback",
					   fi->dist_signed_tx_len);

				/* Phase 4d2: register a pending_sweep for our
				 * output in the dist TX. LSP (our_participant_idx=0)
				 * gets the stock share; each client gets a leaf.
				 * Both roles run this path against fi->dist_signed_tx;
				 * the helper finds our spk by derived xonly. No
				 * match ⇒ silent no-op (e.g. if the dist TX was
				 * built for a non-us role). csv_delay=0 since dist
				 * outputs are immediately spendable after confirm. */
				ss_register_sweep_from_tx(fi,
					fi->is_lsp ? SWEEP_TYPE_FACTORY_LSTOCK
						   : SWEEP_TYPE_FACTORY_LEAF,
					fi->dist_signed_tx,
					fi->dist_signed_tx_len, 0);

				/* Phase 3c2.5d: register the dist TX for CPFP
				 * if it carries an anchor. The dist TX is
				 * the fallback that lets clients claim their
				 * funds after factory expiry — a stuck dist
				 * TX is a real problem. */
				int dist_anchor_vout =
					ss_find_p2a_vout(fi->dist_signed_tx,
							 fi->dist_signed_tx_len);
				if (dist_anchor_vout >= 0) {
					uint8_t dist_txid[32];
					struct sha256 h1, h2;
					sha256(&h1, fi->dist_signed_tx,
					       fi->dist_signed_tx_len);
					sha256(&h2, &h1, sizeof(h1));
					memcpy(dist_txid, &h2, 32);
					ss_register_pending_cpfp(fi,
						CPFP_PARENT_DIST,
						dist_txid,
						(uint32_t)dist_anchor_vout,
						fi->funding_amount_sats,
						fi->expiry_block + 144,
						ss_state.current_blockheight);
				}
			}

			/* Build and broadcast timeout spend TXs for each
			 * node with a CLTV timeout (LSP signs alone via
			 * timeout script path — unilateral exit safety valve). */
			factory_t *ftx = (factory_t *)fi->lib_factory;
			if (ftx && ss_state.has_master_key) {
				secp256k1_keypair lsp_kp;
				unsigned char lsp_sk[32];
				derive_factory_seckey(lsp_sk, fi->instance_id, 0);
				if (secp256k1_keypair_create(global_secp_ctx,
							     &lsp_kp, lsp_sk)) {
					/* LSP's own P2TR address as destination */
					secp256k1_xonly_pubkey lsp_xonly;
					int parity;
					if (!secp256k1_keypair_xonly_pub(global_secp_ctx,
						&lsp_xonly, &parity, &lsp_kp))
						break;
					unsigned char dxonly[32];
					secp256k1_xonly_pubkey_serialize(
						global_secp_ctx, dxonly, &lsp_xonly);
					uint8_t dest_spk[34];
					dest_spk[0] = 0x51; dest_spk[1] = 0x20;
					memcpy(dest_spk + 2, dxonly, 32);

					for (size_t ni = 1; ni < ftx->n_nodes; ni++) {
						if (ftx->nodes[ni].cltv_timeout == 0)
							continue;
						int parent = ftx->nodes[ni].parent_index;
						if (parent < 0) continue;
						tx_buf_t timeout_tx;
						tx_buf_init(&timeout_tx, 256);
						if (factory_build_timeout_spend_tx(ftx,
							ftx->nodes[parent].txid,
							ftx->nodes[ni].parent_vout,
							ftx->nodes[ni].input_amount,
							(int)ni, &lsp_kp,
							dest_spk, 34, 500,
							&timeout_tx)) {
							char *th = tal_arr(cmd, char,
								timeout_tx.len * 2 + 1);
							for (size_t h = 0;
							     h < timeout_tx.len; h++)
								sprintf(th + h*2, "%02x",
									timeout_tx.data[h]);
							ss_broadcast_factory_tx(cmd, fi,
										th,
										FACTORY_TX_STATE);
							plugin_log(plugin_handle, LOG_INFORM,
								   "Timeout spend: node %zu "
								   "(%zu bytes)", ni,
								   timeout_tx.len);

							/* Phase 4d2: register sweep against
							 * this timeout-spend TX's output. Dest
							 * is LSP's P2TR key-path, so the sweep
							 * will only register on the LSP side.
							 * csv_delay=0: timeout-spend outputs
							 * are immediately spendable once the
							 * TX confirms. */
							ss_register_sweep_from_tx(fi,
								SWEEP_TYPE_FACTORY_TIMEOUT,
								timeout_tx.data,
								timeout_tx.len, 0);
						}
						tx_buf_free(&timeout_tx);
					}
				}
			}
		} else if (ss_factory_should_warn(fi,
				ss_state.current_blockheight)) {
			/* Early-warning window: current_block +
			 * early_warning_time >= expiry_block. Any HTLC still
			 * in flight whose cltv_expiry lands after the factory
			 * expires would be unrecoverable — the factory's root
			 * UTXO is gone, the state-TX race window has closed,
			 * and only the CLTV unilateral exit is left (which
			 * doesn't carry HTLC resolution). Force-close the
			 * channels NOW so the commitment TX publishes while
			 * the factory is still valid and HTLC timeout/success
			 * paths can resolve on-chain via standard LN mechanics.
			 *
			 * Fire once per factory. The flag resets on plugin
			 * restart so a crash during the close loop doesn't
			 * strand channels. Both LSP and client run this path;
			 * CLN de-dupes close requests on already-closing
			 * channels. */
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "Factory %zu approaching expiry at block %u "
				   "(current: %u, warning_time=%u) — force-"
				   "closing %zu channel(s)",
				   i, fi->expiry_block,
				   ss_state.current_blockheight,
				   fi->early_warning_time,
				   fi->n_channels);

			if (!fi->warning_close_triggered) {
				fi->warning_close_triggered = true;
				fi->lifecycle = FACTORY_LIFECYCLE_DYING;
				for (size_t ch = 0; ch < fi->n_channels; ch++) {
					char cid_hex[65];
					for (int j = 0; j < 32; j++)
						sprintf(cid_hex + j*2, "%02x",
							fi->channels[ch]
							   .channel_id[j]);
					cid_hex[64] = '\0';
					struct out_req *creq =
						jsonrpc_request_start(cmd,
							"close",
							rpc_done, rpc_err,
							fi);
					json_add_string(creq->js, "id",
							cid_hex);
					/* unilateraltimeout=1 means "mutual
					 * close if peer responds within 1s,
					 * else unilateral". In the early-
					 * warning window we want channels
					 * closed on-chain promptly; we're
					 * intentionally biased toward
					 * unilateral rather than waiting out
					 * a slow peer. */
					json_add_u32(creq->js,
						"unilateraltimeout", 1);
					send_outreq(creq);
					plugin_log(plugin_handle, LOG_INFORM,
						"warning-close: factory %zu "
						"channel %s", i, cid_hex);
				}
				ss_save_factory(cmd, fi);
			}
		}

		/* DW epoch exhaustion warning: if epoch is within 10 of
		 * max_epochs, warn once per block so operator can migrate. */
		if (fi->is_lsp && fi->max_epochs > 0
		    && fi->epoch >= fi->max_epochs - 10
		    && fi->lifecycle == FACTORY_LIFECYCLE_ACTIVE) {
			uint32_t remaining = fi->max_epochs - fi->epoch;
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "Factory %zu: %u/%u epochs used (%u remaining)"
				   " — call factory-migrate before exhaustion",
				   i, fi->epoch, fi->max_epochs, remaining);
		}

		/* DW cascade: if factory is DYING (force-close in progress),
		 * re-broadcast signed tree nodes on each block. Child nodes
		 * that failed because parent wasn't confirmed may now succeed. */
		if (fi->lifecycle == FACTORY_LIFECYCLE_DYING) {
			factory_t *fcl = (factory_t *)fi->lib_factory;
			if (fcl) {
				for (size_t ni = 0; ni < fcl->n_nodes; ni++) {
					if (!fcl->nodes[ni].is_signed) continue;
					tx_buf_t *stx = &fcl->nodes[ni].signed_tx;
					if (!stx->data || stx->len == 0) continue;
					char *tx_hex = tal_arr(cmd, char,
						stx->len * 2 + 1);
					for (size_t h = 0; h < stx->len; h++)
						sprintf(tx_hex + h*2, "%02x",
							stx->data[h]);
					ss_broadcast_factory_tx(cmd, fi, tx_hex,
								ni == 0 ? FACTORY_TX_KICKOFF
									: FACTORY_TX_STATE);

					/* Phase 3c2.5d: register for CPFP
					 * monitoring. Compute child txid,
					 * locate the P2A anchor vout via
					 * scanner (handles the anchor-at-
					 * variable-vout reality). Skip if no
					 * anchor (fee_should_use_anchor off). */
					int anchor_vout =
						ss_find_p2a_vout(stx->data,
								 stx->len);
					if (anchor_vout >= 0) {
						uint8_t tx_txid[32];
						struct sha256 h1, h2;
						sha256(&h1, stx->data, stx->len);
						sha256(&h2, &h1, sizeof(h1));
						memcpy(tx_txid, &h2, 32);

						uint64_t value = fcl->nodes[ni]
							.n_outputs > 0
							? fcl->nodes[ni]
							   .outputs[0].amount_sats
							: fi->funding_amount_sats;
						ss_register_pending_cpfp(fi,
							ni == 0
							  ? CPFP_PARENT_KICKOFF
							  : CPFP_PARENT_STATE,
							tx_txid,
							(uint32_t)anchor_vout,
							value,
							fi->expiry_block,
							ss_state.current_blockheight);
					}
				}
			}
		}

		/* Breach scan: check if factory's funding UTXO is still
		 * unspent. Runs for any active factory with a real on-chain
		 * funding UTXO, regardless of role.
		 *
		 * Previously gated on `n_breach_epochs > 0`, which meant the
		 * LSP never ran it (the LSP generates its own secrets and
		 * doesn't accumulate breach_data — breach_data is populated
		 * on the CLIENT side when LSP sends REVOKE). That left the
		 * LSP blind to breaches of its own factories: if a client
		 * published an old (pre-rotation) state TX, the LSP wouldn't
		 * notice until channels went offline and by then the cascade
		 * window may have closed.
		 *
		 * Now both sides scan. breach_utxo_checked handles the
		 * no-secrets case gracefully: it attempts burn TXs only for
		 * epochs where we actually have the revocation secret, and
		 * logs LOG_BROKEN if nothing could be built. Also intentionally
		 * drops the FACTORY_LIFECYCLE_ACTIVE gate from PR #2's version
		 * — DYING factories still need breach monitoring (the DW cascade
		 * race isn't over just because we called force-close).
		 *
		 * Extracted to ss_launch_breach_scan() in the catch-up commit
		 * so the startup-scan path (ss_catchup_breach_scan) and the
		 * per-block path share the same guards. */
		ss_launch_breach_scan(cmd, fi, i);

		/* Phase 4a: proactive deep-unwind detection. Philosophy
		 * ported from upstream's factory_recovery_scan — scan every
		 * block for on-chain state changes, don't wait for a
		 * root-spend heartbeat to trigger. Closes the trustless gap
		 * where counterparty confirms a state TX in a block our
		 * plugin missed (brief offline, private-mempool attack, etc):
		 * the heartbeat may never fire for the root, but scanning
		 * the last few blocks for a TX spending kickoff's output
		 * catches the state TX directly.
		 *
		 * Gate: only for factories with real on-chain funding
		 * (same gate as ss_launch_breach_scan — without confirmed
		 * funding there's no kickoff that can possibly be on chain).
		 * Window is narrow (2 blocks) because this runs every block
		 * — 144-block catchup lives in the startup path + in
		 * breach_utxo_checked.
		 *
		 * Cost: 2 RPCs per factory per block (getblockhash +
		 * getblock). Cheap even with N=20 factories. */
		{
			bool has_real_funding = false;
			for (int fb = 0; fb < 32; fb++) {
				if (fi->funding_txid[fb] != 0) {
					has_real_funding = true;
					break;
				}
			}
			factory_t *fct = (factory_t *)fi->lib_factory;
			if (has_real_funding && fct && fct->n_nodes > 0
			    && !factory_is_closed(fi->lifecycle)) {
				static const uint8_t zero32[32] = {0};
				if (memcmp(fct->nodes[0].txid, zero32, 32) != 0)
					ss_launch_state_tx_scan(cmd, fi,
						fct->nodes[0].txid, 2);
			}
		}

		/* Phase 3c: drive the pending-penalty fee-bump scheduler.
		 * Runs for any factory with pending entries regardless of
		 * lifecycle — a penalty can still be live even as lifecycle
		 * transitions around it. Reorg check is currently a stub;
		 * Phase 4e will populate it. */
		if (fi->n_pending_penalties > 0) {
			ss_penalty_reorg_check_stub(fi);
			ss_penalty_scheduler_tick(cmd, fi,
				ss_state.current_blockheight);

			/* Phase 4b2: auto-trigger source_check every block
			 * for any PENDING/BROADCAST pending_penalty. If the
			 * source UTXO has been RBF'd away, the callback flips
			 * state to STALE and launches a state-TX scan which
			 * (via state_scan_block_cb) will auto-rebuild the
			 * penalty against the new state TX.
			 *
			 * Cost: N BROADCAST pending_penalty entries ×
			 * 1 checkutxo RPC per block. Cheap for typical N<=16. */
			ss_penalty_source_check(cmd, fi);
		}

		/* Phase 4d: sweep scheduler tick. Cheap; only walks in-memory
		 * array. */
		if (fi->n_pending_sweeps > 0) {
			ss_sweep_scheduler_tick(cmd, fi,
				ss_state.current_blockheight);
			/* Phase 4d2: probe source + sweep confirmations via
			 * getrawtransaction, then kick off broadcast of any
			 * entry that has become READY. */
			ss_sweep_probe_all(cmd, fi);
			ss_sweep_kick_all_ready(cmd, fi);
		}

		/* Phase 3c2: CPFP-via-anchor scheduler tick. Walks pending
		 * cpfps for parents that are stuck and would benefit from a
		 * child. V1 logs intents; V2 (3c2.5) will build + broadcast. */
		if (fi->n_pending_cpfps > 0) {
			ss_cpfp_scheduler_tick(cmd, fi,
				ss_state.current_blockheight);
		}

		/* Phase 4c: stuck-INIT detection. Once per
		 * FACTORY_INIT_STUCK_BLOCKS interval beyond creation, log a
		 * loud warning. We don't auto-abort — operator decides
		 * (some ceremonies legitimately take a long time over slow
		 * networks). The warning_close_triggered flag is reused
		 * here as a one-shot per-restart latch so the warning
		 * doesn't spam every block. */
		if (fi->lifecycle == FACTORY_LIFECYCLE_INIT
		    && fi->creation_block > 0
		    && !fi->warning_close_triggered
		    && ss_state.current_blockheight
		       >= fi->creation_block + FACTORY_INIT_STUCK_BLOCKS) {
			char iid_hex[65];
			for (int j = 0; j < 32; j++)
				sprintf(iid_hex + j*2, "%02x",
					fi->instance_id[j]);
			iid_hex[64] = '\0';
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "STUCK INIT: factory %s in lifecycle=INIT "
				   "for %u blocks (since block %u). "
				   "Counterparty likely never responded. "
				   "Consider factory-abort-stuck %s.",
				   iid_hex,
				   ss_state.current_blockheight
				     - fi->creation_block,
				   fi->creation_block, iid_hex);
			fi->warning_close_triggered = true;
		}
	}

	/* Ladder lifecycle: advance block, evict expired factories,
	 * log dying factories that need client migration. */
	if (ss_ladder && ss_ladder->n_factories > 0) {
		ladder_advance_block(ss_ladder, ss_state.current_blockheight);

		/* Log factories entering DYING state */
		ladder_factory_t *dying = ladder_get_dying(ss_ladder);
		if (dying && dying->cached_state == FACTORY_DYING) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				   "LADDER: factory %u entered DYING state "
				   "at block %u — client migration needed",
				   dying->factory_id,
				   ss_state.current_blockheight);
		}

		/* Evict expired factories */
		size_t evicted = ladder_evict_expired(ss_ladder);
		if (evicted > 0)
			plugin_log(plugin_handle, LOG_INFORM,
				   "LADDER: evicted %zu expired factories",
				   evicted);
	}

	return notification_handled(cmd);
}

/* factory-check-breach RPC — check if a txid matches an old epoch
 * and build penalty tx if so. */
static struct command_result *json_factory_check_breach(struct command *cmd,
							const char *buf,
							const jsmntok_t *params)
{
	const char *id_hex;
	const char *txid_hex;
	u32 *vout;
	u64 *amount_sats;
	u32 *epoch;
	factory_instance_t *fi;
	uint8_t instance_id[32];

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_req("txid", param_string, &txid_hex),
		   p_req("vout", param_u32, &vout),
		   p_req("amount_sats", param_u64, &amount_sats),
		   p_req("epoch", param_u32, &epoch),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	for (int j = 0; j < 32; j++) {
		unsigned int b;
		sscanf(id_hex + j*2, "%02x", &b);
		instance_id[j] = (uint8_t)b;
	}

	fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	factory_t *factory = (factory_t *)fi->lib_factory;
	if (!factory)
		return command_fail(cmd, LIGHTNINGD, "No lib_factory");

	/* Parse the L-stock txid */
	uint8_t l_txid[32];
	if (strlen(txid_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad txid");
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		sscanf(txid_hex + j*2, "%02x", &b);
		l_txid[31 - j] = (uint8_t)b; /* internal byte order */
	}

	/* Build burn tx for the specified epoch.
	 * lib PR #121 (zmn t/1242) added leaf_node as the 3rd arg to
	 * factory_build_burn_tx. This dev RPC takes a raw txid from the
	 * operator, so we look up the matching leaf by scanning the
	 * factory's nodes. Returns a clear error if no leaf matches
	 * (caller must have passed a valid L-stock txid from one of this
	 * factory's leaves). */
	const factory_node_t *leaf_for_burn = NULL;
	for (size_t li = 0; li < factory->n_nodes; li++) {
		if (memcmp(factory->nodes[li].txid, l_txid, 32) == 0) {
			leaf_for_burn = &factory->nodes[li];
			break;
		}
	}
	if (!leaf_for_burn) {
		return command_fail(cmd, LIGHTNINGD,
			"No leaf in factory with that l_stock_txid — "
			"check the txid matches an existing leaf node");
	}

	tx_buf_t burn_tx;
	tx_buf_init(&burn_tx, 256);

	if (!factory_build_burn_tx(factory, &burn_tx, leaf_for_burn,
				    l_txid, *vout, *amount_sats,
				    *epoch)) {
		tx_buf_free(&burn_tx);
		return command_fail(cmd, LIGHTNINGD,
				    "Failed to build burn tx (no revocation "
				    "secret for epoch %u?)", *epoch);
	}

	/* Convert to hex */
	char *burn_hex = tal_arr(cmd, char, burn_tx.len * 2 + 1);
	for (size_t h = 0; h < burn_tx.len; h++)
		sprintf(burn_hex + h*2, "%02x", burn_tx.data[h]);

	plugin_log(plugin_handle, LOG_INFORM,
		   "Breach penalty tx built for epoch %u (%zu bytes)",
		   *epoch, burn_tx.len);

	/* Broadcast penalty TX immediately via classified wrapper. */
	ss_broadcast_factory_tx(cmd, fi, burn_hex, FACTORY_TX_BURN);
	plugin_log(plugin_handle, LOG_INFORM,
		   "Breach penalty tx broadcast for epoch %u", *epoch);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "burn_tx", burn_hex);
	json_add_u64(js, "burn_tx_len", burn_tx.len);
	json_add_u32(js, "epoch", *epoch);
	json_add_string(js, "status", "penalty_broadcast");
	tx_buf_free(&burn_tx);
	return command_finished(cmd, js);
}

/* Handle peer connect — send supported_factory_protocols */
static struct command_result *handle_connect(struct command *cmd,
					     const char *buf,
					     const jsmntok_t *params)
{
	const jsmntok_t *connect_tok = json_get_member(buf, params, "connect");
	if (!connect_tok)
		return notification_handled(cmd);

	const jsmntok_t *id_tok = json_get_member(buf, connect_tok, "id");
	if (!id_tok)
		return notification_handled(cmd);

	const char *peer_id = json_strdup(cmd, buf, id_tok);

	/* Send our supported protocols to the newly connected peer */
	send_supported_protocols(cmd, peer_id);

	/* Phase D.4: if we've previously interacted with this peer as an LSP
	 * (have an outgoing_join or a pending_proposal for them), fire a
	 * SIGN_QUEUE_REQUEST so we pick up any held / missed / expired
	 * ceremonies they're tracking for us. */
	{
		uint8_t conn_pk[33];
		bool conn_pk_ok = (strlen(peer_id) == 66
				   && ss_decode_node_id_hex(peer_id, conn_pk));
		bool known_lsp = false;
		if (conn_pk_ok) {
			for (size_t k = 0; k < ss_state.n_outgoing_joins; k++) {
				if (memcmp(ss_state.outgoing_joins[k].lsp_node_id,
					   conn_pk, 33) == 0) { known_lsp = true; break; }
			}
			if (!known_lsp) {
				for (int k = 0; k < SS_POLICY_CACHE_SIZE; k++) {
					struct ss_pending_proposal_entry *pp = &ss_pending_proposals[k];
					if (pp->used
					    && memcmp(pp->lsp_peer_id, conn_pk, 33) == 0) {
						known_lsp = true;
						break;
					}
				}
			}
		}
		if (known_lsp) {
			plugin_log(plugin_handle, LOG_INFORM,
				   "BOLT-8 (re)connect with known LSP %s - "
				   "firing SIGN_QUEUE_REQUEST", peer_id);
			send_factory_msg(cmd, peer_id,
				SS_SUBMSG_SIGN_QUEUE_REQUEST,
				NULL, 0);
		}
	}

	/* Recovery: if a factory we're the LSP for has this peer as a
	 * client mid-ceremony, re-send the cached payload so the
	 * ceremony can continue without manual intervention.
	 * NOTE: ss_state.is_lsp is never assigned anywhere (calloc-zero
	 * default), so we can't gate on the global. The per-factory
	 * fi->is_lsp check inside the loop body is the actual gate. */
	if (strlen(peer_id) != 66)
		return notification_handled(cmd);

	uint8_t pid[33];
	for (int pj = 0; pj < 33; pj++) {
		unsigned int pb;
		if (sscanf(peer_id + pj*2, "%02x", &pb) != 1)
			return notification_handled(cmd);
		pid[pj] = (uint8_t)pb;
	}

	/* Resend REVOKE for any factory where this peer is a client with
	 * an un-acked revocation secret. Separate from ceremony resumption
	 * below because pending REVOKEs are tracked per-client in meta and
	 * don't depend on the ceremony state machine. Idempotent on the
	 * client side: re-storing the same secret doesn't break anything;
	 * the client will just re-ack. */
	for (size_t fi_i = 0; fi_i < ss_state.n_factories; fi_i++) {
		factory_instance_t *lsp_fi = ss_state.factories[fi_i];
		if (!lsp_fi || !lsp_fi->is_lsp) continue;
		factory_t *lf = (factory_t *)lsp_fi->lib_factory;
		if (!lf) continue;
		for (size_t ci = 0; ci < lsp_fi->n_clients; ci++) {
			client_state_t *c = &lsp_fi->clients[ci];
			if (c->pending_revoke_epoch == UINT32_MAX) continue;
			if (memcmp(c->node_id, pid, 33) != 0) continue;
			unsigned char rs[32];
			if (!factory_get_revocation_secret(lf,
				c->pending_revoke_epoch, rs)) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					"Can't resend REVOKE: secret for "
					"epoch %u missing on factory %zu",
					c->pending_revoke_epoch, fi_i);
				continue;
			}
			uint8_t pl[36];
			uint32_t e = c->pending_revoke_epoch;
			pl[0] = (e >> 24) & 0xFF;
			pl[1] = (e >> 16) & 0xFF;
			pl[2] = (e >> 8) & 0xFF;
			pl[3] = e & 0xFF;
			memcpy(pl + 4, rs, 32);
			send_factory_msg(cmd, peer_id,
				SS_SUBMSG_REVOKE, pl, 36);
			plugin_log(plugin_handle, LOG_INFORM,
				"LSP: resent REVOKE (epoch %u) to %s on "
				"reconnect", e, peer_id);
		}
	}

	for (size_t fi_i = 0; fi_i < ss_state.n_factories; fi_i++) {
		factory_instance_t *fi = ss_state.factories[fi_i];
		if (!fi) continue;

		bool is_propose = (fi->ceremony == CEREMONY_PROPOSED &&
				   fi->lib_factory &&
				   fi->n_cached_nonces > 0);
		bool is_nonces  = (fi->ceremony == CEREMONY_NONCES_COLLECTED &&
				   fi->cached_all_nonces_wire &&
				   fi->cached_all_nonces_len > 0);
		/* Rotation reconnect: if a client disconnects after receiving
		 * ROTATE_PROPOSE but before sending ROTATE_NONCE, its
		 * nonce_received flag stays false and the cached payload is
		 * resent on reconnect. */
		bool is_rotating = (fi->ceremony == CEREMONY_ROTATING &&
				    fi->cached_rotate_propose_wire &&
				    fi->cached_rotate_propose_len > 0);
		/* PS-advance reconnect: if a client disconnects after
		 * receiving LEAF_ADVANCE_PROPOSE but before sending PSIG,
		 * resend the cached PROPOSE so the ceremony continues.
		 * Triggered by ps_pending_leaf != -1 + a cached payload. */
		bool is_ps_pending = (fi->ps_pending_leaf != -1 &&
				      fi->cached_ps_propose_wire &&
				      fi->cached_ps_propose_len > 0);
		if (is_ps_pending && fi->is_lsp &&
		    memcmp(fi->cached_ps_propose_target_pid, pid, 33) == 0) {
			send_factory_msg(cmd, peer_id,
				SS_SUBMSG_LEAF_ADVANCE_PROPOSE,
				fi->cached_ps_propose_wire,
				fi->cached_ps_propose_len);
			plugin_log(plugin_handle, LOG_INFORM,
				"Reconnect recovery: re-sent"
				" LEAF_ADVANCE_PROPOSE to client (PS"
				" advance was stalled with"
				" ps_pending_leaf=%d)",
				fi->ps_pending_leaf);
		}
		if (!is_propose && !is_nonces && !is_rotating)
			continue;

		for (size_t ci = 0; ci < fi->n_clients; ci++) {
			if (memcmp(fi->clients[ci].node_id, pid, 33) != 0)
				continue;

			if (is_propose && !fi->clients[ci].nonce_received &&
			    fi->clients[ci].propose_retry_count < SS_MAX_PROPOSE_RETRIES) {
				fi->clients[ci].propose_retry_count++;
				plugin_log(plugin_handle, LOG_DBG,
					   "LSP: reconnect re-PROPOSE %u/%u for client",
					   (unsigned)fi->clients[ci].propose_retry_count,
					   (unsigned)SS_MAX_PROPOSE_RETRIES);
				/* Re-send FACTORY_PROPOSE so client can respond
				 * with its NONCE_BUNDLE. Build nonce bundle from
				 * the cached LSP nonce entries. */
				factory_t *factory = (factory_t *)fi->lib_factory;
				nonce_bundle_t *nb = calloc(1, sizeof(nonce_bundle_t));
				if (!nb) break;

				memcpy(nb->instance_id, fi->instance_id, 32);
				nb->n_participants = (uint32_t)(fi->n_clients + 1);
				nb->n_nodes = factory->n_nodes;
				nb->n_entries = fi->n_cached_nonces;
				memcpy(nb->entries, fi->cached_nonces,
				       fi->n_cached_nonces * sizeof(nonce_entry_t));

				/* Slot 0: LSP real pubkey; rest: placeholders */
				secp256k1_context *ctx = global_secp_ctx;
				secp256k1_pubkey lsp_pub;
				if (secp256k1_ec_pubkey_create(ctx, &lsp_pub,
							       fi->our_seckey)) {
					size_t pklen = 33;
					secp256k1_ec_pubkey_serialize(ctx,
						nb->pubkeys[0], &pklen,
						&lsp_pub, SECP256K1_EC_COMPRESSED);
				}
				for (size_t pk = 1;
				     pk < nb->n_participants &&
				     pk < MAX_PARTICIPANTS; pk++) {
					unsigned char psk[32];
					derive_placeholder_seckey(psk,
						fi->instance_id, (int)pk);
					secp256k1_pubkey ph_pub;
					if (secp256k1_ec_pubkey_create(ctx,
								       &ph_pub,
								       psk)) {
						size_t pklen = 33;
						secp256k1_ec_pubkey_serialize(ctx,
							nb->pubkeys[pk], &pklen,
							&ph_pub,
							SECP256K1_EC_COMPRESSED);
					}
				}

				uint8_t *nbuf = calloc(1, MAX_WIRE_BUF);
				if (!nbuf) { free(nb); break; }
				size_t blen = nonce_bundle_serialize(nb, nbuf,
								     MAX_WIRE_BUF);
				free(nb);

				uint32_t pidx = (uint32_t)(ci + 1);
				uint8_t *cbuf = calloc(1, blen + 4);
				if (!cbuf) { free(nbuf); break; }
				memcpy(cbuf, nbuf, blen);
				cbuf[blen]     = (pidx >> 24) & 0xFF;
				cbuf[blen + 1] = (pidx >> 16) & 0xFF;
				cbuf[blen + 2] = (pidx >> 8)  & 0xFF;
				cbuf[blen + 3] =  pidx         & 0xFF;
				free(nbuf);

				send_factory_msg(cmd, peer_id,
						 SS_SUBMSG_FACTORY_PROPOSE,
						 cbuf, blen + 4);
				free(cbuf);

				plugin_log(plugin_handle, LOG_INFORM,
					   "Reconnect recovery: re-sent"
					   " FACTORY_PROPOSE to client %zu"
					   " (participant_idx=%u)", ci, pidx);

			} else if (is_nonces && !fi->clients[ci].psig_received) {
				/* Re-send ALL_NONCES so client can respond with
				 * its PSIG_BUNDLE. Use the cached wire payload. */
				send_factory_msg(cmd, peer_id,
						 SS_SUBMSG_ALL_NONCES,
						 fi->cached_all_nonces_wire,
						 fi->cached_all_nonces_len);

				plugin_log(plugin_handle, LOG_INFORM,
					   "Reconnect recovery: re-sent"
					   " ALL_NONCES to client %zu", ci);
			} else if (is_rotating && !fi->clients[ci].nonce_received) {
				/* Rotation reconnect: client dropped after
				 * receiving ROTATE_PROPOSE but before sending
				 * ROTATE_NONCE. Resend the cached ROTATE_PROPOSE
				 * payload so the rotation can finish. Idempotent
				 * on the client side: duplicate ROTATE_PROPOSE
				 * just rebuilds the same nonce bundle. */
				send_factory_msg(cmd, peer_id,
						 SS_SUBMSG_ROTATE_PROPOSE,
						 fi->cached_rotate_propose_wire,
						 fi->cached_rotate_propose_len);

				plugin_log(plugin_handle, LOG_INFORM,
					   "Reconnect recovery: re-sent"
					   " ROTATE_PROPOSE to client %zu"
					   " (rotation was stalled at"
					   " CEREMONY_ROTATING)", ci);
			}

			break; /* peer occupies at most one slot per factory */
		}
	}

	return notification_handled(cmd);
}

/* RPC: factory-open-channels
 * Opens LN channels inside a completed factory.
 * Must be called after factory-create ceremony finishes (FACTORY_READY).
 * Separated from ceremony completion so the RPC cmd context stays alive
 * for the async fundchannel_start / fundchannel_complete chain. */
static struct command_result *json_factory_open_channels(struct command *cmd,
							  const char *buf,
							  const jsmntok_t *params)
{
	const char *inst_hex;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &inst_hex),
		   NULL))
		return command_param_failed();

	/* Decode 32-byte instance_id from hex */
	uint8_t instance_id[32];
	if (strlen(inst_hex) != 64) {
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "instance_id must be 64 hex chars");
	}
	for (int i = 0; i < 32; i++) {
		unsigned int b;
		if (sscanf(inst_hex + i*2, "%02x", &b) != 1)
			return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
					    "instance_id: invalid hex");
		instance_id[i] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "No factory with that instance_id");

	if (fi->ceremony != CEREMONY_COMPLETE)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Factory ceremony not complete (state=%d)",
				    fi->ceremony);

	if (!fi->is_lsp)
		return command_fail(cmd, JSONRPC2_INVALID_PARAMS,
				    "Only the LSP opens channels");

	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-open-channels: opening channels for %zu clients",
		   fi->n_clients);

	open_factory_channels(cmd, fi);

	return command_still_pending(cmd);
}

/* Plugin init */
static const char *init(struct command *init_cmd,
			const char *buf UNUSED,
			const jsmntok_t *config UNUSED)
{
	plugin_handle = init_cmd->plugin;

	/* Seed random() for factory instance_id generation.
	 * Without this, default seed=1 → same instance_id every restart,
	 * causing datastore-loaded factories to collide with new ones. */
	{
		unsigned int seed;
		FILE *urandom = fopen("/dev/urandom", "rb");
		if (urandom) {
			if (fread(&seed, sizeof(seed), 1, urandom) != 1)
				seed = (unsigned int)time(NULL);
			fclose(urandom);
		} else {
			seed = (unsigned int)time(NULL);
		}
		srandom(seed);
	}

	ss_state_init(&ss_state);

	global_secp_ctx = secp256k1_context_create(
		SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

	/* Fetch current blockheight and our node_id from lightningd */
	struct node_id our_id;
	u32 blockheight;
	rpc_scan(init_cmd, "getinfo",
		 take(json_out_obj(NULL, NULL, NULL)),
		 "{id:%,blockheight:%}",
		 JSON_SCAN(json_to_node_id, &our_id),
		 JSON_SCAN(json_to_u32, &blockheight));
	ss_state.current_blockheight = blockheight;
	memcpy(ss_state.our_node_id, our_id.k, 33);

	/* Derive factory master key from HSM via makesecret */
	struct secret master_secret;
	rpc_scan(init_cmd, "makesecret",
		 take(json_out_obj(NULL, "string",
				    "superscalar-factory-key")),
		 "{secret:%}",
		 JSON_SCAN(json_to_secret, &master_secret));
	memcpy(ss_state.factory_master_key, master_secret.data, 32);
	/* HSM key active: each node derives its own factory seckey from
	 * its master key + instance_id. Real pubkeys are exchanged during
	 * the NONCE_BUNDLE round; LSP rebuilds the DW tree after collection. */
	ss_state.has_master_key = true;
	plugin_log(plugin_handle, LOG_INFORM,
		   "Factory master key derived from HSM (active — real pubkey "
		   "exchange enabled)");

	/* Phase 3 of two-DB / one-plugin refactor: open the two SQLite
	 * databases this plugin will own (libsuperscalar.db, superscalar-cln.db).
	 * MUST run BEFORE any wallet-db reader (ss_load_iid_counter,
	 * ss_load_outgoing_joins, ss_load_factories) because ss_db_init pins
	 * the path globals to absolute via getcwd — if readers run first they
	 * see relative paths and fail under pyln-testing's shifting cwds.
	 *
	 * Files are created on first start (empty schemas). Phase 4 migration
	 * script populates them from the old soupwallet.db. Phase 5 cutover
	 * removed the sidecar. Failure to open either DB is fatal. */
	if (!ss_db_init()) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "ss_db_init() failed; refusing to start. "
			   "Check the libsuperscalar-db-path and "
			   "superscalar-cln-db-path options + disk space + perms.");
		return "ss_db_init failed";
	}

	/* Gap 8: load monotonic iid counter BEFORE factories so any
	 * derivation we do during startup picks up the right value. */
	ss_load_iid_counter(init_cmd);

	/* Phase 3: load client-side outgoing_joins persistent state. */
	ss_load_outgoing_joins(init_cmd);

	/* Phase C: load persisted policy cache. */

	ss_policy_cache_load_from_disk();
	ss_lsp_sig_queue_load_from_disk();

	/* Task #115: load persisted client signing prefs (or fall back to
	 * canonical defaults) before any FACTORY_PROPOSE can arrive. */
	ss_signing_prefs_load_or_default();

	/* Audit #5 follow-up: log our resolved DB path for operator verification. */
	ss_log_resolved_db_path();

	/* Load persisted factories from datastore */
	ss_load_factories(init_cmd);

	/* Startup catch-up: one-shot breach scan across every active
	 * factory. CLN's block_added notifications only fire on NEW
	 * blocks after init — if the plugin was offline while a breach
	 * occurred (peer published an old kickoff), we'd otherwise miss
	 * it until the next block, at which point the DW state-TX
	 * cascade window may have closed. Scanning now means the
	 * response fires on the very first block tick after init. */
	ss_catchup_breach_scan(init_cmd);

	/* Initialize ladder (multi-factory lifecycle manager).
	 * Uses LSP keypair derived from HSM master key. */
	{
		secp256k1_keypair lsp_kp;
		unsigned char lsp_sk[32];
		/* Use master key directly as LSP ladder key */
		memcpy(lsp_sk, ss_state.factory_master_key, 32);
		if (secp256k1_keypair_create(global_secp_ctx, &lsp_kp, lsp_sk)) {
			ss_ladder = calloc(1, sizeof(ladder_t));
			if (ss_ladder) {
				ladder_init(ss_ladder, global_secp_ctx,
					    &lsp_kp,
					    4320,  /* active: ~30 days */
					    432);  /* dying: ~3 days */
				ss_ladder->current_block =
					ss_state.current_blockheight;
				plugin_log(plugin_handle, LOG_INFORM,
					   "Ladder initialized (active=%u, "
					   "dying=%u blocks)",
					   ss_ladder->active_blocks,
					   ss_ladder->dying_blocks);
			}
		}
	}

	/* Phase 3 + Bug B fix: register the combined reaper timer.
	 * Browse reaper now also scans join slots (ss_join_reap_scan).
	 * Two separate global_timer registrations on the same interval
	 * was crashing the plugin after ~13s. */
	notleak(global_timer(plugin_handle, time_from_sec(5),
			     ss_browse_reap_tick, NULL));
	plugin_log(plugin_handle, LOG_INFORM,
		   "combined slot reaper timer registered (5s tick, browse+join)");

	plugin_log(plugin_handle, LOG_INFORM,
		   "SuperScalar factory plugin initialized "
		   "(blockheight=%u, factories=%zu)",
		   ss_state.current_blockheight,
		   ss_state.n_factories);
	return NULL;
}

/* factory-migrate RPC — LSP migrates cooperative clients from a dying
 * factory to a new one. Orchestrates the full lifecycle:
 * 1. Initiates key turnover for all clients (TURNOVER_REQUEST)
 * 2. After all cooperative clients depart, builds cooperative close
 * 3. Creates new factory for cooperative clients with carryover balances
 *
 * This is the "dying period" migration workflow described in ZmnSCPxj's
 * SuperScalar design. Uncooperative clients must unilateral exit. */
static struct command_result *json_factory_migrate(struct command *cmd,
						    const char *buf,
						    const jsmntok_t *params)
{
	const char *inst_hex;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &inst_hex),
		   NULL))
		return command_param_failed();

	if (strlen(inst_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		sscanf(inst_hex + j*2, "%02x", &b);
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");
	if (!fi->is_lsp)
		return command_fail(cmd, LIGHTNINGD, "Only LSP can migrate");

	/* Step 1: Send TURNOVER_REQUEST to all connected, non-departed clients */
	size_t requests_sent = 0;
	for (size_t ci = 0; ci < fi->n_clients; ci++) {
		if (fi->client_departed[ci])
			continue; /* already departed */

		char nid[67];
		for (int j = 0; j < 33; j++)
			sprintf(nid + j*2, "%02x", fi->clients[ci].node_id[j]);
		nid[66] = '\0';

		send_factory_msg(cmd, nid,
				 SS_SUBMSG_TURNOVER_REQUEST,
				 fi->instance_id, 32);
		requests_sent++;

		plugin_log(plugin_handle, LOG_INFORM,
			   "Migration: sent TURNOVER_REQUEST to client %zu",
			   ci);
	}

	/* Mark factory as dying */
	fi->lifecycle = FACTORY_LIFECYCLE_DYING;
	ss_save_factory(cmd, fi);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "status", "migration_initiated");
	json_add_u64(js, "turnover_requests_sent", requests_sent);
	json_add_u64(js, "already_departed", fi->n_departed);
	json_add_u64(js, "total_clients", fi->n_clients);

	/* Check if we can already close (all clients already departed) */
	if (fi->n_departed >= fi->n_clients) {
		json_add_string(js, "next_step", "all_departed_ready_to_close");
	} else {
		json_add_string(js, "next_step",
				"waiting_for_turnover_responses");
	}

	return command_finished(cmd, js);
}

/* factory-migrate-complete RPC — finalize migration after all cooperative
 * clients have departed. Closes the old factory and creates a new one. */
static struct command_result *json_factory_migrate_complete(struct command *cmd,
							    const char *buf,
							    const jsmntok_t *params)
{
	const char *inst_hex;
	u64 *new_funding_sats;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &inst_hex),
		   p_opt_def("new_funding_sats", param_u64, &new_funding_sats,
			     500000),
		   NULL))
		return command_param_failed();

	if (strlen(inst_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		sscanf(inst_hex + j*2, "%02x", &b);
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");
	if (!fi->is_lsp)
		return command_fail(cmd, LIGHTNINGD, "Only LSP can complete migration");

	/* Collect cooperative (departed) client node IDs */
	size_t n_cooperative = 0;
	char cooperative_ids[MAX_FACTORY_PARTICIPANTS][67];

	for (size_t ci = 0; ci < fi->n_clients; ci++) {
		if (!fi->client_departed[ci])
			continue;
		for (int j = 0; j < 33; j++)
			sprintf(cooperative_ids[n_cooperative] + j*2, "%02x",
				fi->clients[ci].node_id[j]);
		cooperative_ids[n_cooperative][66] = '\0';
		n_cooperative++;
	}

	if (n_cooperative == 0)
		return command_fail(cmd, LIGHTNINGD,
				    "No clients have departed yet");

	/* Mark old factory as expired */
	fi->lifecycle = FACTORY_LIFECYCLE_EXPIRED;
	ss_save_factory(cmd, fi);

	plugin_log(plugin_handle, LOG_INFORM,
		   "Migration complete: %zu cooperative clients, "
		   "%zu uncooperative (must unilateral exit)",
		   n_cooperative, fi->n_clients - n_cooperative);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "status", "migration_complete");
	json_add_u64(js, "cooperative_clients", n_cooperative);
	json_add_u64(js, "uncooperative_clients",
		     fi->n_clients - n_cooperative);
	json_add_string(js, "old_factory", inst_hex);
	json_add_string(js, "next_step",
			"call factory-create with cooperative clients "
			"to create the new factory");

	/* List cooperative client IDs for the next factory-create call */
	json_array_start(js, "cooperative_client_ids");
	for (size_t i = 0; i < n_cooperative; i++)
		json_add_string(js, NULL, cooperative_ids[i]);
	json_array_end(js);

	return command_finished(cmd, js);
}

/* factory-buy-liquidity RPC — rebalance a leaf to move L-stock to client.
 * LSP calls this to sell inbound liquidity from its L-stock reserve
 * to a specific client's channel. Calls factory_set_leaf_amounts to
 * adjust amounts, then requires a leaf re-signing ceremony. */
static struct command_result *json_factory_buy_liquidity(struct command *cmd,
							  const char *buf,
							  const jsmntok_t *params)
{
	const char *inst_hex;
	u32 *client_idx;
	u64 *amount_sats;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &inst_hex),
		   p_req("client_idx", param_u32, &client_idx),
		   p_req("amount_sats", param_u64, &amount_sats),
		   NULL))
		return command_param_failed();

	if (strlen(inst_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		sscanf(inst_hex + j*2, "%02x", &b);
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	factory_t *factory = (factory_t *)fi->lib_factory;
	if (!factory)
		return command_fail(cmd, LIGHTNINGD, "No lib_factory");

	/* Match upstream lsp_channels_buy_liquidity (lsp_channels.c:1962):
	 * the operation is only defined for ARITY_2 (3-of-3 DW) leaves.
	 *   - ARITY_PS: re-signing chain[0] with new amounts has no
	 *     chain-level invalidation of the old chain[0] (TX chaining
	 *     needs a unique parent_txid+vout, which a re-sign violates).
	 *     PS users wanting more inbound capacity should rotate the
	 *     factory.
	 *   - ARITY_1: 2-of-2 single-client leaf, "buying liquidity from
	 *     yourself" — degenerate; upstream doesn't implement it.
	 *
	 * WITHIN-EPOCH POISONING NOTE: a successful realloc re-signs the
	 * leaf with new amounts but the previous signed state remains
	 * publishable by the LSP. Until cross-epoch rotation hands over
	 * this epoch's revocation secret, the client has no chain-level
	 * burn path against the old state. Operators MUST sequence the
	 * client's LN payment AFTER the realloc_complete metric fires —
	 * see "Within-Epoch LEAF_REALLOC Poisoning" in README.md for the
	 * design rationale and future hardening options. */
	factory_arity_t eff = ss_effective_arity(fi);
	if (eff != FACTORY_ARITY_2)
		return command_fail(cmd, LIGHTNINGD,
			"factory-buy-liquidity is only supported on ARITY_2 "
			"factories (got %s) — upstream lsp_channels_buy_liquidity "
			"matches this restriction. Rotate the factory if you "
			"need to redistribute liquidity on other arities.",
			eff == FACTORY_ARITY_PS ? "arity_ps"
			: eff == FACTORY_ARITY_1 ? "arity_1"
			: "auto");

	/* Find which leaf this client is on */
	int leaf_node = factory_find_leaf_for_client(factory,
						      *client_idx + 1);
	if (leaf_node < 0)
		return command_fail(cmd, LIGHTNINGD,
				    "Client %u not found on any leaf",
				    *client_idx);

	/* Find leaf_side index */
	int leaf_side = -1;
	for (int ls = 0; ls < factory->n_leaf_nodes; ls++) {
		if ((int)factory->leaf_node_indices[ls] == leaf_node) {
			leaf_side = ls;
			break;
		}
	}
	if (leaf_side < 0)
		return command_fail(cmd, LIGHTNINGD, "Leaf side not found");

	/* Concurrency guard — must run before factory_advance_leaf_unsigned
	 * (which mutates DW state) so a failed concurrent ceremony doesn't
	 * leave the per-leaf counter desynced from the client. */
	if (fi->ps_pending_leaf != -1)
		return command_fail(cmd, LIGHTNINGD,
			"another leaf ceremony in flight on leaf %d — retry later",
			fi->ps_pending_leaf);
	if (fi->rotation_in_progress)
		return command_fail(cmd, LIGHTNINGD,
			"factory rotation in progress — retry after completion");

	/* Step 1: advance the per-leaf DW counter. Mirrors upstream
	 * lsp_realloc_leaf step 1 (lsp_channels.c:1722). The advance is
	 * what makes the new state safer than the old: under DW the new
	 * state has a smaller nSequence, so any broadcast race resolves
	 * in favor of the newer state. Without this call, old + new leaf
	 * TXs share the same nSequence and the LSP could rebroadcast the
	 * old signed leaf to recover the moved sats. */
	int adv_rc = factory_advance_leaf_unsigned(factory, leaf_side);
	if (adv_rc == 0)
		return command_fail(cmd, LIGHTNINGD,
			"DW counter exhausted on leaf %d — rotate the factory "
			"before further reallocations", leaf_side);
	if (adv_rc == -1)
		return command_fail(cmd, LIGHTNINGD,
			"DW counter exhausted on leaf %d — root layer also "
			"advanced; full factory re-sign required, rotate first",
			leaf_side);

	/* Read current amounts from the leaf node AFTER the advance —
	 * factory_advance_leaf_unsigned calls update_l_stock_for_leaf which
	 * may rewrite the L-stock output to reflect the new epoch's secret
	 * commitments. We want to redistribute starting from the post-
	 * advance amounts. */
	factory_node_t *ln = &factory->nodes[leaf_node];
	size_t n_out = ln->n_outputs;
	uint64_t *new_amts = calloc(n_out, sizeof(uint64_t));
	if (!new_amts)
		return command_fail(cmd, LIGHTNINGD, "OOM");

	for (size_t i = 0; i < n_out; i++)
		new_amts[i] = ln->outputs[i].amount_sats;

	/* Find client's output index (non-LSP signer position) */
	uint32_t client_out = 0;
	for (size_t s = 0; s < ln->n_signers; s++) {
		if (ln->signer_indices[s] == *client_idx + 1)
			break;
		if (ln->signer_indices[s] != 0)
			client_out++;
	}
	size_t lstock_out = n_out - 1; /* L-stock is last output */

	/* Check L-stock has enough */
	if (new_amts[lstock_out] < *amount_sats + 546) {
		uint64_t avail = new_amts[lstock_out];
		free(new_amts);
		return command_fail(cmd, LIGHTNINGD,
				    "Insufficient L-stock: %"PRIu64" < %"PRIu64,
				    avail, *amount_sats);
	}

	/* Move amount from L-stock to client */
	new_amts[client_out] += *amount_sats;
	new_amts[lstock_out] -= *amount_sats;

	/* Save amounts for wire transmission BEFORE calling set_leaf_amounts,
	 * since set_leaf_amounts writes into ln->outputs[] and we want the
	 * same array order to send to the client. */
	uint64_t tx_amts[SS_LEAF_REALLOC_PROPOSE_MAX_OUTPUTS];
	size_t tx_n = n_out;
	if (tx_n > SS_LEAF_REALLOC_PROPOSE_MAX_OUTPUTS) {
		free(new_amts);
		return command_fail(cmd, LIGHTNINGD,
			"leaf has too many outputs (%zu > %d) for REALLOC wire",
			n_out, SS_LEAF_REALLOC_PROPOSE_MAX_OUTPUTS);
	}
	memcpy(tx_amts, new_amts, n_out * sizeof(uint64_t));

	int rc = factory_set_leaf_amounts(factory, leaf_side,
					  new_amts, n_out);
	free(new_amts);

	if (!rc)
		return command_fail(cmd, LIGHTNINGD,
				    "factory_set_leaf_amounts failed");

	plugin_log(plugin_handle, LOG_INFORM,
		   "Liquidity purchase: moved %"PRIu64" sats from L-stock "
		   "to client %u on leaf %d — starting re-sign ceremony",
		   *amount_sats, *client_idx, leaf_side);

	/* Trigger LEAF_REALLOC ceremony to sign the modified leaf state.
	 * Without this the reallocation is ceremonial (in-memory) only —
	 * bitcoind wouldn't accept the on-chain TX. */

	/* Init signing session for the modified leaf node. Must happen AFTER
	 * factory_set_leaf_amounts because set_leaf_amounts rebuilds the
	 * unsigned TX (via rebuild_node_tx) and clears is_signed. */
	size_t node_idx = (size_t)leaf_node;
	if (!factory_session_init_node(factory, node_idx))
		return command_fail(cmd, LIGHTNINGD,
			"session_init_node failed for leaf %d", leaf_side);

	int lsp_slot = factory_find_signer_slot(factory, node_idx, 0);
	if (lsp_slot < 0)
		return command_fail(cmd, LIGHTNINGD,
			"LSP not signer on leaf node %zu", node_idx);

	/* Generate LSP secnonce + pubnonce */
	secp256k1_musig_secnonce *lsp_secnonce =
		calloc(1, sizeof(secp256k1_musig_secnonce));
	if (!lsp_secnonce)
		return command_fail(cmd, LIGHTNINGD, "OOM (secnonce)");

	secp256k1_musig_pubnonce lsp_pubnonce;
	secp256k1_pubkey lsp_pub;
	if (!secp256k1_ec_pubkey_create(global_secp_ctx, &lsp_pub,
					fi->our_seckey)) {
		free(lsp_secnonce);
		return command_fail(cmd, LIGHTNINGD, "LSP pubkey derive failed");
	}
	if (!musig_generate_nonce(global_secp_ctx, lsp_secnonce, &lsp_pubnonce,
				  fi->our_seckey, &lsp_pub,
				  &factory->nodes[node_idx].keyagg.cache)) {
		free(lsp_secnonce);
		return command_fail(cmd, LIGHTNINGD, "nonce gen failed");
	}
	if (!factory_session_set_nonce(factory, node_idx, (size_t)lsp_slot,
				       &lsp_pubnonce)) {
		free(lsp_secnonce);
		return command_fail(cmd, LIGHTNINGD, "set_nonce failed");
	}

	uint8_t lsp_pubnonce_ser[66];
	musig_pubnonce_serialize(global_secp_ctx, lsp_pubnonce_ser,
				 &lsp_pubnonce);

	/* Stash pending state — mark is_realloc so PSIG/DONE handlers skip
	 * the chain-advance persistence path. */
	fi->ps_pending_leaf = (int32_t)leaf_side;
	fi->ps_pending_node_idx = (uint32_t)node_idx;
	fi->ps_pending_secnonce = lsp_secnonce;
	fi->ps_pending_start_block = ss_state.current_blockheight;
	fi->ps_pending_is_realloc = 1;

	/* Populate the realloc scratch space so the NONCE / ALL_NONCES /
	 * PSIG_3 handlers can collect peer state. ARITY_2 is the only
	 * arity allowed past the top-level guard. */
	uint32_t two_clients[2];
	size_t got = factory_get_subtree_clients(factory,
		(int)node_idx, two_clients, 2);
	if (got != 2) {
		ss_clear_ps_pending(fi);
		return command_fail(cmd, LIGHTNINGD,
			"ARITY_2 leaf has %zu clients (expected 2)", got);
	}
	fi->realloc_subtree_clients[0] = two_clients[0];
	fi->realloc_subtree_clients[1] = two_clients[1];
	/* Stash the LSP's own pubnonce in slot order. */
	memcpy(fi->realloc_pubnonces[lsp_slot], lsp_pubnonce_ser, 66);
	fi->realloc_has_pubnonce[lsp_slot] = 1;

	uint8_t payload[32 + 4 + 2 + SS_LEAF_REALLOC_PROPOSE_MAX_OUTPUTS * 8 + 66];
	size_t plen = ss_leaf_realloc_propose_build(payload, sizeof(payload),
		fi->instance_id, (uint32_t)leaf_side,
		tx_amts, tx_n, lsp_pubnonce_ser);
	if (plen == 0) {
		ss_clear_ps_pending(fi);
		return command_fail(cmd, LIGHTNINGD,
			"REALLOC_PROPOSE build failed");
	}

	/* Send PROPOSE to both clients on this leaf. realloc_subtree_clients
	 * holds factory-wide participant_idx values (1..N). fi->clients[]
	 * is 0-indexed, so participant_idx i maps to fi->clients[i-1]. */
	char iid_hex[65];
	for (int j = 0; j < 32; j++)
		sprintf(iid_hex + j*2, "%02x", fi->instance_id[j]);
	iid_hex[64] = '\0';

	for (int i = 0; i < 2; i++) {
		uint32_t pi = fi->realloc_subtree_clients[i];
		if (pi == 0 || pi - 1 >= fi->n_clients) continue;
		char ch[67];
		for (int j = 0; j < 33; j++)
			sprintf(ch + j*2, "%02x",
				fi->clients[pi - 1].node_id[j]);
		ch[66] = '\0';
		send_factory_msg(cmd, ch,
			SS_SUBMSG_LEAF_REALLOC_PROPOSE, payload, plen);
	}
	plugin_log(plugin_handle, LOG_INFORM,
		"SS_METRIC event=realloc_propose iid=%s leaf=%d "
		"client=%u amount=%"PRIu64" arity=2",
		iid_hex, leaf_side, *client_idx, *amount_sats);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "status", "realloc_proposed");
	json_add_u64(js, "amount_sats", *amount_sats);
	json_add_u32(js, "leaf_side", leaf_side);
	json_add_u32(js, "client_idx", *client_idx);
	json_add_string(js, "ceremony", "3-of-3");
	return command_finished(cmd, js);
}

/* factory-initiate-exit RPC — LSP triggers key turnover for a client.
 * Sends TURNOVER_REQUEST to the specified client, beginning the
 * assisted exit protocol. The client responds with their factory key. */
static struct command_result *json_factory_initiate_exit(struct command *cmd,
							  const char *buf,
							  const jsmntok_t *params)
{
	const char *inst_hex, *client_hex;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &inst_hex),
		   p_req("client_id", param_string, &client_hex),
		   NULL))
		return command_param_failed();

	if (strlen(inst_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");
	if (strlen(client_hex) != 66)
		return command_fail(cmd, SS_ERR_INSTANCE_ID_INVALID, "Bad client_id (66 hex chars)");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		sscanf(inst_hex + j*2, "%02x", &b);
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");
	if (!fi->is_lsp)
		return command_fail(cmd, LIGHTNINGD, "Only LSP can initiate exit");

	/* Send TURNOVER_REQUEST to the client */
	send_factory_msg(cmd, client_hex,
			 SS_SUBMSG_TURNOVER_REQUEST,
			 fi->instance_id, 32);

	plugin_log(plugin_handle, LOG_INFORM,
		   "Sent TURNOVER_REQUEST to %s", client_hex);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "status", "turnover_requested");
	json_add_string(js, "client_id", client_hex);
	return command_finished(cmd, js);
}

/* factory-ladder-status RPC — show ladder lifecycle state */
static struct command_result *json_factory_ladder_status(struct command *cmd,
							  const char *buf,
							  const jsmntok_t *params)
{
	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	struct json_stream *js = jsonrpc_stream_success(cmd);

	if (!ss_ladder) {
		json_add_bool(js, "initialized", false);
		return command_finished(cmd, js);
	}

	json_add_bool(js, "initialized", true);
	json_add_u32(js, "n_factories", ss_ladder->n_factories);
	json_add_u32(js, "next_factory_id", ss_ladder->next_factory_id);
	json_add_u32(js, "active_blocks", ss_ladder->active_blocks);
	json_add_u32(js, "dying_blocks", ss_ladder->dying_blocks);
	json_add_u32(js, "current_block", ss_ladder->current_block);

	json_array_start(js, "factories");
	for (size_t i = 0; i < ss_ladder->n_factories; i++) {
		ladder_factory_t *lf = &ss_ladder->factories[i];
		json_object_start(js, NULL);
		json_add_u32(js, "factory_id", lf->factory_id);
		json_add_string(js, "state",
			lf->cached_state == FACTORY_ACTIVE ? "active" :
			lf->cached_state == FACTORY_DYING ? "dying" :
			lf->cached_state == FACTORY_EXPIRED ? "expired" :
			"unknown");
		json_add_bool(js, "is_funded", lf->is_funded != 0);
		json_add_bool(js, "is_initialized", lf->is_initialized != 0);
		json_add_u32(js, "n_participants",
			lf->factory.n_participants);
		json_add_u32(js, "n_departed", lf->n_departed);
		json_add_u32(js, "n_nodes", lf->factory.n_nodes);

		uint32_t blocks_left = factory_blocks_until_dying(
			&lf->factory, ss_ladder->current_block);
		json_add_u32(js, "blocks_until_dying", blocks_left);

		uint32_t blocks_exp = factory_blocks_until_expired(
			&lf->factory, ss_ladder->current_block);
		json_add_u32(js, "blocks_until_expired", blocks_exp);

		json_object_end(js);
	}
	json_array_end(js);

	return command_finished(cmd, js);
}

static const struct plugin_hook hooks[] = {
	{ "custommsg", handle_custommsg },
	{ "openchannel", handle_openchannel },
	{ "htlc_accepted", handle_htlc_accepted },
};

/* Phase 1 trustless-watcher: explicit operator reap of a factory the
 * plugin has flagged as closed (externally or otherwise).
 *
 * Safety: by default the RPC only reaps factories whose lifecycle is a
 * closed-* terminal state (set by the watcher). Pass force=true to reap
 * a factory in any state — useful if the watcher hasn't classified yet
 * but the operator knows the record is dead. In either case the in-
 * memory record is removed first (so the plugin immediately stops
 * advertising, scanning, etc.) and the datastore keys are deleted
 * asynchronously. If any delete fails the factory stays out of memory
 * but the orphaned key remains on disk until the operator intervenes —
 * that is strictly safer than re-attaching the zombie.
 *
 * Does NOT force-close channels, does NOT broadcast breach TXs, does
 * NOT touch the on-chain wallet. This is a pure bookkeeping RPC.
 */
static struct command_result *json_factory_confirm_closed(struct command *cmd,
							   const char *buf,
							   const jsmntok_t *params)
{
	const char *id_hex;
	bool *force;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_opt_def("force", param_bool, &force, false),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD,
				    "Bad instance_id length (need 64 hex chars)");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex at byte %d", j);
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD,
				    "Factory %s not found in memory. Already "
				    "reaped, or never loaded.", id_hex);

	if (!factory_is_closed(fi->lifecycle) && !*force)
		return command_fail(cmd, LIGHTNINGD,
				    "Factory %s is in lifecycle %d (not a "
				    "closed-* terminal state). Pass "
				    "force=true to reap regardless — but "
				    "verify first that on-chain funds have "
				    "been secured.",
				    id_hex, fi->lifecycle);

	/* Find the slot before we free the struct. */
	size_t factory_slot = SIZE_MAX;
	for (size_t i = 0; i < ss_state.n_factories; i++) {
		if (ss_state.factories[i] == fi) {
			factory_slot = i;
			break;
		}
	}

	/* Task #84: wallet.db cleanup on factory-close.
	 *
	 * The previous datastore path issued `deldatastore` per key under
	 * `superscalar/factories/<iid>/*`. With persistence moved to
	 * wallet.db, the C plugin doesn't write directly — the Node-side
	 * wallet plugin owns writes. There's no dedicated wallet-delete-
	 * factory RPC yet; until one lands, stale rows for reaped factories
	 * linger in wallet.db (a few KB per factory; harmless because iids
	 * never repeat — `factory_blob:<iid>:*` keys never collide with a
	 * future factory). Operator can DELETE manually via sqlite3 if
	 * grooming the file matters. */
	char iid_hex[65];
	for (int j = 0; j < 32; j++)
		sprintf(iid_hex + j*2, "%02x", fi->instance_id[j]);
	iid_hex[64] = '\0';
	plugin_log(plugin_handle, LOG_DBG,
		   "factory-reap %s: in-memory removal; wallet.db rows "
		   "(factories, lsp_join_queue, wallet_settings:factory_blob:%s:*) "
		   "left in place — harmless because iids never repeat",
		   iid_hex, iid_hex);

	/* Capture lifecycle for the log message before we free fi. */
	int prior_lifecycle = (int)fi->lifecycle;

	/* Remove from in-memory state. Free the struct — any in-flight
	 * hook callbacks holding fi without a freshness check are buggy
	 * regardless, and would crash on the next state change anyway. */
	if (factory_slot != SIZE_MAX) {
		for (size_t i = factory_slot + 1; i < ss_state.n_factories; i++)
			ss_state.factories[i - 1] = ss_state.factories[i];
		ss_state.n_factories--;
		ss_state.factories[ss_state.n_factories] = NULL;
	}
	if (fi->breach_data) free(fi->breach_data);
	if (fi->dist_signed_tx) free(fi->dist_signed_tx);
	if (fi->keyagg_snapshots) free(fi->keyagg_snapshots);
	free(fi);
	fi = NULL; /* poison */

	/* Refresh the factory-index key so the next startup load doesn't
	 * try to reload the reaped factory. */
	if (factory_slot != SIZE_MAX) {
		size_t idx_len = 2 + ss_state.n_factories * 32;
		uint8_t *idx_buf = calloc(1, idx_len);
		if (idx_buf) {
			idx_buf[0] = (ss_state.n_factories >> 8) & 0xFF;
			idx_buf[1] = ss_state.n_factories & 0xFF;
			for (size_t i = 0; i < ss_state.n_factories; i++)
				memcpy(idx_buf + 2 + i * 32,
				       ss_state.factories[i]->instance_id, 32);
			free(idx_buf);
		}
	}

	plugin_log(plugin_handle, LOG_INFORM,
		   "factory-confirm-closed: reaped factory %s "
		   "(was in lifecycle %d; force=%d)",
		   iid_hex, prior_lifecycle, *force ? 1 : 0);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_bool(js, "reaped", true);
	return command_finished(cmd, js);
}

/* Phase 2a: operator-triggered spending-TX scan with a widenable window.
 * Useful when Phase 1's automatic scan missed (e.g., plugin was offline
 * for weeks, then started; the spend predates the 144-block default
 * window). Safe to call repeatedly; each run overwrites the previous
 * classification. */
static struct command_result *json_factory_scan_external_close(struct command *cmd,
							        const char *buf,
							        const jsmntok_t *params)
{
	const char *id_hex;
	u32 *blocks;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_opt_def("blocks", param_u32, &blocks, 1000),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD,
				    "Bad instance_id length (need 64 hex chars)");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex at byte %d", j);
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory %s not found",
				    id_hex);

	ss_launch_spending_tx_scan(cmd, fi, *blocks);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "scan_window_blocks", *blocks);
	json_add_string(js, "status", "scan_launched");
	return command_finished(cmd, js);
}

/* dev-factory-set-signal — test-only hook for injecting a Phase 3b
 * signal bit into a factory and running the classifier. Mirrors CLN's
 * dev-* convention (see dev-forget-channel, dev-memleak). Used by the
 * E2E test suite to exercise every branch of ss_apply_signals without
 * needing a full on-chain ceremony + spend. Safe in production builds
 * (plugin RPCs are always registered), but operators have no reason to
 * call it — misusing it corrupts the factory lifecycle record.
 *
 * Params: instance_id (hex), signal (string name), match_epoch (u32 opt).
 * Signal names map 1:1 to SIGNAL_* bits:
 *   "utxo_spent", "broadcast_missing", "broadcast_known",
 *   "dist_txid_matched", "kickoff_txid_matched",
 *   "witness_current_match", "witness_past_match", "state_tx_match".
 *
 * match_epoch is required for state_tx_match / witness_past_match; it
 * populates fi->state_tx_match_epoch / fi->breach_epoch respectively so
 * the classifier sees consistent inputs.
 */
static struct command_result *json_dev_factory_set_signal(struct command *cmd,
							  const char *buf,
							  const jsmntok_t *params)
{
	const char *id_hex;
	const char *signal_name;
	u32 *match_epoch;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_req("signal", param_string, &signal_name),
		   p_opt("match_epoch", param_u32, &match_epoch),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD,
				    "Bad instance_id length");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex");
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	uint16_t bit = 0;
	if (!strcmp(signal_name, "utxo_spent"))
		bit = SIGNAL_UTXO_SPENT;
	else if (!strcmp(signal_name, "broadcast_missing"))
		bit = SIGNAL_BROADCAST_MISSING;
	else if (!strcmp(signal_name, "broadcast_known"))
		bit = SIGNAL_BROADCAST_KNOWN;
	else if (!strcmp(signal_name, "dist_txid_matched"))
		bit = SIGNAL_DIST_TXID_MATCHED;
	else if (!strcmp(signal_name, "kickoff_txid_matched"))
		bit = SIGNAL_KICKOFF_TXID_MATCHED;
	else if (!strcmp(signal_name, "witness_current_match"))
		bit = SIGNAL_WITNESS_CURRENT_MATCH;
	else if (!strcmp(signal_name, "witness_past_match"))
		bit = SIGNAL_WITNESS_PAST_MATCH;
	else if (!strcmp(signal_name, "state_tx_match"))
		bit = SIGNAL_STATE_TX_MATCH;
	else if (!strcmp(signal_name, "penalty_confirmed"))
		bit = SIGNAL_PENALTY_CONFIRMED;
	else
		return command_fail(cmd, LIGHTNINGD,
				    "Unknown signal '%s'", signal_name);

	fi->signals_observed |= bit;

	/* Consumer signals need companion state populated. Caller supplies
	 * match_epoch; we route it to the right field so ss_apply_signals
	 * can read a consistent picture. */
	if (match_epoch) {
		if (bit == SIGNAL_STATE_TX_MATCH)
			fi->state_tx_match_epoch = *match_epoch;
		else if (bit == SIGNAL_WITNESS_PAST_MATCH)
			fi->breach_epoch = *match_epoch;
	}

	ss_apply_signals(cmd, fi);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_string(js, "signal_set", signal_name);
	json_add_u32(js, "signals_observed", (u32)fi->signals_observed);
	json_add_string(js, "lifecycle",
		fi->lifecycle == FACTORY_LIFECYCLE_INIT ? "init" :
		fi->lifecycle == FACTORY_LIFECYCLE_ACTIVE ? "active" :
		fi->lifecycle == FACTORY_LIFECYCLE_DYING ? "dying" :
		fi->lifecycle == FACTORY_LIFECYCLE_EXPIRED ? "expired" :
		fi->lifecycle == FACTORY_LIFECYCLE_CLOSED_EXTERNALLY
			? "closed_externally" :
		fi->lifecycle == FACTORY_LIFECYCLE_CLOSED_COOPERATIVE
			? "closed_cooperative" :
		fi->lifecycle == FACTORY_LIFECYCLE_CLOSED_UNILATERAL
			? "closed_unilateral" :
		fi->lifecycle == FACTORY_LIFECYCLE_CLOSED_BREACHED
			? "closed_breached" :
		fi->lifecycle == FACTORY_LIFECYCLE_ABORTED
			? "aborted" :
		"unknown");
	return command_finished(cmd, js);
}

/* dev-factory-inject-penalty — test-only hook for Phase 3c.
 * Inserts a pending_penalty_t directly so tests can exercise the
 * fee-bump scheduler, reorg handling, and SIGNAL_PENALTY_CONFIRMED
/* dev-superscalar-state — test-only probe. Returns the plugin's view
 * of current_blockheight and per-factory ps_pending state so tests
 * can synchronize with block-driven scheduler behavior (timeout
 * cleanup, etc.) without polling logs or guessing timing. */
static struct command_result *
json_dev_superscalar_state(struct command *cmd,
			   const char *buf,
			   const jsmntok_t *params)
{
	const char *id_hex;
	if (!param(cmd, buf, params,
		   p_opt("instance_id", param_string, &id_hex),
		   NULL))
		return command_param_failed();

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_u32(js, "current_blockheight", ss_state.current_blockheight);
	json_add_u32(js, "last_observed_blockheight",
		     ss_state.last_observed_blockheight);
	json_add_u64(js, "n_factories", (u64)ss_state.n_factories);

	if (id_hex) {
		if (strlen(id_hex) != 64)
			return command_fail(cmd, LIGHTNINGD,
				"Bad instance_id length");
		uint8_t instance_id[32];
		for (int j = 0; j < 32; j++) {
			unsigned int b;
			if (sscanf(id_hex + j*2, "%02x", &b) != 1)
				return command_fail(cmd, LIGHTNINGD,
					"Bad instance_id hex");
			instance_id[j] = (uint8_t)b;
		}
		factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
		if (!fi)
			return command_fail(cmd, LIGHTNINGD,
				"Factory not found");
		json_add_string(js, "instance_id", id_hex);
		json_add_s32(js, "ps_pending_leaf", fi->ps_pending_leaf);
		json_add_u32(js, "ps_pending_start_block",
			     fi->ps_pending_start_block);
		json_add_u32(js, "ps_pending_is_realloc",
			     (u32)fi->ps_pending_is_realloc);
		json_add_u32(js, "ceremony", (u32)fi->ceremony);
		json_add_u32(js, "epoch", fi->epoch);
		json_add_bool(js, "is_lsp", fi->is_lsp);
		json_add_u64(js, "cached_ps_propose_len",
			     (u64)fi->cached_ps_propose_len);
		json_add_bool(js, "cached_ps_propose_wire_set",
			      fi->cached_ps_propose_wire != NULL);
		{
			char tpid_hex[67] = {0};
			for (int j = 0; j < 33; j++)
				sprintf(tpid_hex + j*2, "%02x",
					fi->cached_ps_propose_target_pid[j]);
			json_add_string(js, "cached_ps_propose_target_pid",
					tpid_hex);
		}
		json_add_u64(js, "cached_ps_psig_len",
			     (u64)fi->cached_ps_psig_len);
		/* Gap 9: keyagg snapshot fingerprint. SHA256 of the persisted
		 * blob — tests use this to verify pre-restart and post-restart
		 * caches are byte-identical. Empty string when no snapshot has
		 * been captured (factory pre-v15 or pre-funding). */
		json_add_u64(js, "keyagg_snapshots_len",
			     (u64)fi->keyagg_snapshots_len);
		if (fi->keyagg_snapshots && fi->keyagg_snapshots_len > 0) {
			struct sha256 fp;
			sha256(&fp, fi->keyagg_snapshots,
			       fi->keyagg_snapshots_len);
			char fp_hex[65] = {0};
			for (int j = 0; j < 32; j++)
				sprintf(fp_hex + j*2, "%02x",
					((uint8_t *)&fp)[j]);
			json_add_string(js, "keyagg_snapshots_fingerprint",
					fp_hex);
		} else {
			json_add_string(js, "keyagg_snapshots_fingerprint",
					"");
		}
	}
	return command_finished(cmd, js);
}

/* dev-superscalar-tick — synthetically advance ss_state.current_block-
 * height and run the per-block PS-pending timeout cleanup. Avoids the
 * pyln-testing harness gap where mined bitcoind blocks don't trigger
 * the plugin's block_added notification (CLN sees the new tip but
 * the notification doesn't reach our handler in --developer mode).
 *
 * Production code is unaffected — this RPC just bumps the height and
 * runs the same cleanup loop the real handler would. */
static struct command_result *
json_dev_superscalar_tick(struct command *cmd,
			  const char *buf,
			  const jsmntok_t *params)
{
	u32 *to_height;
	if (!param(cmd, buf, params,
		   p_req("to_height", param_u32, &to_height),
		   NULL))
		return command_param_failed();

	uint32_t height = *to_height;
	uint32_t prev = ss_state.current_blockheight;
	ss_state.current_blockheight = height;
	ss_state.last_observed_blockheight = height;

	/* Run the same PS_PENDING_TIMEOUT_BLOCKS cleanup as
	 * handle_block_added. Don't run the heavier breach-scan / cpfp /
	 * sweep logic — those are out of scope for this dev RPC and
	 * would slow down tests. */
	size_t cleared = 0;
	size_t ceremony_timeouts = 0;
	for (size_t i = 0; i < ss_state.n_factories; i++) {
		factory_instance_t *fi = ss_state.factories[i];
		if (!fi) continue;
		if (fi->ps_pending_leaf != -1 &&
		    fi->ps_pending_start_block > 0 &&
		    ss_state.current_blockheight >
			fi->ps_pending_start_block + PS_PENDING_TIMEOUT_BLOCKS) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"SS_METRIC event=ps_advance_timeout "
				"leaf=%d started_at=%u current=%u",
				fi->ps_pending_leaf,
				fi->ps_pending_start_block,
				ss_state.current_blockheight);
			ss_clear_ps_pending(fi);
			cleared++;
		}
		/* Task #151: mirror the handle_block_added client-ceremony
		 * timeout check here so tests can synthetically tick blocks
		 * and verify the client self-terminalizes a stalled ceremony. */
		if (!fi->is_lsp
		    && fi->ceremony_started_block > 0
		    && (fi->ceremony == CEREMONY_PROPOSED
		        || fi->ceremony == CEREMONY_NONCES_COLLECTED
		        || fi->ceremony == CEREMONY_PSIGS_COLLECTED
		        || fi->ceremony == CEREMONY_FUNDING_PENDING
		        || fi->ceremony == CEREMONY_ROTATING)
		    && ss_state.current_blockheight >
			fi->ceremony_started_block + CEREMONY_TIMEOUT_BLOCKS) {
			plugin_log(plugin_handle, LOG_UNUSUAL,
				"SS_METRIC event=client_ceremony_timeout "
				"iid=%02x%02x%02x%02x ceremony=%d "
				"started_at=%u current=%u",
				fi->instance_id[0], fi->instance_id[1],
				fi->instance_id[2], fi->instance_id[3],
				(int)fi->ceremony,
				fi->ceremony_started_block,
				ss_state.current_blockheight);
			ss_terminalize_failed(cmd, fi,
				SS_CEREMONY_ABORT_DEADLINE_PASSED);
			ceremony_timeouts++;
		}
	}

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_u32(js, "previous_blockheight", prev);
	json_add_u32(js, "current_blockheight", height);
	json_add_u64(js, "ps_pending_cleared", (u64)cleared);
	json_add_u64(js, "client_ceremony_timeouts", (u64)ceremony_timeouts);
	return command_finished(cmd, js);
}

 /* dev-factory-inject-penalty — synthesize a pending_penalty entry
 * without requiring a real breach/broadcast. */
static struct command_result *
json_dev_factory_inject_penalty(struct command *cmd,
				const char *buf,
				const jsmntok_t *params)
{
	const char *id_hex;
	u32 *epoch;
	u32 *leaf_index;
	u64 *lstock_sats;
	u32 *csv_unlock_block;
	u32 *tx_vsize;
	u32 *first_broadcast_block;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_req("epoch", param_u32, &epoch),
		   p_req("leaf_index", param_u32, &leaf_index),
		   p_req("lstock_sats", param_u64, &lstock_sats),
		   p_req("csv_unlock_block", param_u32, &csv_unlock_block),
		   p_opt_def("tx_vsize", param_u32, &tx_vsize,
			     LSTOCK_BURN_VSIZE_DEFAULT),
		   p_opt("first_broadcast_block", param_u32,
			 &first_broadcast_block),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex");
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	/* Synthesize a burn_txid deterministically from epoch+leaf so
	 * tests can predict it without having to parse a real tx. */
	uint8_t burn_txid[32];
	memset(burn_txid, 0, 32);
	burn_txid[0] = 0xbe;
	burn_txid[1] = 0xef;
	burn_txid[28] = (uint8_t)((*epoch >> 8) & 0xFF);
	burn_txid[29] = (uint8_t)(*epoch & 0xFF);
	burn_txid[30] = (uint8_t)((*leaf_index >> 8) & 0xFF);
	burn_txid[31] = (uint8_t)(*leaf_index & 0xFF);

	uint32_t start_block = first_broadcast_block
		? *first_broadcast_block
		: ss_state.current_blockheight;

	ss_register_pending_penalty(fi, *epoch, (int)*leaf_index,
				    burn_txid, *lstock_sats,
				    *csv_unlock_block, *tx_vsize,
				    start_block);

	ss_save_factory(cmd, fi);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "n_pending_penalties",
		     (u32)fi->n_pending_penalties);
	return command_finished(cmd, js);
}

/* dev-factory-tick-scheduler — test-only hook to run one penalty
 * scheduler tick at a caller-supplied block height. Decouples the
 * scheduler from the block_added notification so tests can drive it
 * deterministically. */
static struct command_result *
json_dev_factory_tick_scheduler(struct command *cmd,
				const char *buf,
				const jsmntok_t *params)
{
	const char *id_hex;
	u32 *block_height;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_req("block_height", param_u32, &block_height),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex");
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	int bumps = ss_penalty_scheduler_tick(cmd, fi, *block_height);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "block_height", *block_height);
	json_add_u32(js, "bumps", (u32)bumps);
	json_add_u32(js, "n_pending_penalties",
		     (u32)fi->n_pending_penalties);
	return command_finished(cmd, js);
}

/* dev-factory-mark-penalty-confirmed — test-only hook. Sets
 * confirmed_block on the pending_penalty matching (epoch, leaf_index)
 * and fires SIGNAL_PENALTY_CONFIRMED. Exercises the scheduler's
 * "stop rebroadcasting" branch and the classifier's reaction. */
static struct command_result *
json_dev_factory_mark_penalty_confirmed(struct command *cmd,
					const char *buf,
					const jsmntok_t *params)
{
	const char *id_hex;
	u32 *epoch;
	u32 *leaf_index;
	u32 *confirmed_block;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_req("epoch", param_u32, &epoch),
		   p_req("leaf_index", param_u32, &leaf_index),
		   p_req("confirmed_block", param_u32, &confirmed_block),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex");
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	pending_penalty_t *pp = NULL;
	for (size_t i = 0; i < fi->n_pending_penalties; i++) {
		if (fi->pending_penalties[i].epoch == *epoch
		    && fi->pending_penalties[i].leaf_index
		       == (int)*leaf_index) {
			pp = &fi->pending_penalties[i];
			break;
		}
	}
	if (!pp)
		return command_fail(cmd, LIGHTNINGD,
				    "No pending penalty for (epoch=%u, leaf=%u)",
				    *epoch, *leaf_index);

	pp->confirmed_block = *confirmed_block;
	pp->state = PENALTY_STATE_CONFIRMED;
	fi->signals_observed |= SIGNAL_PENALTY_CONFIRMED;
	ss_apply_signals(cmd, fi);
	ss_save_factory(cmd, fi);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "epoch", *epoch);
	json_add_u32(js, "leaf_index", *leaf_index);
	json_add_u32(js, "confirmed_block", *confirmed_block);
	return command_finished(cmd, js);
}

/* dev-factory-trigger-deep-unwind-scan — test-only hook to exercise the
 * Phase 4a proactive scan gating without waiting for a block_added
 * notification. Returns without error even when the scan is skipped
 * (no lib_factory, closed lifecycle, zero kickoff txid), so tests can
 * assert the gating contract directly. */
static struct command_result *
json_dev_factory_trigger_deep_unwind_scan(struct command *cmd,
					  const char *buf,
					  const jsmntok_t *params)
{
	const char *id_hex;
	u32 *window;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_opt_def("window", param_u32, &window, 2),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex");
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	const char *skip_reason = NULL;
	bool has_real_funding = false;
	for (int fb = 0; fb < 32; fb++) {
		if (fi->funding_txid[fb] != 0) {
			has_real_funding = true;
			break;
		}
	}
	factory_t *fct = (factory_t *)fi->lib_factory;
	if (!has_real_funding)
		skip_reason = "no_funding";
	else if (!fct || fct->n_nodes == 0)
		skip_reason = "no_lib_factory";
	else if (factory_is_closed(fi->lifecycle))
		skip_reason = "lifecycle_closed";
	else {
		static const uint8_t zero32[32] = {0};
		if (memcmp(fct->nodes[0].txid, zero32, 32) == 0)
			skip_reason = "zero_kickoff_txid";
	}

	if (!skip_reason)
		ss_launch_state_tx_scan(cmd, fi, fct->nodes[0].txid, *window);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "window", *window);
	if (skip_reason)
		json_add_string(js, "skipped", skip_reason);
	else
		json_add_string(js, "status", "scan_launched");
	return command_finished(cmd, js);
}

/* factory-abort-stuck — operator-facing RPC. Flips an INIT factory to
 * ABORTED. Use after determining the ceremony will never complete
 * (counterparty won't respond). For factories with on-chain funding,
 * the existing CLTV unilateral-exit path recovers funds at expiry —
 * this RPC just removes the factory from active-watcher consideration
 * and surfaces the abort timestamp for forensics.
 *
 * Refuses to abort non-INIT factories — those have closer-to-correct
 * lifecycle labels already. */
static struct command_result *
json_factory_abort_stuck(struct command *cmd,
			 const char *buf,
			 const jsmntok_t *params)
{
	const char *id_hex;
	bool *force;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_opt("force", param_bool, &force),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex");
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	if (fi->lifecycle != FACTORY_LIFECYCLE_INIT
	    && !(force && *force))
		return command_fail(cmd, LIGHTNINGD,
				    "Factory lifecycle is %d, not INIT — "
				    "use force=true to override",
				    (int)fi->lifecycle);

	bool has_funding = false;
	for (int b = 0; b < 32; b++)
		if (fi->funding_txid[b] != 0) {
			has_funding = true; break;
		}

	factory_lifecycle_t prior = fi->lifecycle;
	fi->lifecycle = FACTORY_LIFECYCLE_ABORTED;
	fi->aborted_at_block = ss_state.current_blockheight;
	ss_save_factory(cmd, fi);

	/* Task #149: broadcast CEREMONY_ABORT to participants so client and LSP
	 * views converge. Without this, a client with an in-flight ceremony for
	 * this factory keeps waiting forever (the d607 phantom-PROPOSED bug
	 * we observed: LSP=aborted but client stuck at ceremony=proposed).
	 * DEADLINE_PASSED is the closest stock reason for "operator manually
	 * gave up". Mirrors the LSP/client fan-out in ss_terminalize_failed. */
	{
		char peer_hex[67];
		if (fi->is_lsp) {
			for (size_t ci = 0; ci < fi->n_clients; ci++) {
				for (int j = 0; j < 33; j++)
					sprintf(peer_hex + j*2, "%02x",
						fi->clients[ci].node_id[j]);
				peer_hex[66] = '\0';
				ss_send_factory_abort(cmd, peer_hex,
					fi->instance_id,
					SS_CEREMONY_ABORT_DEADLINE_PASSED);
			}
		} else {
			for (int j = 0; j < 33; j++)
				sprintf(peer_hex + j*2, "%02x",
					fi->lsp_node_id[j]);
			peer_hex[66] = '\0';
			ss_send_factory_abort(cmd, peer_hex,
				fi->instance_id,
				SS_CEREMONY_ABORT_DEADLINE_PASSED);
		}
	}

	plugin_log(plugin_handle, LOG_UNUSUAL,
		   "factory-abort-stuck: instance_id=%s lifecycle %d → "
		   "ABORTED at block %u. has_funding=%d. %s",
		   id_hex, (int)prior, ss_state.current_blockheight,
		   has_funding ? 1 : 0,
		   has_funding
		     ? "Funds are 2-of-2 multisig-locked; recover via the "
		       "existing CLTV unilateral-exit path at factory "
		       "expiry block."
		     : "No on-chain funding to recover; safe to reap via "
		       "factory-confirm-closed.");

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_string(js, "previous_lifecycle",
		prior == FACTORY_LIFECYCLE_INIT ? "init" : "other");
	json_add_string(js, "lifecycle", "aborted");
	json_add_u32(js, "aborted_at_block",
		     ss_state.current_blockheight);
	json_add_bool(js, "has_on_chain_funding", has_funding);
	if (has_funding)
		json_add_string(js, "recovery_path",
			"unilateral_cltv_exit_at_factory_expiry");
	return command_finished(cmd, js);
}

/* Task #150: factory-forget — hard-remove a factory record from in-memory
 * state. SAFETY-GATED: refuses unless lifecycle is FAILED or ABORTED AND
 * the factory has zero on-chain footprint (funding_txid all zeros AND
 * n_channels == 0).
 *
 * Closed/expired factories (EXPIRED, CLOSED_*) carry pre-signed exit /
 * distribution TXs and breach-watch state the operator may need for
 * recovery; those MUST stay in the list. factory-forget is for discarding
 * junk drafts that never touched chain -- not a general "delete factory"
 * button. The wallet UI's bucket model uses Hide for everything else.
 *
 * Mirrors the in-memory cleanup pattern from factory-confirm-closed but
 * with the zero-footprint check up front. */
static struct command_result *
json_factory_forget(struct command *cmd,
		    const char *buf,
		    const jsmntok_t *params)
{
	const char *id_hex;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD,
				    "Bad instance_id length (need 64 hex chars)");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex at byte %d", j);
		instance_id[j] = (uint8_t)b;
	}

	/* Find factory + array slot for in-place removal. */
	factory_instance_t *fi = NULL;
	size_t factory_slot = SIZE_MAX;
	for (size_t i = 0; i < ss_state.n_factories; i++) {
		if (memcmp(ss_state.factories[i]->instance_id,
			   instance_id, 32) == 0) {
			fi = ss_state.factories[i];
			factory_slot = i;
			break;
		}
	}
	if (!fi)
		return command_fail(cmd, LIGHTNINGD,
				    "Factory %s not found", id_hex);

	/* Gate 1: lifecycle must be a terminal *failure* state.
	 * Closed-* and EXPIRED factories carry pre-signed recovery / exit
	 * data; refusing those is the whole point of this RPC. */
	if (fi->lifecycle != FACTORY_LIFECYCLE_FAILED
	    && fi->lifecycle != FACTORY_LIFECYCLE_ABORTED) {
		return command_fail(cmd, LIGHTNINGD,
				    "Factory lifecycle is %d (not FAILED or "
				    "ABORTED) -- use Hide in the wallet to "
				    "declutter without dropping recovery data",
				    (int)fi->lifecycle);
	}

	/* Gate 2: zero on-chain footprint. */
	bool has_funding = false;
	for (int j = 0; j < 32; j++)
		if (fi->funding_txid[j] != 0) {
			has_funding = true;
			break;
		}
	if (has_funding)
		return command_fail(cmd, LIGHTNINGD,
				    "Factory has a funding TX recorded (txid "
				    "is non-zero) -- not safe to forget. Funds "
				    "may be recoverable via the CLTV unilateral "
				    "exit path; use Hide instead.");

	if (fi->n_channels > 0)
		return command_fail(cmd, LIGHTNINGD,
				    "Factory has %zu channel(s); close them "
				    "first via factory-close, then "
				    "factory-confirm-closed.",
				    fi->n_channels);

	int prior_lifecycle = (int)fi->lifecycle;

	/* Remove from in-memory state, free fi. Mirrors the
	 * factory-confirm-closed reap path. */
	for (size_t i = factory_slot + 1; i < ss_state.n_factories; i++)
		ss_state.factories[i - 1] = ss_state.factories[i];
	ss_state.n_factories--;
	ss_state.factories[ss_state.n_factories] = NULL;

	if (fi->breach_data) free(fi->breach_data);
	if (fi->dist_signed_tx) free(fi->dist_signed_tx);
	if (fi->keyagg_snapshots) free(fi->keyagg_snapshots);
	free(fi);
	fi = NULL;

	plugin_log(plugin_handle, LOG_UNUSUAL,
		   "factory-forget: instance_id=%s prior_lifecycle=%d "
		   "n_factories now %u",
		   id_hex, prior_lifecycle,
		   (unsigned)ss_state.n_factories);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_string(js, "lifecycle", "forgotten");
	json_add_u32(js, "previous_lifecycle", (uint32_t)prior_lifecycle);
	return command_finished(cmd, js);
}

/* Phase 3c2.5c test RPC — full end-to-end: build, reserve, sign,
 * send. Returns {status, psbt, signed_txid} on success. The signed_txid
 * is the CPFP child's txid; operator/test can check bitcoind mempool
 * to confirm the package was accepted. */
struct test_sign_send_ctx {
	struct command *orig_cmd;
	char *psbt_b64;  /* for response */
};

static struct command_result *
test_sign_send_final_done(struct command *cmd UNUSED,
			  void *arg,
			  const char *child_txid_hex)
{
	struct test_sign_send_ctx *ctx =
		(struct test_sign_send_ctx *)arg;
	struct json_stream *js = jsonrpc_stream_success(ctx->orig_cmd);
	json_add_string(js, "status", "ok");
	json_add_string(js, "psbt", ctx->psbt_b64);
	json_add_string(js, "child_txid", child_txid_hex);
	return command_finished(ctx->orig_cmd, js);
}

static struct command_result *
test_sign_send_final_fail(struct command *cmd UNUSED,
			  void *arg,
			  const char *reason)
{
	struct test_sign_send_ctx *ctx =
		(struct test_sign_send_ctx *)arg;
	struct json_stream *js = jsonrpc_stream_success(ctx->orig_cmd);
	json_add_string(js, "status", "fail");
	json_add_string(js, "reason", reason);
	if (ctx->psbt_b64)
		json_add_string(js, "psbt", ctx->psbt_b64);
	return command_finished(ctx->orig_cmd, js);
}

static struct command_result *
test_sign_send_build_done(struct command *cmd,
			  void *arg,
			  const char *psbt_b64,
			  const char *wallet_txid_hex UNUSED,
			  uint32_t wallet_vout UNUSED,
			  uint64_t wallet_amount_sat UNUSED,
			  const char *change_address UNUSED)
{
	struct test_sign_send_ctx *ctx =
		(struct test_sign_send_ctx *)arg;
	ctx->psbt_b64 = tal_strdup(ctx, psbt_b64);

	ss_cpfp_sign_and_send(cmd, psbt_b64,
			      test_sign_send_final_done,
			      test_sign_send_final_fail,
			      ctx);
	return command_still_pending(cmd);
}

static struct command_result *
test_sign_send_build_fail(struct command *cmd UNUSED,
			  void *arg,
			  const char *reason)
{
	struct test_sign_send_ctx *ctx =
		(struct test_sign_send_ctx *)arg;
	struct json_stream *js = jsonrpc_stream_success(ctx->orig_cmd);
	json_add_string(js, "status", "fail");
	json_add_string(js, "reason", reason);
	return command_finished(ctx->orig_cmd, js);
}

static struct command_result *
json_dev_factory_test_cpfp_end_to_end(struct command *cmd,
				      const char *buf,
				      const jsmntok_t *params)
{
	const char *parent_txid_hex = NULL;
	u32 *anchor_vout;
	u64 *target_feerate;

	if (!param(cmd, buf, params,
		   p_opt("parent_txid", param_string, &parent_txid_hex),
		   p_opt_def("anchor_vout", param_u32, &anchor_vout, 1),
		   p_opt_def("target_feerate_sat_per_kvb",
			     param_u64, &target_feerate, 10000),
		   NULL))
		return command_param_failed();

	static const char kDefaultParentTxid[65] =
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	if (!parent_txid_hex)
		parent_txid_hex = kDefaultParentTxid;

	uint8_t parent_txid_be[32];
	if (!ss_hex_txid_to_internal(parent_txid_hex, parent_txid_be))
		return command_fail(cmd, LIGHTNINGD,
				    "Bad parent_txid hex");

	struct test_sign_send_ctx *ctx =
		tal(cmd, struct test_sign_send_ctx);
	ctx->orig_cmd = cmd;
	ctx->psbt_b64 = NULL;

	ss_build_cpfp_child(cmd, parent_txid_be, *anchor_vout,
			    *target_feerate,
			    test_sign_send_build_done,
			    test_sign_send_build_fail,
			    ctx);
	return command_still_pending(cmd);
}

/* Phase 3c2.5b test RPC — exercise the full pick → change-addr →
 * build-PSBT chain end-to-end with a synthetic parent. Returns the
 * base64 PSBT so tests can decode + inspect it. */
struct test_build_psbt_ctx {
	struct command *orig_cmd;
};

static struct command_result *
test_build_psbt_done(struct command *cmd UNUSED,
		     void *arg,
		     const char *psbt_b64,
		     const char *wallet_txid_hex,
		     uint32_t wallet_vout,
		     uint64_t wallet_amount_sat,
		     const char *change_address)
{
	struct test_build_psbt_ctx *ctx =
		(struct test_build_psbt_ctx *)arg;
	struct json_stream *js =
		jsonrpc_stream_success(ctx->orig_cmd);
	json_add_string(js, "status", "ok");
	json_add_string(js, "psbt", psbt_b64);
	json_add_string(js, "wallet_txid", wallet_txid_hex);
	json_add_u32(js, "wallet_vout", wallet_vout);
	json_add_u64(js, "wallet_amount_sat", wallet_amount_sat);
	json_add_string(js, "change_address", change_address);
	return command_finished(ctx->orig_cmd, js);
}

static struct command_result *
test_build_psbt_fail(struct command *cmd UNUSED,
		     void *arg,
		     const char *reason)
{
	struct test_build_psbt_ctx *ctx =
		(struct test_build_psbt_ctx *)arg;
	struct json_stream *js =
		jsonrpc_stream_success(ctx->orig_cmd);
	json_add_string(js, "status", "fail");
	json_add_string(js, "reason", reason);
	return command_finished(ctx->orig_cmd, js);
}

static struct command_result *
json_dev_factory_test_build_cpfp_psbt(struct command *cmd,
				      const char *buf,
				      const jsmntok_t *params)
{
	const char *parent_txid_hex = NULL;
	u32 *anchor_vout;
	u64 *target_feerate;

	if (!param(cmd, buf, params,
		   p_opt("parent_txid", param_string, &parent_txid_hex),
		   p_opt_def("anchor_vout", param_u32, &anchor_vout, 1),
		   p_opt_def("target_feerate_sat_per_kvb",
			     param_u64, &target_feerate, 10000),
		   NULL))
		return command_param_failed();

	/* Default synthetic parent txid: 0xAA repeated. Used by tests
	 * that don't care about the specific outpoint. */
	static const char kDefaultParentTxid[65] =
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	if (!parent_txid_hex)
		parent_txid_hex = kDefaultParentTxid;

	uint8_t parent_txid_be[32];
	if (!ss_hex_txid_to_internal(parent_txid_hex, parent_txid_be))
		return command_fail(cmd, LIGHTNINGD,
				    "Bad parent_txid hex");

	struct test_build_psbt_ctx *ctx =
		tal(cmd, struct test_build_psbt_ctx);
	ctx->orig_cmd = cmd;

	ss_build_cpfp_child(cmd, parent_txid_be, *anchor_vout,
			    *target_feerate,
			    test_build_psbt_done,
			    test_build_psbt_fail,
			    ctx);
	return command_still_pending(cmd);
}

/* Phase 3c2.5a test RPCs — exercise the wallet helpers end-to-end
 * without invoking the full CPFP pipeline. Used by pytest to verify
 * the async RPC chains work + UTXO selection picks the right coin.
 * Response shape is stable so tests can assert on specific fields. */

struct test_utxo_pick_ctx {
	struct command *orig_cmd;
};

static struct command_result *
test_utxo_pick_done(struct command *cmd UNUSED,
		    void *arg,
		    const char *txid_hex,
		    uint32_t vout,
		    uint64_t amount_sat,
		    const char *spk_hex,
		    const char *address)
{
	struct test_utxo_pick_ctx *ctx =
		(struct test_utxo_pick_ctx *)arg;
	struct json_stream *js = jsonrpc_stream_success(ctx->orig_cmd);
	json_add_string(js, "status", "ok");
	json_add_string(js, "txid", txid_hex);
	json_add_u32(js, "vout", vout);
	json_add_u64(js, "amount_sat", amount_sat);
	json_add_string(js, "scriptpubkey", spk_hex);
	json_add_string(js, "address", address);
	return command_finished(ctx->orig_cmd, js);
}

static struct command_result *
test_utxo_pick_fail(struct command *cmd UNUSED,
		    void *arg,
		    const char *reason)
{
	struct test_utxo_pick_ctx *ctx =
		(struct test_utxo_pick_ctx *)arg;
	struct json_stream *js = jsonrpc_stream_success(ctx->orig_cmd);
	json_add_string(js, "status", "fail");
	json_add_string(js, "reason", reason);
	return command_finished(ctx->orig_cmd, js);
}

static struct command_result *
json_dev_factory_test_utxo_pick(struct command *cmd,
				const char *buf,
				const jsmntok_t *params)
{
	u64 *min_amount_sat;

	if (!param(cmd, buf, params,
		   p_opt_def("min_amount_sat", param_u64, &min_amount_sat,
			     10000),
		   NULL))
		return command_param_failed();

	struct test_utxo_pick_ctx *ctx =
		tal(cmd, struct test_utxo_pick_ctx);
	ctx->orig_cmd = cmd;

	ss_pick_wallet_utxo(cmd, *min_amount_sat,
			    test_utxo_pick_done,
			    test_utxo_pick_fail,
			    ctx);
	return command_still_pending(cmd);
}

struct test_change_addr_ctx {
	struct command *orig_cmd;
};

static struct command_result *
test_change_addr_done(struct command *cmd UNUSED,
		      void *arg,
		      const char *address)
{
	struct test_change_addr_ctx *ctx =
		(struct test_change_addr_ctx *)arg;
	struct json_stream *js = jsonrpc_stream_success(ctx->orig_cmd);
	json_add_string(js, "status", "ok");
	json_add_string(js, "address", address);
	return command_finished(ctx->orig_cmd, js);
}

static struct command_result *
test_change_addr_fail(struct command *cmd UNUSED,
		      void *arg,
		      const char *reason)
{
	struct test_change_addr_ctx *ctx =
		(struct test_change_addr_ctx *)arg;
	struct json_stream *js = jsonrpc_stream_success(ctx->orig_cmd);
	json_add_string(js, "status", "fail");
	json_add_string(js, "reason", reason);
	return command_finished(ctx->orig_cmd, js);
}

static struct command_result *
json_dev_factory_test_change_addr(struct command *cmd,
				  const char *buf,
				  const jsmntok_t *params)
{
	if (!param(cmd, buf, params, NULL))
		return command_param_failed();

	struct test_change_addr_ctx *ctx =
		tal(cmd, struct test_change_addr_ctx);
	ctx->orig_cmd = cmd;

	ss_get_change_p2tr(cmd, test_change_addr_done,
			   test_change_addr_fail, ctx);
	return command_still_pending(cmd);
}

/* dev-factory-inject-cpfp — test-only hook for Phase 3c2. Registers
 * a synthetic pending_cpfp_t so tests can drive the scheduler without
 * a real chain interaction. */
static struct command_result *
json_dev_factory_inject_cpfp(struct command *cmd,
			     const char *buf,
			     const jsmntok_t *params)
{
	const char *id_hex;
	const char *kind_str;
	u32 *anchor_vout;
	u64 *value_at_stake;
	u32 *deadline_block;
	u32 *parent_broadcast_block;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_req("kind", param_string, &kind_str),
		   p_req("anchor_vout", param_u32, &anchor_vout),
		   p_req("value_at_stake", param_u64, &value_at_stake),
		   p_req("deadline_block", param_u32, &deadline_block),
		   p_opt("parent_broadcast_block", param_u32,
			 &parent_broadcast_block),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex");
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	uint8_t kind = CPFP_PARENT_DIST;
	if (!strcmp(kind_str, "dist"))    kind = CPFP_PARENT_DIST;
	else if (!strcmp(kind_str, "state"))   kind = CPFP_PARENT_STATE;
	else if (!strcmp(kind_str, "kickoff")) kind = CPFP_PARENT_KICKOFF;
	else
		return command_fail(cmd, LIGHTNINGD,
				    "Unknown CPFP kind '%s'", kind_str);

	uint8_t fake_txid[32];
	memset(fake_txid, 0, 32);
	fake_txid[0] = 0xc9; fake_txid[1] = 0xfb;
	fake_txid[28] = (uint8_t)(*anchor_vout & 0xFF);
	fake_txid[29] = kind;
	fake_txid[30] = (uint8_t)((*deadline_block >> 8) & 0xFF);
	fake_txid[31] = (uint8_t)(*deadline_block & 0xFF);

	uint32_t start = parent_broadcast_block
		? *parent_broadcast_block
		: ss_state.current_blockheight;

	ss_register_pending_cpfp(fi, kind, fake_txid, *anchor_vout,
				 *value_at_stake, *deadline_block, start);
	ss_save_factory(cmd, fi);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "n_pending_cpfps", (u32)fi->n_pending_cpfps);
	return command_finished(cmd, js);
}

/* dev-factory-tick-cpfp-scheduler — drive the CPFP scheduler at a
 * caller-supplied block height. */
static struct command_result *
json_dev_factory_tick_cpfp_scheduler(struct command *cmd,
				     const char *buf,
				     const jsmntok_t *params)
{
	const char *id_hex;
	u32 *block_height;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_req("block_height", param_u32, &block_height),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex");
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	int intents = ss_cpfp_scheduler_tick(cmd, fi, *block_height);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "block_height", *block_height);
	json_add_u32(js, "intents", (u32)intents);
	json_add_u32(js, "n_pending_cpfps", (u32)fi->n_pending_cpfps);
	return command_finished(cmd, js);
}

/* dev-factory-mark-cpfp-parent-confirmed — flip parent_confirmed_block
 * and let scheduler resolve to RESOLVED state. */
static struct command_result *
json_dev_factory_mark_cpfp_parent_confirmed(struct command *cmd,
					    const char *buf,
					    const jsmntok_t *params)
{
	const char *id_hex;
	u32 *anchor_vout;
	u32 *confirmed_block;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_req("anchor_vout", param_u32, &anchor_vout),
		   p_req("confirmed_block", param_u32, &confirmed_block),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex");
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	pending_cpfp_t *pc = NULL;
	for (size_t i = 0; i < fi->n_pending_cpfps; i++) {
		if (fi->pending_cpfps[i].parent_vout_anchor
		    == *anchor_vout) {
			pc = &fi->pending_cpfps[i];
			break;
		}
	}
	if (!pc)
		return command_fail(cmd, LIGHTNINGD,
				    "No pending CPFP for anchor_vout=%u",
				    *anchor_vout);

	pc->parent_confirmed_block = *confirmed_block;
	ss_save_factory(cmd, fi);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "parent_confirmed_block", *confirmed_block);
	return command_finished(cmd, js);
}

/* factory-source-check — operator-facing RPC that probes the source
 * UTXO each pending burn-TX spends. Flips matching pending_penalty
 * entries to STALE if the source is gone (state TX RBF'd). Phase 4b. */
static struct command_result *
json_factory_source_check(struct command *cmd,
			  const char *buf,
			  const jsmntok_t *params)
{
	const char *id_hex;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex");
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	int probes = ss_penalty_source_check(cmd, fi);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "probes_issued", (u32)probes);
	json_add_u32(js, "n_pending_penalties",
		     (u32)fi->n_pending_penalties);
	return command_finished(cmd, js);
}

/* dev-factory-trigger-source-check — test alias of factory-source-check. */
static struct command_result *
json_dev_factory_trigger_source_check(struct command *cmd,
				      const char *buf,
				      const jsmntok_t *params)
{
	return json_factory_source_check(cmd, buf, params);
}

/* dev-factory-mark-penalty-stale — directly flip a penalty to STALE
 * for tests that don't need to drive the async checkutxo flow.
 * Mirrors dev-factory-mark-penalty-confirmed. */
static struct command_result *
json_dev_factory_mark_penalty_stale(struct command *cmd,
				    const char *buf,
				    const jsmntok_t *params)
{
	const char *id_hex;
	u32 *epoch;
	u32 *leaf_index;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_req("epoch", param_u32, &epoch),
		   p_req("leaf_index", param_u32, &leaf_index),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex");
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	pending_penalty_t *pp = NULL;
	for (size_t i = 0; i < fi->n_pending_penalties; i++) {
		if (fi->pending_penalties[i].epoch == *epoch
		    && fi->pending_penalties[i].leaf_index
		       == (int)*leaf_index) {
			pp = &fi->pending_penalties[i];
			break;
		}
	}
	if (!pp)
		return command_fail(cmd, LIGHTNINGD,
				    "No penalty for (epoch=%u, leaf=%u)",
				    *epoch, *leaf_index);

	pp->state = PENALTY_STATE_STALE;
	ss_save_factory(cmd, fi);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_string(js, "state", "stale");
	return command_finished(cmd, js);
}

/* dev-factory-inject-sweep — test-only hook for Phase 4d. Registers
 * a pending_sweep_t for the scheduler to walk. */
static struct command_result *
json_dev_factory_inject_sweep(struct command *cmd,
			      const char *buf,
			      const jsmntok_t *params)
{
	const char *id_hex;
	const char *type_str;
	u32 *source_vout;
	u64 *amount_sats;
	u32 *csv_delay;
	u32 *confirmed_block;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_req("type", param_string, &type_str),
		   p_req("source_vout", param_u32, &source_vout),
		   p_req("amount_sats", param_u64, &amount_sats),
		   p_req("csv_delay", param_u32, &csv_delay),
		   p_opt("confirmed_block", param_u32, &confirmed_block),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex");
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	uint8_t type = SWEEP_TYPE_FACTORY_LEAF;
	if (!strcmp(type_str, "factory_lstock"))
		type = SWEEP_TYPE_FACTORY_LSTOCK;
	else if (!strcmp(type_str, "factory_leaf"))
		type = SWEEP_TYPE_FACTORY_LEAF;
	else if (!strcmp(type_str, "factory_timeout"))
		type = SWEEP_TYPE_FACTORY_TIMEOUT;
	else
		return command_fail(cmd, LIGHTNINGD,
				    "Unknown sweep type '%s'", type_str);

	uint8_t fake_txid[32];
	memset(fake_txid, 0, 32);
	fake_txid[0] = 0x5e; fake_txid[1] = 0xed;
	fake_txid[30] = (uint8_t)((*source_vout >> 8) & 0xFF);
	fake_txid[31] = (uint8_t)(*source_vout & 0xFF);

	ss_register_pending_sweep(fi, type, fake_txid, *source_vout,
				  *amount_sats, *csv_delay);

	/* Optionally stamp confirmed_block so tests can skip the "waiting
	 * for source confirm" state. */
	if (confirmed_block && fi->n_pending_sweeps > 0) {
		pending_sweep_t *ps =
			&fi->pending_sweeps[fi->n_pending_sweeps - 1];
		ps->confirmed_block = *confirmed_block;
	}

	ss_save_factory(cmd, fi);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "n_pending_sweeps", (u32)fi->n_pending_sweeps);
	return command_finished(cmd, js);
}

/* dev-factory-tick-sweep-scheduler — test-only hook to run one sweep
 * scheduler pass at a caller-supplied block height. */
static struct command_result *
json_dev_factory_tick_sweep_scheduler(struct command *cmd,
				      const char *buf,
				      const jsmntok_t *params)
{
	const char *id_hex;
	u32 *block_height;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_req("block_height", param_u32, &block_height),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex");
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	int transitions = ss_sweep_scheduler_tick(cmd, fi, *block_height);
	/* NOTE: dev-tick deliberately does NOT fire ss_sweep_kick_all_ready.
	 * Auto-kickoff runs only from the real block_added hook. Tests that
	 * need to exercise state-machine advancement without side-effects
	 * keep using dev-factory-mark-sweep-broadcast; tests that want to
	 * exercise the real kickoff path drive bitcoind generate_block
	 * instead (which fires the block_added scheduler integration). */

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "block_height", *block_height);
	json_add_u32(js, "transitions", (u32)transitions);
	json_add_u32(js, "n_pending_sweeps", (u32)fi->n_pending_sweeps);
	return command_finished(cmd, js);
}

/* dev-factory-mark-sweep-broadcast — test-only. Simulates the 4d2
 * integration point that will actually broadcast a sweep TX. Moves the
 * first READY entry to BROADCAST with a synthetic sweep_txid and the
 * caller-supplied block. Real 4d2 code will compute these from the
 * broadcast reply. */
static struct command_result *
json_dev_factory_mark_sweep_broadcast(struct command *cmd,
				      const char *buf,
				      const jsmntok_t *params)
{
	const char *id_hex;
	u32 *source_vout;
	u32 *broadcast_block;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_req("source_vout", param_u32, &source_vout),
		   p_req("broadcast_block", param_u32, &broadcast_block),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex");
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	pending_sweep_t *ps = NULL;
	for (size_t i = 0; i < fi->n_pending_sweeps; i++) {
		if (fi->pending_sweeps[i].source_vout == *source_vout
		    && fi->pending_sweeps[i].state == SWEEP_STATE_READY) {
			ps = &fi->pending_sweeps[i];
			break;
		}
	}
	if (!ps)
		return command_fail(cmd, LIGHTNINGD,
				    "No READY sweep for source_vout=%u",
				    *source_vout);

	ps->state = SWEEP_STATE_BROADCAST;
	ps->broadcast_block = *broadcast_block;
	ps->sweep_txid[0] = 0x5b; /* synthetic marker */
	ps->sweep_txid[1] = 0xcd;
	ss_save_factory(cmd, fi);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_string(js, "state", "broadcast");
	return command_finished(cmd, js);
}

/* dev-factory-mark-sweep-failed — test-only. Sets a pending_sweep to
 * FAILED with the caller-supplied broadcast_block. Simulates a failed
 * broadcast without the real async kickoff chain. Used by
 * test_sweep_retry.py to drive retry cycles deterministically. */
static struct command_result *
json_dev_factory_mark_sweep_failed(struct command *cmd,
				   const char *buf,
				   const jsmntok_t *params)
{
	const char *id_hex;
	u32 *source_vout;
	u32 *broadcast_block;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_req("source_vout", param_u32, &source_vout),
		   p_req("broadcast_block", param_u32, &broadcast_block),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex");
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	pending_sweep_t *ps = NULL;
	for (size_t i = 0; i < fi->n_pending_sweeps; i++) {
		if (fi->pending_sweeps[i].source_vout == *source_vout) {
			ps = &fi->pending_sweeps[i];
			break;
		}
	}
	if (!ps)
		return command_fail(cmd, LIGHTNINGD,
				    "No sweep for source_vout=%u",
				    *source_vout);

	ps->state = SWEEP_STATE_FAILED;
	ps->broadcast_block = *broadcast_block;
	ss_save_factory(cmd, fi);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "source_vout", *source_vout);
	json_add_string(js, "state", "failed");
	json_add_u32(js, "broadcast_block", *broadcast_block);
	return command_finished(cmd, js);
}

/* dev-factory-mark-sweep-confirmed — test-only. Stamps
 * sweep_confirmed_block so the scheduler's BROADCAST→CONFIRMED
 * transition can fire. */
static struct command_result *
json_dev_factory_mark_sweep_confirmed(struct command *cmd,
				      const char *buf,
				      const jsmntok_t *params)
{
	const char *id_hex;
	u32 *source_vout;
	u32 *sweep_confirmed_block;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   p_req("source_vout", param_u32, &source_vout),
		   p_req("sweep_confirmed_block", param_u32,
			 &sweep_confirmed_block),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex");
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	pending_sweep_t *ps = NULL;
	for (size_t i = 0; i < fi->n_pending_sweeps; i++) {
		if (fi->pending_sweeps[i].source_vout == *source_vout) {
			ps = &fi->pending_sweeps[i];
			break;
		}
	}
	if (!ps)
		return command_fail(cmd, LIGHTNINGD,
				    "No sweep for source_vout=%u",
				    *source_vout);

	ps->sweep_confirmed_block = *sweep_confirmed_block;
	ss_save_factory(cmd, fi);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "sweep_confirmed_block", *sweep_confirmed_block);
	return command_finished(cmd, js);
}

/* factory-reorg-check — operator-facing RPC to re-validate confirmed
 * penalty TXs against current chain state. Use after observing a
 * reorg (e.g., from bitcoind logs) to reset any penalty whose TX got
 * evicted. Returns number of probes issued; results materialize
 * asynchronously in the log (LOG_UNUSUAL "REORG RE-EVAL:" lines) and
 * in factory-list.pending_penalties[].state flipping back to
 * "broadcast". */
static struct command_result *
json_factory_reorg_check(struct command *cmd,
			 const char *buf,
			 const jsmntok_t *params)
{
	const char *id_hex;

	if (!param(cmd, buf, params,
		   p_req("instance_id", param_string, &id_hex),
		   NULL))
		return command_param_failed();

	if (strlen(id_hex) != 64)
		return command_fail(cmd, LIGHTNINGD, "Bad instance_id");

	uint8_t instance_id[32];
	for (int j = 0; j < 32; j++) {
		unsigned int b;
		if (sscanf(id_hex + j*2, "%02x", &b) != 1)
			return command_fail(cmd, LIGHTNINGD,
					    "Bad instance_id hex");
		instance_id[j] = (uint8_t)b;
	}

	factory_instance_t *fi = ss_factory_find(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD, "Factory not found");

	int probes = ss_penalty_reorg_check(cmd, fi);

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "instance_id", id_hex);
	json_add_u32(js, "probes_issued", (u32)probes);
	json_add_u32(js, "n_pending_penalties",
		     (u32)fi->n_pending_penalties);
	return command_finished(cmd, js);
}

/* dev-factory-trigger-reorg-check — alias of factory-reorg-check
 * named with dev-* to signal "test / development use." Identical
 * implementation; kept distinct so tests can find it under a stable
 * dev-* prefix alongside the other Phase 4e/5a injection hooks. */
static struct command_result *
json_dev_factory_trigger_reorg_check(struct command *cmd,
				     const char *buf,
				     const jsmntok_t *params)
{
	return json_factory_reorg_check(cmd, buf, params);
}

/* ============================================================================
 * factory-funding-precheck RPC (Phase 4)
 *
 * Wallet calls this BEFORE factory-create to verify enough confirmed
 * non-reserved UTXOs exist. Pure inspection — does not allocate any
 * factory state. Output is shaped to drive the wallet's "you need to
 * deposit N more sats" UI.
 *
 * Default fee estimate: 1000 sats (~ a few hundred vbytes at modest
 * feerate). Caller can override with fee_estimate_sats.
 *
 * Failure modes:
 *   - SS_ERR_INSUFFICIENT_FUNDS only when caller passes strict=true
 *     AND wallet can't cover it. Otherwise returns a JSON response with
 *     sufficient=false so the wallet can render the gap.
 * ============================================================================ */

struct funding_precheck_ctx {
	u64 funding_sats;
	u64 fee_estimate_sats;
	bool strict;
};

static struct command_result *
funding_precheck_listfunds_reply(struct command *cmd,
				 const char *method UNUSED,
				 const char *buf,
				 const jsmntok_t *result,
				 void *arg)
{
	struct funding_precheck_ctx *ctx = (struct funding_precheck_ctx *)arg;

	const jsmntok_t *outputs = json_get_member(buf, result, "outputs");
	if (!outputs || outputs->type != JSMN_ARRAY) {
		return command_fail(cmd, SS_ERR_INTERNAL,
			"factory-funding-precheck: listfunds returned no outputs array");
	}

	uint64_t available_sats = 0;
	uint32_t counted = 0;
	const jsmntok_t *t;
	size_t i;
	json_for_each_arr(i, t, outputs) {
		const jsmntok_t *status_tok = json_get_member(buf, t, "status");
		const jsmntok_t *reserved_tok = json_get_member(buf, t, "reserved");
		const jsmntok_t *amt_tok = json_get_member(buf, t, "amount_msat");
		if (!status_tok || !reserved_tok || !amt_tok) continue;

		if (!json_tok_streq(buf, status_tok, "confirmed")) continue;

		bool reserved_flag;
		if (!json_to_bool(buf, reserved_tok, &reserved_flag)) continue;
		if (reserved_flag) continue;

		u64 amt_msat;
		if (!json_to_u64(buf, amt_tok, &amt_msat)) continue;
		available_sats += amt_msat / 1000;
		counted++;
	}

	uint64_t required_sats = ctx->funding_sats + ctx->fee_estimate_sats;
	bool sufficient = available_sats >= required_sats;
	uint64_t shortfall = sufficient ? 0 : (required_sats - available_sats);

	if (ctx->strict && !sufficient) {
		return command_fail(cmd, SS_ERR_INSUFFICIENT_FUNDS,
			"factory-funding-precheck: wallet has %"PRIu64" sat "
			"confirmed non-reserved, need %"PRIu64" sat "
			"(funding=%"PRIu64" + fee=%"PRIu64"). Shortfall %"PRIu64" sat.",
			available_sats, required_sats,
			ctx->funding_sats, ctx->fee_estimate_sats,
			shortfall);
	}

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_u64(js, "funding_sats", ctx->funding_sats);
	json_add_u64(js, "fee_estimate_sats", ctx->fee_estimate_sats);
	json_add_u64(js, "required_sats", required_sats);
	json_add_u64(js, "available_sats", available_sats);
	json_add_u32(js, "utxos_counted", counted);
	json_add_bool(js, "sufficient", sufficient);
	if (!sufficient)
		json_add_u64(js, "shortfall_sats", shortfall);
	return command_finished(cmd, js);
}

static struct command_result *
funding_precheck_listfunds_err(struct command *cmd,
			       const char *method UNUSED,
			       const char *buf UNUSED,
			       const jsmntok_t *result UNUSED,
			       void *arg UNUSED)
{
	return command_fail(cmd, SS_ERR_INTERNAL,
		"factory-funding-precheck: listfunds RPC failed");
}

static struct command_result *
json_factory_funding_precheck(struct command *cmd,
			      const char *buf,
			      const jsmntok_t *params)
{
	u64 *funding_sats;
	u64 *fee_estimate_sats_opt;
	bool *strict_opt;
	if (!param(cmd, buf, params,
		   p_req("funding_sats", param_u64, &funding_sats),
		   p_opt("fee_estimate_sats", param_u64, &fee_estimate_sats_opt),
		   p_opt("strict", param_bool, &strict_opt),
		   NULL))
		return command_param_failed();

	struct funding_precheck_ctx *ctx = tal(cmd, struct funding_precheck_ctx);
	ctx->funding_sats = *funding_sats;
	ctx->fee_estimate_sats = fee_estimate_sats_opt ? *fee_estimate_sats_opt : 253; /* 1 sat/vb floor; CLN min_acceptable */
	ctx->strict = strict_opt ? *strict_opt : false;

	struct out_req *req = jsonrpc_request_start(cmd, "listfunds",
		funding_precheck_listfunds_reply,
		funding_precheck_listfunds_err,
		ctx);
	send_outreq(req);
	return command_still_pending(cmd);
}

static const struct plugin_command commands[] = {
	{
		"dev-factory-set-signal",
		json_dev_factory_set_signal,
	},
	{
		"dev-superscalar-state",
		json_dev_superscalar_state,
	},
	{
		"dev-superscalar-tick",
		json_dev_superscalar_tick,
	},
	{
		"dev-factory-inject-penalty",
		json_dev_factory_inject_penalty,
	},
	{
		"dev-factory-tick-scheduler",
		json_dev_factory_tick_scheduler,
	},
	{
		"dev-factory-mark-penalty-confirmed",
		json_dev_factory_mark_penalty_confirmed,
	},
	{
		"dev-factory-trigger-deep-unwind-scan",
		json_dev_factory_trigger_deep_unwind_scan,
	},
	{
		"dev-factory-trigger-reorg-check",
		json_dev_factory_trigger_reorg_check,
	},
	{
		"factory-reorg-check",
		json_factory_reorg_check,
	},
	{
		"dev-factory-inject-sweep",
		json_dev_factory_inject_sweep,
	},
	{
		"dev-factory-tick-sweep-scheduler",
		json_dev_factory_tick_sweep_scheduler,
	},
	{
		"dev-factory-mark-sweep-broadcast",
		json_dev_factory_mark_sweep_broadcast,
	},
	{
		"dev-factory-mark-sweep-failed",
		json_dev_factory_mark_sweep_failed,
	},
	{
		"dev-factory-mark-sweep-confirmed",
		json_dev_factory_mark_sweep_confirmed,
	},
	{
		"dev-factory-trigger-source-check",
		json_dev_factory_trigger_source_check,
	},
	{
		"dev-factory-mark-penalty-stale",
		json_dev_factory_mark_penalty_stale,
	},
	{
		"factory-source-check",
		json_factory_source_check,
	},
	{
		"factory-abort-stuck",
		json_factory_abort_stuck,
	},
	{
		"factory-forget",
		json_factory_forget,
	},
	{
		"dev-factory-test-utxo-pick",
		json_dev_factory_test_utxo_pick,
	},
	{
		"dev-factory-test-change-addr",
		json_dev_factory_test_change_addr,
	},
	{
		"dev-factory-test-build-cpfp-psbt",
		json_dev_factory_test_build_cpfp_psbt,
	},
	{
		"dev-factory-test-cpfp-end-to-end",
		json_dev_factory_test_cpfp_end_to_end,
	},
	{
		"dev-factory-inject-cpfp",
		json_dev_factory_inject_cpfp,
	},
	{
		"dev-factory-tick-cpfp-scheduler",
		json_dev_factory_tick_cpfp_scheduler,
	},
	{
		"dev-factory-mark-cpfp-parent-confirmed",
		json_dev_factory_mark_cpfp_parent_confirmed,
	},
	{
		"client-list-held-proposals",
		json_client_list_held_proposals,
	},
	{
		"client-list-outgoing-joins",
		json_client_list_outgoing_joins,
	},
	{
		"factory-get-cached-policy",
		json_factory_get_cached_policy,
	},
	{
		"client-list-recent-sign-queue-events",
		json_client_list_recent_sign_queue_events,
	},
	{
		"client-dismiss-sign-queue-event",
		json_client_dismiss_sign_queue_event,
	},
	{
		"client-signing-prefs-get",
		json_client_signing_prefs_get,
	},
	{
		"client-signing-prefs-set",
		json_client_signing_prefs_set,
	},
	{
		"factory-browse-host",
		json_factory_browse_host,
	},
	{
		"factory-approve-proposal",
		json_factory_approve_proposal,
	},
	{
		"factory-refuse-proposal",
		json_factory_refuse_proposal,
	},
	{
		"factory-review-proposal",
		json_factory_review_proposal,
	},
	{
		"factory-join-request",
		json_factory_join_request,
	},
	{
		"factory-cancel-join",
		json_factory_cancel_join,
	},
	{
		"factory-incoming-joins",
		json_factory_incoming_joins,
	},
	{
		"factory-funding-precheck",
		json_factory_funding_precheck,
	},
	{
		"factory-kick-joiner",
		json_factory_kick_joiner,
	},
	{
		"factory-create",
		json_factory_create,
	},
	{
		"factory-trigger-ceremony",
		json_factory_trigger_ceremony,
	},
	{
		"factory-list",
		json_factory_list,
	},
	{
		"factory-metrics",
		json_factory_metrics,
	},
	{
		"factory-rotate",
		json_factory_rotate,
	},
	{
		"factory-close",
		json_factory_close,
	},
	{
		"factory-force-close",
		json_factory_force_close,
	},
	{
		"factory-ps-advance",
		json_factory_ps_advance,
	},
	{
		"factory-check-breach",
		json_factory_check_breach,
	},
	{
		"factory-open-channels",
		json_factory_open_channels,
	},
	{
		"factory-ladder-status",
		json_factory_ladder_status,
	},
	{
		"factory-initiate-exit",
		json_factory_initiate_exit,
	},
	{
		"factory-buy-liquidity",
		json_factory_buy_liquidity,
	},
	{
		"factory-migrate",
		json_factory_migrate,
	},
	{
		"factory-migrate-complete",
		json_factory_migrate_complete,
	},
	{
		"factory-close-departed",
		json_factory_close_departed,
	},
	{
		"factory-confirm-closed",
		json_factory_confirm_closed,
	},
	{
		"factory-scan-external-close",
		json_factory_scan_external_close,
	},
	{
		"wallet-get-iid-counter",
		json_wallet_get_iid_counter,
	},
	{
		"wallet-increment-iid-counter",
		json_wallet_increment_iid_counter,
	},
	{
		"wallet-set-iid-counter",
		json_wallet_set_iid_counter,
	},
	{
		"wallet-upsert-factory",
		json_wallet_upsert_factory,
	},
	{
		"wallet-get-factory",
		json_wallet_get_factory,
	},
	{
		"wallet-list-factories-by-role",
		json_wallet_list_factories_by_role,
	},
	{
		"wallet-upsert-join-queue-entry",
		json_wallet_upsert_join_queue_entry,
	},
	{
		"wallet-list-join-queue-by-status",
		json_wallet_list_join_queue_by_status,
	},
	{
		"wallet-count-join-queue-by-status",
		json_wallet_count_join_queue_by_status,
	},
	{
		"wallet-upsert-outgoing-join",
		json_wallet_upsert_outgoing_join,
	},
	{
		"wallet-list-outgoing-joins-by-status",
		json_wallet_list_outgoing_joins_by_status,
	},
	{
		"wallet-save-factory-policy-snapshot",
		json_wallet_save_factory_policy_snapshot,
	},
	{
		"wallet-get-factory-policy-snapshot",
		json_wallet_get_factory_policy_snapshot,
	},
	{
		"wallet-set-operator-pref",
		json_wallet_set_operator_pref,
	},
	{
		"wallet-get-operator-pref",
		json_wallet_get_operator_pref,
	},
	{
		"wallet-set-signing-pref",
		json_wallet_set_signing_pref,
	},
	{
		"wallet-get-signing-pref",
		json_wallet_get_signing_pref,
	},
	{
		"wallet-set-setting",
		json_wallet_set_setting,
	},
	{
		"wallet-get-setting",
		json_wallet_get_setting,
	},
	{
		"wallet-status",
		json_wallet_status,
	},
	{
		"wallet-approve-join-queued",
		json_wallet_approve_join_queued,
	},
	{
		"wallet-refuse-join-queued",
		json_wallet_refuse_join_queued,
	},
	{
		"wallet-list-known-peers",
		json_wallet_list_known_peers,
	},
	{
		"wallet-set-peer-note",
		json_wallet_set_peer_note,
	},
	{
		"wallet-get-peer-note",
		json_wallet_get_peer_note,
	},
	{
		"wallet-set-peer-reputation",
		json_wallet_set_peer_reputation,
	},
	{
		"wallet-get-peer-reputation",
		json_wallet_get_peer_reputation,
	},
	{
		"wallet-list-events-since",
		json_wallet_list_events_since,
	},
	{
		"wallet-get-latest-event-id",
		json_wallet_get_latest_event_id,
	},
};

static const struct plugin_notification notifs[] = {
	{ "block_added", handle_block_added },
	{ "connect", handle_connect },
};

int main(int argc, char *argv[])
{
	setup_locale();

	/* Feature bit 271 (pluggable_channel_factories) is advertised
	 * by the CLN fork's base code in common/features.h.
	 * No need to set it again from the plugin. */

	plugin_main(argv, init,
		    take(NULL),
		    PLUGIN_RESTARTABLE,
		    true,
		    NULL,
		    commands, ARRAY_SIZE(commands),
		    notifs, ARRAY_SIZE(notifs),
		    hooks, ARRAY_SIZE(hooks),
		    NULL, 0,
		    plugin_option("superscalar-browse-timeout-secs",
				  "int",
				  "Seconds before a pending factory-browse-host "
				  "request times out and is reaped. Default 30.",
				  u32_option, u32_jsonfmt,
				  &ss_browse_timeout_secs),
		    plugin_option("superscalar-join-timeout-secs",
				  "int",
				  "Seconds before a pending factory-join-request "
				  "times out and is reaped. Default 30.",
				  u32_option, u32_jsonfmt,
				  &ss_join_timeout_secs),
		    plugin_option("superscalar-wallet-db",
				  "string",
				  "Override path for the wallet.db that the C "
				  "plugin opens read-only at restart. Should "
				  "match the Node-side soupwallet-db-path.",
				  charp_option, charp_jsonfmt,
				  &ss_wallet_db_path_override),
		    plugin_option("libsuperscalar-db-path",
				  "string",
				  "Path to libsuperscalar.db (lib-owned protocol state). "
				  "Default: <CWD>/libsuperscalar.db.",
				  charp_option, charp_jsonfmt,
				  &ss_lib_db_path_override),
		    plugin_option("superscalar-cln-db-path",
				  "string",
				  "Path to superscalar-cln.db (plugin-owned policy/"
				  "coordination state). Default: <CWD>/superscalar-cln.db.",
				  charp_option, charp_jsonfmt,
				  &ss_plugin_db_path_override),
		    plugin_option("enable-session-restore",
				  "bool",
				  "Forward-looking integration point for lib task #80. "
				  "When the lib ships factory_restore_sessions() and this "
				  "option is true, ss_load_factories will attempt to "
				  "restore in-flight MuSig2 sessions instead of resetting "
				  "them to FAILED. Default false (use interim mitigation). "
				  "Do NOT enable until the lib API is available and "
				  "regtest-verified — see LIB_TEAM_REPLY_MUSIG_PERSISTENCE.md.",
				  bool_option, bool_jsonfmt,
				  &ss_enable_session_restore),
		    NULL);
}
