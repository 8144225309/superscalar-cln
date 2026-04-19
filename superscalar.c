/* SuperScalar channel factory plugin for Core Lightning.
 *
 * Links against libsuperscalar.a for DW tree construction,
 * MuSig2 signing, and factory state management.
 */
#include "config.h"
#include <ccan/array_size/array_size.h>
#include <ccan/tal/str/str.h>
#include <common/json_param.h>
#include <common/json_stream.h>
#include <plugins/libplugin.h>
#include <bitcoin/psbt.h>
#include <bitcoin/privkey.h>
#include <common/features.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <inttypes.h>
#include <ccan/crypto/sha256/sha256.h>
#include <secp256k1.h>
#include <secp256k1_extrakeys.h>

#include "ceremony.h"
#include "factory_state.h"
#include "nonce_exchange.h"
#include "persist.h"

/* SuperScalar library */
#include <superscalar/factory.h>
#include <superscalar/musig.h>
#include <superscalar/dw_state.h>
#include <superscalar/ladder.h>
#include <superscalar/adaptor.h>
#include <superscalar/htlc_fee_bump.h>
#include <common/bech32.h>

static struct plugin *plugin_handle;
static superscalar_state_t ss_state;
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

/* Compute worst-case DW tree unwind time for HTLC safety.
 * This is the minimum early_warning_time: if an HTLC times out in
 * fewer blocks than this, we can't force-close the factory in time
 * to enforce it on-chain.
 *
 * Formula: n_layers * step_blocks * (states_per_layer - 1)
 *          + n_layers * 6 (confirmation buffer per layer)
 *          + 36 (flat safety margin ~6 hours) */
static uint16_t compute_early_warning_time(size_t n_clients)
{
	/* DW tree depth: arity-1 for 2 participants, arity-2 for 3+ */
	size_t n_layers;
	if (n_clients <= 1)
		n_layers = 1;
	else {
		/* ceil(log2(ceil(n_clients/2))) + 1 for arity-2 */
		size_t leaves = (n_clients + 1) / 2;
		n_layers = 1;
		while ((1u << n_layers) < leaves)
			n_layers++;
		n_layers++; /* +1 for the root→state transition */
	}
	uint32_t total = n_layers * DW_STEP_BLOCKS * (DW_STATES_PER_LAYER - 1)
		       + n_layers * 6 + 36;
	if (total > 65535) total = 65535;
	return (uint16_t)total;
}

/* SuperScalar protocol ID: first 32 bytes of "SuperScalar/v1" zero-padded */
static const uint8_t SUPERSCALAR_PROTOCOL_ID[32] = {
	'S','u','p','e','r','S','c','a','l','a','r','/','v','1',
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

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
		uint64_t lt = ln->input_amount;
		amts[nclients] = lt > csum ? lt - csum : 546;
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
		fi->ceremony = CEREMONY_FAILED;
		return notification_handled(cmd);
	}

	const char *txid_hex = json_strdup(cmd, buf, txid_tok);
	if (!txid_hex || strlen(txid_hex) != 64) {
		plugin_log(plugin_handle, LOG_BROKEN,
			   "withdraw: bad txid hex");
		fi->ceremony = CEREMONY_FAILED;
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
	fctx->fi->ceremony = CEREMONY_FAILED;
	const char *err_str = json_strdup(tmpctx, buf, result);
	plugin_log(plugin_handle, LOG_BROKEN,
		   "withdraw failed: %s", err_str ? err_str : "unknown");
	return command_hook_success(cmd);
}

/* Send a SuperScalar message wrapped in factory_piggyback (submsg 4).
 * Wire format: type(2) + submsg_id=4(2) + TLV[0]=protocol_id(34) +
 *              TLV[1024]=payload(4+len) where payload = ss_submsg(2)+data */
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
	char *hex = tal_arr(cmd, char, actual_len * 2 + 1);
	for (size_t h = 0; h < actual_len; h++)
		sprintf(hex + h*2, "%02x", wire[h]);

	struct out_req *req = jsonrpc_request_start(cmd,
		"sendcustommsg", rpc_done, rpc_err, cmd);
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

	/* Funding amount: half of factory total for 2 participants (demo) */
	struct amount_sat funding_amt;
	funding_amt.satoshis = DEFAULT_FUNDING_SATS;

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
			uint64_t amt = fi->clients[ci].allocation_sats;
			if (amt == 0)
				amt = DEFAULT_FUNDING_SATS;
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
			     : compute_early_warning_time(fi->n_clients));
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

	/* Send ROTATE_COMPLETE to clients */
	for (size_t ci = 0; ci < fi->n_clients; ci++) {
		char nid[67];
		for (int j = 0; j < 33; j++)
			sprintf(nid + j*2, "%02x",
				fi->clients[ci].node_id[j]);
		nid[66] = '\0';
		send_factory_msg(cmd, nid,
			SS_SUBMSG_ROTATE_COMPLETE,
			fi->instance_id, 32);
	}

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
static void ss_save_factory(struct command *cmd, factory_instance_t *fi)
{
	char key[128];
	uint8_t *buf;
	size_t len;

	/* Save metadata */
	ss_persist_key_meta(fi, key, sizeof(key));
	len = ss_persist_serialize_meta(fi, &buf);
	if (len > 0 && buf) {
		jsonrpc_set_datastore_binary(cmd, key, buf, len,
			"create-or-replace", rpc_done, rpc_err, fi);
		free(buf);
	}

	/* Save channel mappings */
	if (fi->n_channels > 0) {
		ss_persist_key_channels(fi, key, sizeof(key));
		len = ss_persist_serialize_channels(fi, &buf);
		if (len > 0 && buf) {
			jsonrpc_set_datastore_binary(cmd, key, buf, len,
				"create-or-replace", rpc_done, rpc_err, fi);
			free(buf);
		}
	}

	/* Save breach data for current epoch */
	for (size_t i = 0; i < fi->n_breach_epochs; i++) {
		ss_persist_key_breach(fi, fi->breach_data[i].epoch,
				      key, sizeof(key));
		len = ss_persist_serialize_breach(&fi->breach_data[i], &buf);
		if (len > 0 && buf) {
			jsonrpc_set_datastore_binary(cmd, key, buf, len,
				"create-or-replace", rpc_done, rpc_err, fi);
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
			jsonrpc_set_datastore_binary(cmd, key, bi_buf, bi_len,
				"create-or-replace", rpc_done, rpc_err, fi);
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
	jsonrpc_set_datastore_binary(cmd,
		"superscalar/factory-index", idx_buf, idx_len,
		"create-or-replace", rpc_done, rpc_err, fi);
	free(idx_buf);

	/* Save signed DW tree transactions (for force-close after restart).
	 * Both LSP and client persist independently — each must be able
	 * to unilaterally exit without the other's cooperation. */
	if (fi->lib_factory) {
		ss_persist_key_signed_txs(fi, key, sizeof(key));
		len = ss_persist_serialize_signed_txs(fi->lib_factory, &buf);
		if (len > 0 && buf) {
			jsonrpc_set_datastore_binary(cmd, key, buf, len,
				"create-or-replace", rpc_done, rpc_err, fi);
			free(buf);
		}
	}

	/* Save signed distribution TX (inverted timeout default).
	 * After expiry, this TX gives clients their funds without LSP. */
	if (fi->dist_signed_tx && fi->dist_signed_tx_len > 0) {
		ss_persist_key_dist_tx(fi, key, sizeof(key));
		len = ss_persist_serialize_dist_tx(fi, &buf);
		if (len > 0 && buf) {
			jsonrpc_set_datastore_binary(cmd, key, buf, len,
				"create-or-replace", rpc_done, rpc_err, fi);
			free(buf);
		}
	}

	plugin_log(plugin_handle, LOG_DBG,
		   "Persisted factory state (epoch=%u, channels=%zu)",
		   fi->epoch, fi->n_channels);
}

/* Load factories from CLN datastore on startup.
 * Reads factory-index key to discover instance IDs, then
 * loads each factory's meta and channel mappings. */
static void ss_load_factories(struct command *cmd)
{
	size_t loaded = 0;
	u8 *meta_hex = NULL;
	const char *err;

	/* Read factory index: count(2) + instance_ids(32 each) */
	err = rpc_scan_datastore_hex(tmpctx, cmd,
		"superscalar/factory-index",
		JSON_SCAN_TAL(tmpctx, json_tok_bin_from_hex, &meta_hex));

	if (!err && meta_hex) {
		/* Index format: count(2) + instance_ids(32 each) */
		size_t idx_len = tal_bytelen(meta_hex);
		if (idx_len >= 2) {
			uint16_t count = (meta_hex[0] << 8) | meta_hex[1];
			const u8 *p = meta_hex + 2;
			size_t rem = idx_len - 2;

			for (uint16_t i = 0; i < count && rem >= 32; i++) {
				char id_hex[65];
				for (int j = 0; j < 32; j++)
					sprintf(id_hex + j*2, "%02x", p[j]);
				id_hex[64] = '\0';

				/* Try loading this factory's meta */
				char meta_path[128];
				snprintf(meta_path, sizeof(meta_path),
					 "superscalar/factories/%s/meta",
					 id_hex);
				u8 *fmeta = NULL;
				err = rpc_scan_datastore_hex(tmpctx, cmd,
					meta_path,
					JSON_SCAN_TAL(tmpctx,
						json_tok_bin_from_hex,
						&fmeta));
				if (err || !fmeta) {
					p += 32; rem -= 32;
					continue;
				}

				/* Deserialize */
				factory_instance_t *fi = ss_factory_new(
					&ss_state, p);
				if (!fi) {
					p += 32; rem -= 32;
					continue;
				}

				if (!ss_persist_deserialize_meta(fi,
					fmeta, tal_bytelen(fmeta))) {
					plugin_log(plugin_handle, LOG_UNUSUAL,
						   "Failed to deserialize "
						   "factory %s", id_hex);
					p += 32; rem -= 32;
					continue;
				}

				/* Load channel mappings */
				char ch_path[128];
				snprintf(ch_path, sizeof(ch_path),
					 "superscalar/factories/%s/channels",
					 id_hex);
				u8 *chdata = NULL;
				if (!rpc_scan_datastore_hex(tmpctx, cmd,
					ch_path,
					JSON_SCAN_TAL(tmpctx,
						json_tok_bin_from_hex,
						&chdata))
				    && chdata) {
					ss_persist_deserialize_channels(fi,
						chdata, tal_bytelen(chdata));
				}

				/* Load breach data */
				char bi_path[128];
				snprintf(bi_path, sizeof(bi_path),
					 "superscalar/factories/%s/breach-index",
					 id_hex);
				u8 *bidata = NULL;
				if (!rpc_scan_datastore_hex(tmpctx, cmd,
						bi_path,
						JSON_SCAN_TAL(tmpctx,
							json_tok_bin_from_hex,
							&bidata))
				    && bidata) {
					size_t bi_len = tal_bytelen(bidata);
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
							char breach_path[128];
							snprintf(breach_path,
								 sizeof(breach_path),
								 "superscalar/factories/%s/breach/%u",
								 id_hex, ep);
							u8 *bdata = NULL;
							if (!rpc_scan_datastore_hex(tmpctx, cmd,
									breach_path,
									JSON_SCAN_TAL(tmpctx,
										json_tok_bin_from_hex,
										&bdata))
							    && bdata) {
								epoch_breach_data_t bd;
								memset(&bd, 0, sizeof(bd));
								if (ss_persist_deserialize_breach(
									&bd, bdata,
									tal_bytelen(bdata))) {
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

				loaded++;
				plugin_log(plugin_handle, LOG_INFORM,
					   "Loaded factory %s (epoch=%u, "
					   "channels=%zu, breach_epochs=%zu, "
					   "lifecycle=%d)",
					   id_hex, fi->epoch,
					   fi->n_channels, fi->n_breach_epochs,
					   fi->lifecycle);

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
							int slot = fi->is_lsp
								? (int)(ci + 1) : 0;
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
							n_total <= 2
							? FACTORY_ARITY_1
							: FACTORY_ARITY_2);
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
							/* Load signed TXs from
							 * datastore if available */
							{
							char stx_key[128];
							ss_persist_key_signed_txs(
								fi, stx_key,
								sizeof(stx_key));
							u8 *stx_data = NULL;
							const char *stx_err;
							stx_err = rpc_scan_datastore_hex(
								tmpctx, cmd, stx_key,
								JSON_SCAN_TAL(tmpctx,
									json_tok_bin_from_hex,
									&stx_data));
							if (!stx_err && stx_data) {
								size_t stx_len =
									tal_bytelen(stx_data);
								if (stx_len > 0)
									ss_persist_deserialize_signed_txs(
										f, stx_data,
										stx_len);
								plugin_log(plugin_handle,
									LOG_INFORM,
									"Loaded signed "
									"TXs (%zu bytes)",
									stx_len);
							}
							}

							/* Fix early_warning_time
							 * for old factories */
							if (fi->early_warning_time == 0)
								fi->early_warning_time =
									compute_early_warning_time(
										n_total > 1
										? n_total - 1 : 1);
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

				/* Load signed distribution TX (inverted timeout
				 * default) — survives restart for auto-broadcast
				 * at expiry. */
				{
					char dtx_key[128];
					ss_persist_key_dist_tx(fi, dtx_key,
						sizeof(dtx_key));
					u8 *dtx_data = NULL;
					const char *dtx_err;
					dtx_err = rpc_scan_datastore_hex(
						tmpctx, cmd, dtx_key,
						JSON_SCAN_TAL(tmpctx,
							json_tok_bin_from_hex,
							&dtx_data));
					if (!dtx_err && dtx_data) {
						size_t dtx_len =
							tal_bytelen(dtx_data);
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

				p += 32; rem -= 32;
			}
		}
	}

	plugin_log(plugin_handle, LOG_INFORM,
		   "Loaded %zu factories from datastore", loaded);

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
					"address: %s. Check on-chain and either "
					"complete the ceremony or delete the "
					"factory.", iid_hex, addr);
			}
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
		factory_set_arity(new_f, n_total <= 2
			? FACTORY_ARITY_1 : FACTORY_ARITY_2);
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

		factory_t *old_f = f;
		if (old_f) { factory_free(old_f); free(old_f); }
		fi->lib_factory = new_f;
		f = new_f;

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
		fi->ceremony = CEREMONY_FAILED;
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

static void dispatch_superscalar_submsg(struct command *cmd,
					const char *peer_id,
					u16 submsg_id,
					const u8 *data, size_t len)
{
	factory_instance_t *fi = NULL;

	/* Extract instance_id from submessage (first 32 bytes).
	 * Don't strip it — handlers that use nonce_bundle_deserialize
	 * expect the full payload including instance_id. */
	if (len >= 32 && submsg_id != SS_SUBMSG_FACTORY_PROPOSE
	    && submsg_id != SS_SUBMSG_ROTATE_PROPOSE
	    && submsg_id != SS_SUBMSG_REVOKE
	    && submsg_id != SS_SUBMSG_REVOKE_ACK
	    && submsg_id != SS_SUBMSG_CLOSE_PROPOSE) {
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

			fi = ss_factory_new(&ss_state, nb->instance_id);
			if (!fi) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "Failed to create factory");
				free(nb);
				break;
			}
			fi->is_lsp = false;
			fi->n_clients = nb->n_participants > 1
				? nb->n_participants - 1 : 0;
			fi->funding_amount_sats = propose_funding_sats;
			fi->creation_block = ss_state.current_blockheight;
			fi->expiry_block = ss_state.current_blockheight + 4320 + 432;
			fi->n_tree_nodes = nb->n_nodes > 0 ? nb->n_nodes : 2;
			fi->early_warning_time = compute_early_warning_time(
				fi->n_clients);

			/* Store LSP peer_id as node_id */
			if (strlen(peer_id) == 66) {
				for (int j = 0; j < 33; j++) {
					unsigned int b;
					sscanf(peer_id + j*2, "%02x", &b);
					fi->lsp_node_id[j] = (uint8_t)b;
				}
			}

			/* Store LSP factory pubkey (slot 0) for
			 * tree rebuild after restart */
			if (nb->n_participants > 0 && nb->pubkeys[0][0] != 0) {
				fi->clients[0].has_factory_pubkey = true;
				memcpy(fi->clients[0].factory_pubkey,
				       nb->pubkeys[0], 33);
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
			if (nb->n_participants <= 2)
				factory_set_arity(factory, FACTORY_ARITY_1);
			else
				factory_set_arity(factory, FACTORY_ARITY_2);

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
						nonce_bundle_t psig_nb;
						memset(&psig_nb, 0, sizeof(psig_nb));
						memcpy(psig_nb.instance_id, fi->instance_id, 32);
						psig_nb.n_participants = nb->n_participants;
						psig_nb.n_nodes = factory->n_nodes;
						psig_nb.n_entries = 0;

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
								psig_nb.entries[psig_nb.n_entries].pubnonce,
								&psig);
							psig_nb.entries[psig_nb.n_entries].node_idx = ni;
							psig_nb.entries[psig_nb.n_entries].signer_slot = slot;
							psig_nb.n_entries++;
						}

						uint8_t pbuf[MAX_WIRE_BUF];
						size_t plen = nonce_bundle_serialize(
							&psig_nb, pbuf, sizeof(pbuf));
						send_factory_msg(cmd, peer_id,
							SS_SUBMSG_PSIG_BUNDLE,
							pbuf, plen);

						plugin_log(plugin_handle, LOG_INFORM,
							   "Client: sent PSIG_BUNDLE "
							   "(%zu psigs)", psig_nb.n_entries);
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
						factory_set_arity(tmp_f,
							nt <= 2 ? FACTORY_ARITY_1
								: FACTORY_ARITY_2);
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
							fi->ceremony = CEREMONY_FAILED;
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
							fi->ceremony = CEREMONY_FAILED;
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
							n_total <= 2 ? FACTORY_ARITY_1
								     : FACTORY_ARITY_2);
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
					factory_set_arity(new_f,
						anb->n_participants <= 2
						? FACTORY_ARITY_1 : FACTORY_ARITY_2);
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
					for (size_t ci = 0; ci < fi->n_clients; ci++) {
						char nid[67];
						for (int j = 0; j < 33; j++)
							sprintf(nid + j*2, "%02x",
								fi->clients[ci].node_id[j]);
						nid[66] = '\0';
						send_factory_msg(cmd, nid,
							SS_SUBMSG_FACTORY_READY,
							fi->instance_id, 32);
					}
					plugin_log(plugin_handle, LOG_INFORM,
						   "LSP: sent FACTORY_READY (no dist TX)");
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
			fi->ceremony = CEREMONY_COMPLETE;
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

			/* Send DIST_NONCE */
			nonce_bundle_t nresp;
			memset(&nresp, 0, sizeof(nresp));
			memcpy(nresp.instance_id, fi->instance_id, 32);
			nresp.n_participants = 1 + fi->n_clients;
			nresp.n_nodes = 1;
			nresp.n_entries = 1;
			nresp.entries[0].node_idx = dist_idx;
			nresp.entries[0].signer_slot = our_idx;
			musig_pubnonce_serialize(ctx,
				nresp.entries[0].pubnonce, &pub);

			uint8_t nbuf[MAX_WIRE_BUF];
			size_t nlen = nonce_bundle_serialize(&nresp,
				nbuf, sizeof(nbuf));
			send_factory_msg(cmd, peer_id,
				SS_SUBMSG_DIST_NONCE, nbuf, nlen);

			/* Finalize standalone session with dist sighash */
			if (musig_session_finalize_nonces(ctx, dsess,
				f->dist_sighash, NULL, NULL)) {
				secp256k1_keypair kp;
				if (!secp256k1_keypair_create(ctx, &kp, our_sec))
					break;
				secp256k1_musig_partial_sig psig;
				if (musig_create_partial_sig(ctx, &psig, sec,
					&kp, dsess)) {

					nonce_bundle_t presp;
					memset(&presp, 0, sizeof(presp));
					memcpy(presp.instance_id, fi->instance_id, 32);
					presp.n_participants = nresp.n_participants;
					presp.n_nodes = 1;
					presp.n_entries = 1;
					presp.entries[0].node_idx = dist_idx;
					presp.entries[0].signer_slot = our_idx;
					musig_partial_sig_serialize(ctx,
						presp.entries[0].pubnonce, &psig);

					uint8_t pbuf[MAX_WIRE_BUF];
					size_t plen = nonce_bundle_serialize(
						&presp, pbuf, sizeof(pbuf));
					send_factory_msg(cmd, peer_id,
						SS_SUBMSG_DIST_PSIG, pbuf, plen);

					plugin_log(plugin_handle, LOG_INFORM,
						   "Client: sent DIST_NONCE + DIST_PSIG");
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
				else if (fi->n_clients == 1)
					fi->clients[0].nonce_received = true;
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

			/* All client PSIGs received. Create LSP's own. */
			bool lsp_signed = false;
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
				secp256k1_musig_partial_sig lsp_psig;
				if (musig_create_partial_sig(global_secp_ctx,
					&lsp_psig, sn, &lsp_kp, dsess)) {
					lsp_signed = true;
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

				/* Store signed dist TX for timeout fallback.
				 * After expiry, broadcast this to give clients
				 * their funds without LSP cooperation. */
				if (f->dist_unsigned_tx.data &&
				    f->dist_unsigned_tx.len > 0) {
					free(fi->dist_signed_tx);
					fi->dist_signed_tx = malloc(
						f->dist_unsigned_tx.len);
					if (fi->dist_signed_tx) {
						memcpy(fi->dist_signed_tx,
						       f->dist_unsigned_tx.data,
						       f->dist_unsigned_tx.len);
						fi->dist_signed_tx_len =
							f->dist_unsigned_tx.len;
						/* Phase 2b: precompute the
						 * coop-close txid so the
						 * classifier can match a
						 * published dist TX later. */
						ss_compute_dist_signed_txid(fi);
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
				for (size_t ci = 0; ci < fi->n_clients; ci++) {
					char nid[67];
					for (int j = 0; j < 33; j++)
						sprintf(nid + j*2, "%02x",
							fi->clients[ci].node_id[j]);
					nid[66] = '\0';
					send_factory_msg(cmd, nid,
						SS_SUBMSG_FACTORY_READY,
						fi->instance_id, 32);
				}
				plugin_log(plugin_handle, LOG_INFORM,
					   "LSP: sent FACTORY_READY to %zu "
					   "clients — call factory-open-channels",
					   fi->n_clients);
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

			nonce_bundle_t nb;
			if (!nonce_bundle_deserialize(&nb, data + 8, len - 8)) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "Bad ROTATE_PROPOSE nonce bundle");
				break;
			}

			if (!fi) {
				fi = ss_factory_find(&ss_state, nb.instance_id);
			}
			if (!fi || !fi->lib_factory) {
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "No factory for rotation");
				break;
			}

			factory_t *factory = (factory_t *)fi->lib_factory;
			secp256k1_context *ctx = global_secp_ctx;

			/* Phase 2b: snapshot current epoch's kickoff witness
			 * sig BEFORE advancing. Used later to classify a
			 * spending TX as breach vs normal-exit. */
			ss_snapshot_current_epoch_kickoff_sig(fi);

			/* Advance our DW counter to match */
			dw_counter_advance(&factory->counter);
			fi->epoch = new_epoch;

			/* Rebuild node transactions */
			for (size_t ni = 0; ni < factory->n_nodes; ni++)
				factory_rebuild_node_tx(factory, ni);

			/* Re-init signing sessions */
			factory_sessions_init(factory);

			/* Set LSP nonces on sessions */
			for (size_t e = 0; e < nb.n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				musig_pubnonce_parse(ctx, &pn,
					nb.entries[e].pubnonce);
				factory_session_set_nonce(factory,
					nb.entries[e].node_idx,
					nb.entries[e].signer_slot, &pn);
			}

			/* Generate our nonces */
			int our_idx = fi->our_participant_idx;
			unsigned char our_sec[32];
			derive_factory_seckey(our_sec, fi->instance_id, our_idx);

			size_t our_count = factory_count_nodes_for_participant(
				factory, our_idx);

			secp256k1_pubkey our_pub;
			if (!secp256k1_ec_pubkey_create(ctx, &our_pub, our_sec))
				break;

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

			nonce_bundle_t resp;
			memset(&resp, 0, sizeof(resp));
			memcpy(resp.instance_id, fi->instance_id, 32);
			resp.n_participants = nb.n_participants;
			resp.n_nodes = factory->n_nodes;
			resp.n_entries = 0;

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
					resp.entries[resp.n_entries].pubnonce,
					&pub);
				resp.entries[resp.n_entries].node_idx = ni;
				resp.entries[resp.n_entries].signer_slot = slot;
				resp.n_entries++;
			}

			/* Send ROTATE_NONCE */
			uint8_t rbuf[MAX_WIRE_BUF];
			size_t rlen = nonce_bundle_serialize(&resp,
				rbuf, sizeof(rbuf));
			send_factory_msg(cmd, peer_id,
					 SS_SUBMSG_ROTATE_NONCE,
					 rbuf, rlen);

			/* Finalize and create partial sigs */
			if (!factory_sessions_finalize(factory)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Client: rotate finalize failed");
				break;
			}

			secp256k1_keypair kp;
			if (!secp256k1_keypair_create(ctx, &kp, our_sec)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "Client: rotate keypair failed");
				break;
			}

			nonce_bundle_t psig_nb;
			memset(&psig_nb, 0, sizeof(psig_nb));
			memcpy(psig_nb.instance_id, fi->instance_id, 32);
			psig_nb.n_participants = nb.n_participants;
			psig_nb.n_nodes = factory->n_nodes;
			psig_nb.n_entries = 0;

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
					psig_nb.entries[psig_nb.n_entries].pubnonce,
					&psig);
				psig_nb.entries[psig_nb.n_entries].node_idx = ni;
				psig_nb.entries[psig_nb.n_entries].signer_slot = slot;
				psig_nb.n_entries++;
			}

			/* Send ROTATE_PSIG */
			uint8_t pbuf[MAX_WIRE_BUF];
			size_t plen = nonce_bundle_serialize(&psig_nb,
				pbuf, sizeof(pbuf));
			send_factory_msg(cmd, peer_id,
					 SS_SUBMSG_ROTATE_PSIG,
					 pbuf, plen);

			fi->ceremony = CEREMONY_ROTATING;
			plugin_log(plugin_handle, LOG_INFORM,
				   "Client: sent ROTATE_NONCE + ROTATE_PSIG "
				   "(%zu psigs)", psig_nb.n_entries);
		}
		break;

	case SS_SUBMSG_ROTATE_NONCE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "ROTATE_NONCE from %s (len=%zu)",
			   peer_id, len);
		/* LSP side: client sent rotation nonces */
		if (fi && fi->is_lsp) {
			nonce_bundle_t cnb;
			if (!nonce_bundle_deserialize(&cnb, data, len))
				break;
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) break;
			secp256k1_context *ctx = global_secp_ctx;

			size_t nonces_set = 0;
			for (size_t e = 0; e < cnb.n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				if (!musig_pubnonce_parse(ctx, &pn,
					cnb.entries[e].pubnonce))
					continue;
				if (!factory_session_set_nonce(f,
					cnb.entries[e].node_idx,
					cnb.entries[e].signer_slot, &pn))
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
						break;
					}
				}
			}

			/* Cache client nonces for ALL_NONCES round */
			if (fi->cached_nonces && fi->n_cached_nonces + cnb.n_entries
			    <= fi->cached_nonces_cap) {
				nonce_entry_t *cache =
					(nonce_entry_t *)fi->cached_nonces;
				memcpy(cache + fi->n_cached_nonces,
				       cnb.entries,
				       cnb.n_entries * sizeof(nonce_entry_t));
				fi->n_cached_nonces += cnb.n_entries;
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "LSP: rotate nonces set %zu/%zu "
				   "(cached: %zu total)",
				   nonces_set, cnb.n_entries,
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
					/* Reset nonce tracking for PSIG round */
					ss_factory_reset_ceremony(fi);
				}
			}
		}
		break;

	case SS_SUBMSG_ROTATE_PSIG:
		plugin_log(plugin_handle, LOG_INFORM,
			   "ROTATE_PSIG from %s (len=%zu)",
			   peer_id, len);
		/* LSP side: client sent rotation partial sigs */
		if (fi && fi->is_lsp) {
			nonce_bundle_t pnb;
			if (!nonce_bundle_deserialize(&pnb, data, len))
				break;
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) break;

			/* Set client psigs */
			size_t psigs_set = 0;
			for (size_t e = 0; e < pnb.n_entries; e++) {
				secp256k1_musig_partial_sig ps;
				if (!musig_partial_sig_parse(global_secp_ctx,
					&ps, pnb.entries[e].pubnonce))
					continue;
				if (!factory_session_set_partial_sig(f,
					pnb.entries[e].node_idx,
					pnb.entries[e].signer_slot, &ps))
					continue;
				psigs_set++;
			}

			plugin_log(plugin_handle, LOG_INFORM,
				   "LSP: rotate client psigs set %zu/%zu",
				   psigs_set, pnb.n_entries);

			/* Create LSP's own psigs */
			secp256k1_keypair lsp_kp;
			if (!secp256k1_keypair_create(global_secp_ctx,
				&lsp_kp, fi->our_seckey)) {
				plugin_log(plugin_handle, LOG_BROKEN,
					   "LSP: rotate keypair failed");
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
						&rlsp_pk, rlsp_sk))
						break;

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
		}
		break;

	case SS_SUBMSG_ROTATE_COMPLETE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "ROTATE_COMPLETE from %s (len=%zu)",
			   peer_id, len);
		if (fi) {
			fi->ceremony = CEREMONY_ROTATE_COMPLETE;
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
		/* fi is NULL (payload starts with output count, not instance_id) */
		if (!fi) {
			for (size_t i = 0; i < ss_state.n_factories; i++) {
				if (!ss_state.factories[i]->is_lsp) {
					fi = ss_state.factories[i];
					break;
				}
			}
		}
		if (fi && len >= 4) {
			factory_t *factory = (factory_t *)fi->lib_factory;
			if (!factory) break;
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

			/* Parse LSP nonces from remainder */
			size_t hdr_consumed = (size_t)(p - data);
			nonce_bundle_t cnb;
			if (hdr_consumed < len &&
			    nonce_bundle_deserialize(&cnb,
				p, len - hdr_consumed)) {
				/* Re-init just node 0 session for close signing */
				factory_session_init_node(factory, 0);

				for (size_t e = 0; e < cnb.n_entries; e++) {
					secp256k1_musig_pubnonce pn;
					musig_pubnonce_parse(ctx, &pn,
						cnb.entries[e].pubnonce);
					factory_session_set_nonce(factory,
						cnb.entries[e].node_idx,
						cnb.entries[e].signer_slot,
						&pn);
				}
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

			/* Send CLOSE_NONCE */
			nonce_bundle_t nresp;
			memset(&nresp, 0, sizeof(nresp));
			memcpy(nresp.instance_id, fi->instance_id, 32);
			nresp.n_participants = 2;
			nresp.n_nodes = 1;
			nresp.n_entries = 1;
			nresp.entries[0].node_idx = 0;
			nresp.entries[0].signer_slot = our_idx;
			musig_pubnonce_serialize(ctx,
				nresp.entries[0].pubnonce, &pub);

			uint8_t nbuf[MAX_WIRE_BUF];
			size_t nlen = nonce_bundle_serialize(&nresp,
				nbuf, sizeof(nbuf));
			send_factory_msg(cmd, peer_id,
					 SS_SUBMSG_CLOSE_NONCE,
					 nbuf, nlen);

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

				nonce_bundle_t presp;
				memset(&presp, 0, sizeof(presp));
				memcpy(presp.instance_id, fi->instance_id, 32);
				presp.n_participants = 2;
				presp.n_nodes = 1;
				presp.n_entries = 1;
				presp.entries[0].node_idx = 0;
				presp.entries[0].signer_slot = our_idx;
				musig_partial_sig_serialize(ctx,
					presp.entries[0].pubnonce, &psig);

				uint8_t pbuf[MAX_WIRE_BUF];
				size_t plen = nonce_bundle_serialize(&presp,
					pbuf, sizeof(pbuf));
				send_factory_msg(cmd, peer_id,
					SS_SUBMSG_CLOSE_PSIG,
					pbuf, plen);

				plugin_log(plugin_handle, LOG_INFORM,
					   "Client: sent CLOSE_NONCE + CLOSE_PSIG");
			}

			tx_buf_free(&close_tx);
			fi->lifecycle = FACTORY_LIFECYCLE_DYING;
		}
		break;

	case SS_SUBMSG_CLOSE_NONCE:
		plugin_log(plugin_handle, LOG_INFORM,
			   "CLOSE_NONCE from %s (len=%zu)",
			   peer_id, len);
		/* LSP side: client sent close nonces */
		if (fi && fi->is_lsp) {
			nonce_bundle_t cnb;
			if (!nonce_bundle_deserialize(&cnb, data, len))
				break;
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) break;

			for (size_t e = 0; e < cnb.n_entries; e++) {
				secp256k1_musig_pubnonce pn;
				if (!musig_pubnonce_parse(global_secp_ctx, &pn,
					cnb.entries[e].pubnonce))
					continue;
				factory_session_set_nonce(f,
					cnb.entries[e].node_idx,
					cnb.entries[e].signer_slot, &pn);
			}

			/* Finalize just node 0 (close tx) */
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
		/* LSP side: client sent close partial sig */
		if (fi && fi->is_lsp) {
			nonce_bundle_t pnb;
			if (!nonce_bundle_deserialize(&pnb, data, len))
				break;
			factory_t *f = (factory_t *)fi->lib_factory;
			if (!f) break;

			for (size_t e = 0; e < pnb.n_entries; e++) {
				secp256k1_musig_partial_sig ps;
				if (!musig_partial_sig_parse(global_secp_ctx,
					&ps, pnb.entries[e].pubnonce))
					continue;
				factory_session_set_partial_sig(f,
					pnb.entries[e].node_idx,
					pnb.entries[e].signer_slot, &ps);
			}

			/* Create LSP's own partial sig */
			secp256k1_keypair lsp_kp;
			if (!secp256k1_keypair_create(global_secp_ctx,
				&lsp_kp, fi->our_seckey))
				break;

			musig_nonce_pool_t *lsp_pool =
				(musig_nonce_pool_t *)fi->nonce_pool;
			if (lsp_pool && fi->n_secnonces > 0) {
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

	/* Key turnover: LSP acknowledges departure */
	case SS_SUBMSG_TURNOVER_ACK:
		plugin_log(plugin_handle, LOG_INFORM,
			   "TURNOVER_ACK from %s — departure confirmed",
			   peer_id);
		break;

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
			   "htlc_accepted: rejecting HTLC cltv_expiry=%u "
			   "(need >= %u + %u + 1 = %u)",
			   cltv_expiry, ss_state.current_blockheight,
			   max_early_warning,
			   ss_state.current_blockheight + max_early_warning + 1);
		struct json_stream *js = jsonrpc_stream_success(cmd);
		json_add_string(js, "result", "fail");
		json_add_u32(js, "failure_code", 0x1000 | 14);
		return command_finished(cmd, js);
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
	if (!param(cmd, buf, params,
		   p_req("funding_sats", param_u64, &funding_sats),
		   p_req("clients", param_array, &clients_tok),
		   p_opt("allocations", param_array, &allocations_tok),
		   NULL))
		return command_param_failed();

	/* Generate random instance_id */
	for (int i = 0; i < 32; i++)
		instance_id[i] = (uint8_t)(random() & 0xFF);

	fi = ss_factory_new(&ss_state, instance_id);
	if (!fi)
		return command_fail(cmd, LIGHTNINGD,
				    "Too many active factories");

	fi->is_lsp = true;
	fi->lifecycle = FACTORY_LIFECYCLE_INIT;
	fi->ceremony = CEREMONY_IDLE;

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
	 * split fallback is used downstream. */
	fi->n_allocations = 0;
	if (allocations_tok) {
		const jsmntok_t *at;
		size_t ai;
		size_t alloc_count = 0;
		uint64_t alloc_sum = 0;
		json_for_each_arr(ai, at, allocations_tok) {
			if (alloc_count >= fi->n_clients)
				break;
			u64 v;
			if (!json_to_u64(buf, at, &v))
				return command_fail(cmd, LIGHTNINGD,
					"allocations[%zu] not a u64", ai);
			fi->clients[alloc_count].allocation_sats = v;
			alloc_sum += v;
			alloc_count++;
		}
		if (alloc_count != fi->n_clients)
			return command_fail(cmd, LIGHTNINGD,
				"allocations length (%zu) != clients length (%zu)",
				alloc_count, fi->n_clients);
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

	/* Initialize the factory via libsuperscalar */
	secp_ctx = global_secp_ctx;

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

		/* Set arity: 1 client/leaf for 2 participants, 2 for more */
		if (fi->n_clients <= 1) {
			factory_set_arity(factory, FACTORY_ARITY_1);
		} else {
			factory_set_arity(factory, FACTORY_ARITY_2);
		}

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
				    *funding_sats, synth_spk, 34);

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
			uint64_t total = *funding_sats;
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
					uint64_t leaf_total = ln->input_amount;
					amts[n_clients_on_leaf] = leaf_total > client_sum
						? leaf_total - client_sum : 546;

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
		fi->funding_amount_sats = *funding_sats;
		fi->creation_block = ss_state.current_blockheight;
		fi->expiry_block = factory->cltv_timeout > 0
			? factory->cltv_timeout
			: ss_state.current_blockheight + 4320; /* ~30 days */

		/* Compute HTLC safety parameter from DW tree depth.
		 * This is the minimum time needed to force-close the
		 * factory before an HTLC times out. */
		fi->early_warning_time = compute_early_warning_time(
			fi->n_clients);

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

				send_factory_msg(cmd, client_hex,
					SS_SUBMSG_FACTORY_PROPOSE,
					cbuf, blen + 12 + extra);
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
			"unknown");
		if (fi->closed_externally_at_block > 0)
			json_add_u32(js, "closed_externally_at_block",
				     fi->closed_externally_at_block);

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
						? "replaced" : "unknown");
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
	factory_session_set_nonce(factory, 0, 0, &pubnonce);

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

	/* Append nonce bundle */
	nonce_bundle_t nb;
	memset(&nb, 0, sizeof(nb));
	memcpy(nb.instance_id, fi->instance_id, 32);
	nb.n_participants = n_participants;
	nb.n_nodes = 1;
	nb.n_entries = 1;
	nb.entries[0].node_idx = 0;
	nb.entries[0].signer_slot = 0;
	musig_pubnonce_serialize(ctx, nb.entries[0].pubnonce, &pubnonce);

	for (size_t pk = 0; pk < n_participants && pk < MAX_PARTICIPANTS; pk++) {
		unsigned char sk2[32];
		derive_factory_seckey(sk2, fi->instance_id, (int)pk);
		secp256k1_pubkey ppk;
		if (!secp256k1_ec_pubkey_create(ctx, &ppk, sk2))
			continue;
		size_t pklen = 33;
		secp256k1_ec_pubkey_serialize(ctx, nb.pubkeys[pk], &pklen,
			&ppk, SECP256K1_EC_COMPRESSED);
	}

	uint8_t nbuf[MAX_WIRE_BUF];
	size_t nlen = nonce_bundle_serialize(&nb, nbuf, sizeof(nbuf));
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

	/* Build nonce bundle for rotation */
	nonce_bundle_t nb;
	memset(&nb, 0, sizeof(nb));
	memcpy(nb.instance_id, fi->instance_id, 32);
	nb.n_participants = n_participants;
	nb.n_nodes = factory->n_nodes;
	nb.n_entries = 0;

	for (size_t pk = 0; pk < n_participants && pk < MAX_PARTICIPANTS; pk++) {
		size_t pklen = 33;
		secp256k1_ec_pubkey_serialize(ctx,
			nb.pubkeys[pk], &pklen,
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
			nb.entries[nb.n_entries].pubnonce, &pubnonce);
		nb.entries[nb.n_entries].node_idx = ni;
		nb.entries[nb.n_entries].signer_slot = slot;
		nb.n_entries++;
	}

	/* Cache LSP rotation nonces for ALL_NONCES round (3+ party) */
	if (fi->cached_nonces) free(fi->cached_nonces);
	fi->cached_nonces_cap = MAX_NONCE_ENTRIES;
	fi->cached_nonces = calloc(fi->cached_nonces_cap,
		sizeof(nonce_entry_t));
	fi->n_cached_nonces = 0;
	if (fi->cached_nonces && nb.n_entries <= fi->cached_nonces_cap) {
		memcpy(fi->cached_nonces, nb.entries,
		       nb.n_entries * sizeof(nonce_entry_t));
		fi->n_cached_nonces = nb.n_entries;
	}

	/* Serialize and send ROTATE_PROPOSE to all clients.
	 * Payload: [4 bytes: old_epoch] [4 bytes: new_epoch] + nonce_bundle */
	uint8_t nbuf[MAX_WIRE_BUF];
	size_t nlen = nonce_bundle_serialize(&nb, nbuf, sizeof(nbuf));

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
 * Phase 3c: penalty pathway + fee bumping.
 *
 * When the classifier fires CLOSED_BREACHED, the broadcast sites in
 * breach_utxo_checked have already sent a burn TX. We record that
 * broadcast as a pending_penalty_t and then let the per-block
 * scheduler (ss_penalty_scheduler_tick) re-evaluate it every block:
 *   - if unconfirmed and the scheduled feerate has risen ≥25%, RBF
 *   - if <6 blocks from the CSV deadline, bump every block (urgent)
 *   - if confirmed, stop rebroadcasting and set SIGNAL_PENALTY_CONFIRMED
 *   - if CSV deadline passed without confirm, mark PENALTY_STATE_REPLACED
 *     (we lost the race; counterparty can claim)
 *
 * Fee math is delegated to upstream SuperScalar's htlc_fee_bump.c
 * (linked in via the slim extraction list). We do NOT reimplement the
 * LND-style linear-fee function — see feedback_reuse_superscalar_upstream.
 *
 * Reorg resilience: if a previously-confirmed penalty txid disappears
 * from the chain (verified via gettxout), we reset confirmed_block=0
 * and kick the scheduler to rebroadcast.
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
}

/* Turn a pending_penalty_t into an htlc_fee_bump_t so we can ask
 * upstream's fee scheduler "should we bump now?". Recomputed every
 * tick from persisted state — we don't hold the fb_t across calls
 * because htlc_fee_bump is a pure-function API. */
static void ss_penalty_to_fb(const pending_penalty_t *pp,
			     htlc_fee_bump_t *fb)
{
	memset(fb, 0, sizeof(*fb));
	/* Init via the library's own initialiser. budget_pct=50 matches the
	 * HTLC_FEE_BUMP_DEFAULT_BUDGET_PCT — half of the L-stock value is
	 * the cap on our fee spend. tx_vsize is what we used at build
	 * time. start_feerate seeded at 1000 sat/kvB (1 sat/vB); the
	 * scheduler will escalate from there up to the budget cap as the
	 * CSV deadline approaches. */
	htlc_fee_bump_init(fb,
			   pp->first_broadcast_block,
			   pp->csv_unlock_block,
			   pp->lstock_sats,
			   HTLC_FEE_BUMP_DEFAULT_BUDGET_PCT,
			   pp->tx_vsize ? pp->tx_vsize : LSTOCK_BURN_VSIZE_DEFAULT,
			   1000);
	fb->last_feerate = pp->last_feerate;
	fb->last_bump_block = pp->last_broadcast_block;
	if (pp->confirmed_block) {
		fb->confirmed = 1;
		fb->confirm_block = pp->confirmed_block;
	}
}

/* Per-block scheduler. Called from handle_block_added for each factory
 * with pending penalties. Walks every entry and:
 *   - skips confirmed + replaced entries
 *   - if should_bump per upstream's fee scheduler, triggers a (logical)
 *     rebroadcast. The actual tx bytes come from re-running
 *     factory_build_burn_tx for the epoch/leaf. For v1, we just LOG the
 *     intent; the next commit will wire the actual rebroadcast. That
 *     keeps this PR's surface area narrow — algorithm + persistence
 *     first, broadcast integration second.
 *
 * Returns the number of entries that would have been bumped. */
static int ss_penalty_scheduler_tick(struct command *cmd,
				     factory_instance_t *fi,
				     uint32_t current_block)
{
	int bumps = 0;
	for (size_t i = 0; i < fi->n_pending_penalties; i++) {
		pending_penalty_t *pp = &fi->pending_penalties[i];
		if (pp->state == PENALTY_STATE_CONFIRMED
		    || pp->state == PENALTY_STATE_REPLACED)
			continue;

		htlc_fee_bump_t fb;
		ss_penalty_to_fb(pp, &fb);

		if (htlc_fee_bump_is_expired(&fb, current_block)) {
			if (pp->state != PENALTY_STATE_REPLACED) {
				pp->state = PENALTY_STATE_REPLACED;
				/* LOG_UNUSUAL not LOG_BROKEN: an adversarial
				 * outcome (we lost the race), not a plugin
				 * internal bug. pyln-testing treats BROKEN as
				 * a fatal teardown error. */
				plugin_log(plugin_handle, LOG_UNUSUAL,
					   "PENALTY EXPIRED: epoch=%u leaf=%d "
					   "CSV at block %u passed without "
					   "our burn confirming. Counterparty "
					   "can now claim the revoked output.",
					   pp->epoch, pp->leaf_index,
					   pp->csv_unlock_block);
			}
			continue;
		}

		if (!htlc_fee_bump_should_bump(&fb, current_block))
			continue;

		uint64_t scheduled_feerate =
			htlc_fee_bump_calc_feerate(&fb, current_block);
		int urgent = htlc_fee_bump_is_urgent(&fb, current_block);
		uint32_t remaining =
			htlc_fee_bump_blocks_remaining(&fb, current_block);

		plugin_log(plugin_handle, LOG_INFORM,
			   "penalty_scheduler: bump epoch=%u leaf=%d "
			   "urgent=%d blocks_remaining=%u feerate=%"PRIu64
			   " sat/kvB (last %"PRIu64" sat/kvB) — "
			   "rebroadcast pending",
			   pp->epoch, pp->leaf_index, urgent, remaining,
			   scheduled_feerate, pp->last_feerate);

		/* Rebroadcast: re-run factory_build_burn_tx for this
		 * (epoch, leaf_index), broadcast via ss_broadcast_factory_tx,
		 * update pp->last_feerate + last_broadcast_block. The
		 * function is idempotent from bitcoind's perspective — a
		 * second sendrawtransaction of the same burn returns
		 * "already known" or "already in mempool/chain", which the
		 * broadcast-reply classifier handles cleanly. */
		factory_t *f = (factory_t *)fi->lib_factory;
		if (f && pp->leaf_index >= 0
		    && (size_t)pp->leaf_index < f->n_nodes) {
			factory_node_t *leaf = &f->nodes[pp->leaf_index];
			if (leaf->n_outputs > 0) {
				uint32_t lstock_vout =
					(uint32_t)(leaf->n_outputs - 1);
				uint64_t lstock_amt =
					leaf->outputs[lstock_vout].amount_sats;

				tx_buf_t burn_tx;
				tx_buf_init(&burn_tx, 256);
				if (factory_build_burn_tx(f, &burn_tx,
							  leaf->txid,
							  lstock_vout,
							  lstock_amt,
							  pp->epoch)) {
					char *burn_hex = tal_arr(cmd, char,
						burn_tx.len * 2 + 1);
					for (size_t h = 0; h < burn_tx.len; h++)
						sprintf(burn_hex + h*2, "%02x",
							burn_tx.data[h]);
					ss_broadcast_factory_tx(cmd, fi,
								burn_hex,
								FACTORY_TX_BURN);
					pp->last_feerate = scheduled_feerate;
					pp->last_broadcast_block = current_block;
					bumps++;
				}
				tx_buf_free(&burn_tx);
			}
		}
	}
	if (bumps > 0)
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
					   "(confirmed_at=%u, current=%u). "
					   "Phase 4d2 will broadcast.",
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
			transitions++;
			dirty = true;
		}
	}

	if (dirty)
		ss_save_factory(cmd, fi);
	return transitions;
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
				if (factory_build_burn_tx(f, &burn_tx,
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
	const jsmntok_t *block_tok = json_get_member(buf, params, "block");
	if (block_tok) {
		const jsmntok_t *height_tok = json_get_member(buf, block_tok,
							       "height");
		if (height_tok) {
			u32 height;
			json_to_u32(buf, height_tok, &height);
			ss_state.current_blockheight = height;
		}
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
		}

		/* Phase 4d: sweep scheduler tick. Cheap; only walks in-memory
		 * array. */
		if (fi->n_pending_sweeps > 0) {
			ss_sweep_scheduler_tick(cmd, fi,
				ss_state.current_blockheight);
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

	/* Build burn tx for the specified epoch */
	tx_buf_t burn_tx;
	tx_buf_init(&burn_tx, 256);

	if (!factory_build_burn_tx(factory, &burn_tx,
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

	/* Recovery: if we're the LSP and this peer is a factory client
	 * who disconnected mid-ceremony, re-send FACTORY_PROPOSE so the
	 * ceremony can continue without manual intervention. */
	if (!ss_state.is_lsp || strlen(peer_id) != 66)
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
		if (!is_propose && !is_nonces)
			continue;

		for (size_t ci = 0; ci < fi->n_clients; ci++) {
			if (memcmp(fi->clients[ci].node_id, pid, 33) != 0)
				continue;

			if (is_propose && !fi->clients[ci].nonce_received) {
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

	/* Read current amounts from the leaf node */
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

	int rc = factory_set_leaf_amounts(factory, leaf_side,
					  new_amts, n_out);
	free(new_amts);

	if (!rc)
		return command_fail(cmd, LIGHTNINGD,
				    "factory_set_leaf_amounts failed");

	plugin_log(plugin_handle, LOG_INFORM,
		   "Liquidity purchase: moved %"PRIu64" sats from L-stock "
		   "to client %u on leaf %d",
		   *amount_sats, *client_idx, leaf_side);

	/* TODO: trigger leaf re-signing ceremony (MuSig2 over new leaf TX).
	 * For now, just update the tree state — the next rotation will
	 * pick up the new amounts. */

	struct json_stream *js = jsonrpc_stream_success(cmd);
	json_add_string(js, "status", "liquidity_allocated");
	json_add_u64(js, "amount_sats", *amount_sats);
	json_add_u32(js, "leaf_side", leaf_side);
	json_add_u32(js, "client_idx", *client_idx);
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
		return command_fail(cmd, LIGHTNINGD, "Bad client_id (66 hex chars)");

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

	/* Snapshot what we need before we remove fi from ss_state — the
	 * async deldatastore callbacks shouldn't touch freed memory. */
	size_t factory_slot = SIZE_MAX;
	for (size_t i = 0; i < ss_state.n_factories; i++) {
		if (ss_state.factories[i] == fi) {
			factory_slot = i;
			break;
		}
	}

	/* Dispatch deldatastore for each known key under this factory.
	 * Failures are logged but not reported to the caller — the
	 * authoritative action here is the in-memory removal below, and
	 * orphaned datastore entries degrade gracefully on next startup
	 * (ss_load_factories just skips keys whose meta is missing). */
	char iid_hex[65];
	for (int j = 0; j < 32; j++)
		sprintf(iid_hex + j*2, "%02x", fi->instance_id[j]);
	iid_hex[64] = '\0';

	static const char *fixed_subkeys[] = {
		"meta", "channels", "signed_txs", "dist_tx", "breach-index"
	};
	for (size_t k = 0; k < sizeof(fixed_subkeys)/sizeof(fixed_subkeys[0]);
	     k++) {
		struct out_req *req = jsonrpc_request_start(cmd, "deldatastore",
			rpc_done, rpc_done /* treat errors as informational */,
			fi);
		json_array_start(req->js, "key");
		json_add_string(req->js, NULL, "superscalar");
		json_add_string(req->js, NULL, "factories");
		json_add_string(req->js, NULL, iid_hex);
		json_add_string(req->js, NULL, fixed_subkeys[k]);
		json_array_end(req->js);
		send_outreq(req);
	}
	/* Per-epoch breach keys we know about. */
	for (size_t bi = 0; bi < fi->n_breach_epochs; bi++) {
		char epoch_str[16];
		snprintf(epoch_str, sizeof(epoch_str), "%u",
			 fi->breach_data[bi].epoch);
		struct out_req *req = jsonrpc_request_start(cmd, "deldatastore",
			rpc_done, rpc_done, fi);
		json_array_start(req->js, "key");
		json_add_string(req->js, NULL, "superscalar");
		json_add_string(req->js, NULL, "factories");
		json_add_string(req->js, NULL, iid_hex);
		json_add_string(req->js, NULL, "breach");
		json_add_string(req->js, NULL, epoch_str);
		json_array_end(req->js);
		send_outreq(req);
	}

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
			jsonrpc_set_datastore_binary(cmd,
				"superscalar/factory-index",
				idx_buf, idx_len,
				"create-or-replace", rpc_done, rpc_done,
				NULL);
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
		"unknown");
	return command_finished(cmd, js);
}

/* dev-factory-inject-penalty — test-only hook for Phase 3c.
 * Inserts a pending_penalty_t directly so tests can exercise the
 * fee-bump scheduler, reorg handling, and SIGNAL_PENALTY_CONFIRMED
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

static const struct plugin_command commands[] = {
	{
		"dev-factory-set-signal",
		json_dev_factory_set_signal,
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
		"dev-factory-mark-sweep-confirmed",
		json_dev_factory_mark_sweep_confirmed,
	},
	{
		"factory-create",
		json_factory_create,
	},
	{
		"factory-list",
		json_factory_list,
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
		    NULL);
}
