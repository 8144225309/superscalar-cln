/*
 * factory_policy.c — TLV codec + canonical defaults for ss_factory_policy_t.
 *
 * Step 2 of B1.  Implements:
 *   ss_factory_policy_init_defaults()         — per FACTORY_POLICY_V1 §4
 *   ss_client_signing_prefs_init_defaults()   — conservative joiner prefs
 *   ss_factory_policy_encode_diff()           — TLV-diff-from-defaults encoder
 *   ss_factory_policy_decode()                — TLV decoder (defaults-first)
 *
 * Wire format (per FACTORY_POLICY_V1 §4):
 *   [u16 type][u16 length][value...]
 *   ... repeated ...
 *
 * Multi-byte values are big-endian (matches the rest of the plugin).
 *
 * Diff semantics: encoder writes a TLV only if the field differs from the
 * canonical default.  schema_version is ALWAYS emitted first (per §4.1.1).
 * The decoder begins by setting all fields to defaults, then overwrites
 * each TLV it can decode.  Unknown TLV IDs are skipped silently for
 * forward compatibility.
 */

#include "factory_policy.h"
#include <string.h>

/* ============================================================================
 * Defaults
 * ========================================================================= */

void ss_factory_policy_init_defaults(ss_factory_policy_t *p)
{
	if (!p) return;
	memset(p, 0, sizeof(*p));

	/* §4.1 */
	p->schema_version = SS_FACTORY_POLICY_SCHEMA_VERSION;
	memcpy(p->protocol_id, SS_FACTORY_POLICY_PROTOCOL_ID_DEFAULT,
		strlen(SS_FACTORY_POLICY_PROTOCOL_ID_DEFAULT));

	/* §4.2 Tree shape */
	p->arity_mode              = SS_DEFAULT_ARITY_MODE;
	p->leaf_arity              = 2;
	p->leaf_channel_type       = SS_DEFAULT_LEAF_CHANNEL_TYPE;
	p->ps_subfactory_arity     = 2;
	p->epoch_count             = 16;
	p->n_layers                = 2;
	p->dw_step_blocks          = 144;
	p->static_near_root_layers = 0;

	/* §4.3 Lifecycle */
	p->lifetime_blocks       = 4320;   /* ~30d */
	p->dying_period_blocks   = 288;    /* ~2d */
	p->block_early_count     = 144;    /* ~1d */
	p->confirm_timeout_sec   = 86400;  /* 24h */

	/* §4.4 Economics */
	p->per_client_capacity_sat    = 100000;
	p->lsp_reserve_per_leaf_sat   = 50000;
	p->lsp_initial_balance_pct    = 100;
	p->lsp_fee_sat                = 0;
	p->lsp_fee_ppm                = 0;
	p->join_fee_sat               = 0;
	p->min_capacity_per_join_sat  = 10000;
	/* derived: max_capacity_per_join_sat = per_client_capacity_sat */
	p->max_capacity_per_join_sat  = p->per_client_capacity_sat;

	/* §4.5 Channel options */
	p->allow_bolt12       = true;
	p->allow_amp          = false;
	p->htlc_min_sat       = 1;
	p->htlc_max_sat       = 0;  /* 0 = channel capacity */
	p->allow_blinded_paths = true;

	/* §4.6 HTLC policy */
	p->max_concurrent_htlcs_per_channel = 30;
	p->max_in_flight_msat_per_channel   = 0;  /* 0 = 90% of capacity */
	/* derived from block_early_count: */
	p->min_final_cltv_expiry_delta      = (uint32_t)p->block_early_count + 18;
	p->cltv_expiry_delta_forward        = (uint32_t)p->block_early_count + 40;
	p->max_accepted_htlcs               = 483;

	/* §4.7 Joiner admission */
	p->auto_accept_joiners      = false;
	/* banlist + allowlist already zeroed by memset (n_entries = 0) */
	p->proof_tier_required      = SS_DEFAULT_PROOF_TIER;
	p->auto_finalize_on_dying   = true;
	p->allow_tier_b_rollover    = true;
	/* derived: joiner_admission_window_blocks = lifetime - dying */
	p->joiner_admission_window_blocks = p->lifetime_blocks
		- p->dying_period_blocks;

	/* §4.8 Watchtower policy */
	p->watchtower_mode                      = SS_DEFAULT_WT_MODE;
	p->poison_tx_strategy                   = SS_DEFAULT_POISON_STRATEGY;
	p->breach_response_fee_rate_sat_per_kvb = 1000;
	p->wt_startup_scan_depth_blocks         = 144;
	p->reorg_alarm_depth_blocks             = 2;
	p->reorg_response_strategy              = SS_DEFAULT_REORG_RESPONSE;

	/* §4.9 PS chain policy */
	p->max_advance_count_per_leaf         = 10;
	p->advance_dust_warning_threshold_sat = 1000;
	/* derived: state_replay_defense_window_blocks = lifetime_blocks */
	p->state_replay_defense_window_blocks = p->lifetime_blocks;

	/* §4.10 Fee policy */
	p->fee_rate_strategy        = SS_DEFAULT_FEE_STRATEGY;
	p->min_fee_rate_sat_per_kvb = 1000;

	/* §4.11 Migration policy */
	p->migration_paths_supported = SS_DEFAULT_MIGRATION_PATHS;
	p->allow_splice              = false;
	p->allow_jit_fallback        = true;

	/* §4.12 Routing / forwarding policy */
	p->forward_fee_policy       = SS_DEFAULT_FORWARD_POLICY;
	p->forward_fee_base_msat    = 1000;
	p->forward_fee_ppm          = 1;
	p->lsp_self_routing_allowed = true;

	/* §4.13 Lifecycle commitments */
	p->auto_host_next             = true;
	p->ladder_cadence_blocks      = 4320;
	p->auto_rotate_periodically   = false;
	p->rotation_interval_blocks   = 0;
	p->expected_rotation_blocks   = 0;
}

void ss_client_signing_prefs_init_defaults(ss_client_signing_prefs_t *prefs)
{
	if (!prefs) return;
	memset(prefs, 0, sizeof(*prefs));
	prefs->max_htlc_min_sat                       = 10000;
	prefs->min_htlc_max_sat                       = 100000;
	prefs->min_max_concurrent_htlcs               = 5;
	prefs->min_max_in_flight_msat                 = 1000000;  /* 1k sat */
	prefs->max_min_final_cltv_delta               = 200;
	prefs->max_cltv_delta_forward                 = 200;
	prefs->max_min_capacity_per_join_sat          = 1000000;
	prefs->min_max_capacity_per_join_sat          = 10000;
	prefs->require_strict_proof_tier              = true;
	prefs->max_proof_tier                         = PROOF_TIER_INVOICE;
	prefs->min_rotation_interval_blocks           = 144;
	prefs->require_tier_b_rollover                = false;
	prefs->min_state_replay_defense_window_blocks = 288;
}

/* ============================================================================
 * Big-endian read/write primitives (network byte order — matches plugin)
 * ========================================================================= */

static void put_u16_be(uint8_t *b, uint16_t v) {
	b[0] = (uint8_t)(v >> 8); b[1] = (uint8_t)v;
}
static void put_u32_be(uint8_t *b, uint32_t v) {
	b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16);
	b[2] = (uint8_t)(v >> 8);  b[3] = (uint8_t)v;
}
static void put_u64_be(uint8_t *b, uint64_t v) {
	b[0] = (uint8_t)(v >> 56); b[1] = (uint8_t)(v >> 48);
	b[2] = (uint8_t)(v >> 40); b[3] = (uint8_t)(v >> 32);
	b[4] = (uint8_t)(v >> 24); b[5] = (uint8_t)(v >> 16);
	b[6] = (uint8_t)(v >> 8);  b[7] = (uint8_t)v;
}
static uint16_t get_u16_be(const uint8_t *b) {
	return ((uint16_t)b[0] << 8) | b[1];
}
static uint32_t get_u32_be(const uint8_t *b) {
	return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16)
		| ((uint32_t)b[2] << 8)  | b[3];
}
static uint64_t get_u64_be(const uint8_t *b) {
	return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48)
		| ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32)
		| ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16)
		| ((uint64_t)b[6] << 8)  | b[7];
}

/* ============================================================================
 * Single-TLV encoders.  Each returns 0 if it would overflow buf, else the
 * total bytes written (4 header + value_len).  Caller advances offset.
 * Buffer space invariant: caller passes `cap = total_cap - cur_off`.
 * ========================================================================= */

static size_t emit_tlv_u8(uint8_t *buf, size_t cap, uint16_t tlv, uint8_t v)
{
	if (cap < 5) return 0;
	put_u16_be(buf, tlv);
	put_u16_be(buf + 2, 1);
	buf[4] = v;
	return 5;
}
static size_t emit_tlv_u16(uint8_t *buf, size_t cap, uint16_t tlv, uint16_t v)
{
	if (cap < 6) return 0;
	put_u16_be(buf, tlv);
	put_u16_be(buf + 2, 2);
	put_u16_be(buf + 4, v);
	return 6;
}
static size_t emit_tlv_u32(uint8_t *buf, size_t cap, uint16_t tlv, uint32_t v)
{
	if (cap < 8) return 0;
	put_u16_be(buf, tlv);
	put_u16_be(buf + 2, 4);
	put_u32_be(buf + 4, v);
	return 8;
}
static size_t emit_tlv_u64(uint8_t *buf, size_t cap, uint16_t tlv, uint64_t v)
{
	if (cap < 12) return 0;
	put_u16_be(buf, tlv);
	put_u16_be(buf + 2, 8);
	put_u64_be(buf + 4, v);
	return 12;
}
static size_t emit_tlv_bool(uint8_t *buf, size_t cap, uint16_t tlv, bool v)
{
	return emit_tlv_u8(buf, cap, tlv, v ? 1 : 0);
}
static size_t emit_tlv_bytes(uint8_t *buf, size_t cap, uint16_t tlv,
			      const uint8_t *src, size_t srclen)
{
	if (srclen > 0xFFFF) return 0;
	if (cap < 4 + srclen) return 0;
	put_u16_be(buf, tlv);
	put_u16_be(buf + 2, (uint16_t)srclen);
	memcpy(buf + 4, src, srclen);
	return 4 + srclen;
}
static size_t emit_tlv_pubkey_list(uint8_t *buf, size_t cap, uint16_t tlv,
				    const ss_policy_pubkey_list_t *list)
{
	size_t srclen = (size_t)list->n_entries * SS_POLICY_PUBKEY_LEN;
	if (srclen > 0xFFFF) return 0;
	if (cap < 4 + srclen) return 0;
	put_u16_be(buf, tlv);
	put_u16_be(buf + 2, (uint16_t)srclen);
	memcpy(buf + 4, list->entries, srclen);
	return 4 + srclen;
}

/* Macros for the encoder body — keep the per-field block readable. */
#define EMIT_IF_DIFF(EMIT_CALL) do { \
	size_t _w = (EMIT_CALL); \
	if (_w == 0) return 0; \
	off += _w; \
} while (0)

#define DIFF_U8(field, tlv)  do { \
	if (p->field != d->field) EMIT_IF_DIFF(emit_tlv_u8(buf + off, cap - off, (tlv), p->field)); \
} while (0)
#define DIFF_U16(field, tlv) do { \
	if (p->field != d->field) EMIT_IF_DIFF(emit_tlv_u16(buf + off, cap - off, (tlv), p->field)); \
} while (0)
#define DIFF_U32(field, tlv) do { \
	if (p->field != d->field) EMIT_IF_DIFF(emit_tlv_u32(buf + off, cap - off, (tlv), p->field)); \
} while (0)
#define DIFF_U64(field, tlv) do { \
	if (p->field != d->field) EMIT_IF_DIFF(emit_tlv_u64(buf + off, cap - off, (tlv), p->field)); \
} while (0)
#define DIFF_BOOL(field, tlv) do { \
	if (p->field != d->field) EMIT_IF_DIFF(emit_tlv_bool(buf + off, cap - off, (tlv), p->field)); \
} while (0)
#define DIFF_ENUM(field, tlv) do { \
	if (p->field != d->field) EMIT_IF_DIFF(emit_tlv_u8(buf + off, cap - off, (tlv), (uint8_t)p->field)); \
} while (0)

/* ============================================================================
 * Public encoder — TLV-diff-from-defaults.
 *
 * Writes a TLV for each field whose value differs from `defaults`.
 * schema_version is ALWAYS emitted first.
 *
 * Returns total bytes written, or 0 on buffer overflow.
 * ========================================================================= */

size_t ss_factory_policy_encode_diff(const ss_factory_policy_t *p,
				       const ss_factory_policy_t *defaults,
				       uint8_t *buf, size_t cap)
{
	if (!p || !defaults || !buf) return 0;
	const ss_factory_policy_t *d = defaults;
	size_t off = 0;

	/* §4.1.1 — schema_version is ALWAYS emitted first (per spec) */
	EMIT_IF_DIFF(emit_tlv_u32(buf + off, cap - off,
		SS_POLICY_TLV_SCHEMA_VERSION, p->schema_version));

	/* §4.1.2 protocol_id */
	if (memcmp(p->protocol_id, d->protocol_id, 32) != 0)
		EMIT_IF_DIFF(emit_tlv_bytes(buf + off, cap - off,
			SS_POLICY_TLV_PROTOCOL_ID, p->protocol_id, 32));

	/* §4.2 Tree shape */
	DIFF_ENUM(arity_mode,             SS_POLICY_TLV_ARITY_MODE);
	DIFF_U8  (leaf_arity,             SS_POLICY_TLV_LEAF_ARITY);
	DIFF_ENUM(leaf_channel_type,      SS_POLICY_TLV_LEAF_CHANNEL_TYPE);
	DIFF_U8  (ps_subfactory_arity,    SS_POLICY_TLV_PS_SUBFACTORY_ARITY);
	DIFF_U16 (epoch_count,            SS_POLICY_TLV_EPOCH_COUNT);
	DIFF_U8  (n_layers,               SS_POLICY_TLV_N_LAYERS);
	DIFF_U16 (dw_step_blocks,         SS_POLICY_TLV_DW_STEP_BLOCKS);
	DIFF_U8  (static_near_root_layers, SS_POLICY_TLV_STATIC_NEAR_ROOT_LAYERS);

	/* §4.3 Lifecycle */
	DIFF_U32(lifetime_blocks,      SS_POLICY_TLV_LIFETIME_BLOCKS);
	DIFF_U32(dying_period_blocks,  SS_POLICY_TLV_DYING_PERIOD_BLOCKS);
	DIFF_U16(block_early_count,    SS_POLICY_TLV_BLOCK_EARLY_COUNT);
	DIFF_U32(confirm_timeout_sec,  SS_POLICY_TLV_CONFIRM_TIMEOUT_SEC);

	/* §4.4 Economics */
	DIFF_U64(per_client_capacity_sat,    SS_POLICY_TLV_PER_CLIENT_CAPACITY_SAT);
	DIFF_U64(lsp_reserve_per_leaf_sat,   SS_POLICY_TLV_LSP_RESERVE_PER_LEAF_SAT);
	DIFF_U8 (lsp_initial_balance_pct,    SS_POLICY_TLV_LSP_INITIAL_BALANCE_PCT);
	DIFF_U64(lsp_fee_sat,                SS_POLICY_TLV_LSP_FEE_SAT);
	DIFF_U32(lsp_fee_ppm,                SS_POLICY_TLV_LSP_FEE_PPM);
	DIFF_U64(join_fee_sat,               SS_POLICY_TLV_JOIN_FEE_SAT);
	DIFF_U64(min_capacity_per_join_sat,  SS_POLICY_TLV_MIN_CAPACITY_PER_JOIN_SAT);
	DIFF_U64(max_capacity_per_join_sat,  SS_POLICY_TLV_MAX_CAPACITY_PER_JOIN_SAT);

	/* §4.5 Channel options */
	DIFF_BOOL(allow_bolt12,        SS_POLICY_TLV_ALLOW_BOLT12);
	DIFF_BOOL(allow_amp,           SS_POLICY_TLV_ALLOW_AMP);
	DIFF_U64 (htlc_min_sat,        SS_POLICY_TLV_HTLC_MIN_SAT);
	DIFF_U64 (htlc_max_sat,        SS_POLICY_TLV_HTLC_MAX_SAT);
	DIFF_BOOL(allow_blinded_paths, SS_POLICY_TLV_ALLOW_BLINDED_PATHS);

	/* §4.6 HTLC policy */
	DIFF_U16(max_concurrent_htlcs_per_channel, SS_POLICY_TLV_MAX_CONCURRENT_HTLCS_PER_CHANNEL);
	DIFF_U64(max_in_flight_msat_per_channel,   SS_POLICY_TLV_MAX_IN_FLIGHT_MSAT_PER_CHANNEL);
	DIFF_U32(min_final_cltv_expiry_delta,      SS_POLICY_TLV_MIN_FINAL_CLTV_EXPIRY_DELTA);
	DIFF_U32(cltv_expiry_delta_forward,        SS_POLICY_TLV_CLTV_EXPIRY_DELTA_FORWARD);
	DIFF_U16(max_accepted_htlcs,               SS_POLICY_TLV_MAX_ACCEPTED_HTLCS);

	/* §4.7 Joiner admission */
	DIFF_BOOL(auto_accept_joiners, SS_POLICY_TLV_AUTO_ACCEPT_JOINERS);
	if (p->banlist.n_entries != d->banlist.n_entries
	    || (p->banlist.n_entries > 0
		&& memcmp(p->banlist.entries, d->banlist.entries,
			  (size_t)p->banlist.n_entries * SS_POLICY_PUBKEY_LEN) != 0))
		EMIT_IF_DIFF(emit_tlv_pubkey_list(buf + off, cap - off,
			SS_POLICY_TLV_BANLIST, &p->banlist));
	if (p->allowlist.n_entries != d->allowlist.n_entries
	    || (p->allowlist.n_entries > 0
		&& memcmp(p->allowlist.entries, d->allowlist.entries,
			  (size_t)p->allowlist.n_entries * SS_POLICY_PUBKEY_LEN) != 0))
		EMIT_IF_DIFF(emit_tlv_pubkey_list(buf + off, cap - off,
			SS_POLICY_TLV_ALLOWLIST, &p->allowlist));
	DIFF_ENUM(proof_tier_required,            SS_POLICY_TLV_PROOF_TIER_REQUIRED);
	DIFF_BOOL(auto_finalize_on_dying,          SS_POLICY_TLV_AUTO_FINALIZE_ON_DYING);
	DIFF_BOOL(allow_tier_b_rollover,           SS_POLICY_TLV_ALLOW_TIER_B_ROLLOVER);
	DIFF_U32 (joiner_admission_window_blocks,  SS_POLICY_TLV_JOINER_ADMISSION_WINDOW_BLOCKS);

	/* §4.8 Watchtower policy */
	DIFF_ENUM(watchtower_mode,                       SS_POLICY_TLV_WATCHTOWER_MODE);
	DIFF_ENUM(poison_tx_strategy,                    SS_POLICY_TLV_POISON_TX_STRATEGY);
	DIFF_U64 (breach_response_fee_rate_sat_per_kvb,  SS_POLICY_TLV_BREACH_RESPONSE_FEE_RATE);
	DIFF_U16 (wt_startup_scan_depth_blocks,          SS_POLICY_TLV_WT_STARTUP_SCAN_DEPTH);
	DIFF_U8  (reorg_alarm_depth_blocks,              SS_POLICY_TLV_REORG_ALARM_DEPTH);
	DIFF_ENUM(reorg_response_strategy,               SS_POLICY_TLV_REORG_RESPONSE_STRATEGY);

	/* §4.9 PS chain policy */
	DIFF_U16(max_advance_count_per_leaf,         SS_POLICY_TLV_MAX_ADVANCE_COUNT_PER_LEAF);
	DIFF_U64(advance_dust_warning_threshold_sat, SS_POLICY_TLV_ADVANCE_DUST_WARNING_SAT);
	DIFF_U32(state_replay_defense_window_blocks, SS_POLICY_TLV_STATE_REPLAY_DEFENSE_WINDOW);

	/* §4.10 Fee policy */
	DIFF_ENUM(fee_rate_strategy,         SS_POLICY_TLV_FEE_RATE_STRATEGY);
	DIFF_U64 (min_fee_rate_sat_per_kvb,  SS_POLICY_TLV_MIN_FEE_RATE_SAT_PER_KVB);

	/* §4.11 Migration policy */
	DIFF_U8  (migration_paths_supported, SS_POLICY_TLV_MIGRATION_PATHS_SUPPORTED);
	DIFF_BOOL(allow_splice,              SS_POLICY_TLV_ALLOW_SPLICE);
	DIFF_BOOL(allow_jit_fallback,        SS_POLICY_TLV_ALLOW_JIT_FALLBACK);

	/* §4.12 Routing / forwarding */
	DIFF_ENUM(forward_fee_policy,       SS_POLICY_TLV_FORWARD_FEE_POLICY);
	DIFF_U64 (forward_fee_base_msat,    SS_POLICY_TLV_FORWARD_FEE_BASE_MSAT);
	DIFF_U32 (forward_fee_ppm,          SS_POLICY_TLV_FORWARD_FEE_PPM);
	DIFF_BOOL(lsp_self_routing_allowed, SS_POLICY_TLV_LSP_SELF_ROUTING_ALLOWED);

	/* §4.13 Lifecycle commitments */
	DIFF_BOOL(auto_host_next,            SS_POLICY_TLV_AUTO_HOST_NEXT);
	DIFF_U32 (ladder_cadence_blocks,     SS_POLICY_TLV_LADDER_CADENCE_BLOCKS);
	DIFF_BOOL(auto_rotate_periodically,  SS_POLICY_TLV_AUTO_ROTATE_PERIODICALLY);
	DIFF_U32 (rotation_interval_blocks,  SS_POLICY_TLV_ROTATION_INTERVAL_BLOCKS);
	DIFF_U32 (expected_rotation_blocks,  SS_POLICY_TLV_EXPECTED_ROTATION_BLOCKS);

	return off;
}

#undef DIFF_U8
#undef DIFF_U16
#undef DIFF_U32
#undef DIFF_U64
#undef DIFF_BOOL
#undef DIFF_ENUM
#undef EMIT_IF_DIFF

/* ============================================================================
 * Public decoder — overwrites defaults with whatever TLVs are in buf.
 *
 * Returns 1 on success, 0 if buf is malformed (truncated TLV header / value).
 * Unknown TLV IDs are skipped silently (forward-compat).  Per-field length
 * mismatches are also tolerated (skip with warning at higher layer if you
 * want — we just refuse to write the field).
 * ========================================================================= */

int ss_factory_policy_decode(const uint8_t *buf, size_t len,
			       ss_factory_policy_t *p)
{
	if (!buf || !p) return 0;
	ss_factory_policy_init_defaults(p);

	size_t off = 0;
	while (off + 4 <= len) {
		uint16_t tlv = get_u16_be(buf + off);
		uint16_t vlen = get_u16_be(buf + off + 2);
		off += 4;
		if (off + vlen > len) return 0;  /* truncated value */
		const uint8_t *v = buf + off;

		switch (tlv) {
		/* §4.1 */
		case SS_POLICY_TLV_SCHEMA_VERSION:
			if (vlen == 4) p->schema_version = get_u32_be(v);
			break;
		case SS_POLICY_TLV_PROTOCOL_ID:
			if (vlen == 32) memcpy(p->protocol_id, v, 32);
			break;

		/* §4.2 */
		case SS_POLICY_TLV_ARITY_MODE:
			if (vlen == 1) p->arity_mode = (ss_arity_mode_t)v[0];
			break;
		case SS_POLICY_TLV_LEAF_ARITY:
			if (vlen == 1) p->leaf_arity = v[0]; break;
		case SS_POLICY_TLV_LEAF_CHANNEL_TYPE:
			if (vlen == 1) p->leaf_channel_type = (ss_leaf_channel_type_t)v[0];
			break;
		case SS_POLICY_TLV_PS_SUBFACTORY_ARITY:
			if (vlen == 1) p->ps_subfactory_arity = v[0]; break;
		case SS_POLICY_TLV_EPOCH_COUNT:
			if (vlen == 2) p->epoch_count = get_u16_be(v); break;
		case SS_POLICY_TLV_N_LAYERS:
			if (vlen == 1) p->n_layers = v[0]; break;
		case SS_POLICY_TLV_DW_STEP_BLOCKS:
			if (vlen == 2) p->dw_step_blocks = get_u16_be(v); break;
		case SS_POLICY_TLV_STATIC_NEAR_ROOT_LAYERS:
			if (vlen == 1) p->static_near_root_layers = v[0]; break;

		/* §4.3 */
		case SS_POLICY_TLV_LIFETIME_BLOCKS:
			if (vlen == 4) p->lifetime_blocks = get_u32_be(v); break;
		case SS_POLICY_TLV_DYING_PERIOD_BLOCKS:
			if (vlen == 4) p->dying_period_blocks = get_u32_be(v); break;
		case SS_POLICY_TLV_BLOCK_EARLY_COUNT:
			if (vlen == 2) p->block_early_count = get_u16_be(v); break;
		case SS_POLICY_TLV_CONFIRM_TIMEOUT_SEC:
			if (vlen == 4) p->confirm_timeout_sec = get_u32_be(v); break;

		/* §4.4 */
		case SS_POLICY_TLV_PER_CLIENT_CAPACITY_SAT:
			if (vlen == 8) p->per_client_capacity_sat = get_u64_be(v); break;
		case SS_POLICY_TLV_LSP_RESERVE_PER_LEAF_SAT:
			if (vlen == 8) p->lsp_reserve_per_leaf_sat = get_u64_be(v); break;
		case SS_POLICY_TLV_LSP_INITIAL_BALANCE_PCT:
			if (vlen == 1) p->lsp_initial_balance_pct = v[0]; break;
		case SS_POLICY_TLV_LSP_FEE_SAT:
			if (vlen == 8) p->lsp_fee_sat = get_u64_be(v); break;
		case SS_POLICY_TLV_LSP_FEE_PPM:
			if (vlen == 4) p->lsp_fee_ppm = get_u32_be(v); break;
		case SS_POLICY_TLV_JOIN_FEE_SAT:
			if (vlen == 8) p->join_fee_sat = get_u64_be(v); break;
		case SS_POLICY_TLV_MIN_CAPACITY_PER_JOIN_SAT:
			if (vlen == 8) p->min_capacity_per_join_sat = get_u64_be(v); break;
		case SS_POLICY_TLV_MAX_CAPACITY_PER_JOIN_SAT:
			if (vlen == 8) p->max_capacity_per_join_sat = get_u64_be(v); break;

		/* §4.5 */
		case SS_POLICY_TLV_ALLOW_BOLT12:
			if (vlen == 1) p->allow_bolt12 = (v[0] != 0); break;
		case SS_POLICY_TLV_ALLOW_AMP:
			if (vlen == 1) p->allow_amp = (v[0] != 0); break;
		case SS_POLICY_TLV_HTLC_MIN_SAT:
			if (vlen == 8) p->htlc_min_sat = get_u64_be(v); break;
		case SS_POLICY_TLV_HTLC_MAX_SAT:
			if (vlen == 8) p->htlc_max_sat = get_u64_be(v); break;
		case SS_POLICY_TLV_ALLOW_BLINDED_PATHS:
			if (vlen == 1) p->allow_blinded_paths = (v[0] != 0); break;

		/* §4.6 */
		case SS_POLICY_TLV_MAX_CONCURRENT_HTLCS_PER_CHANNEL:
			if (vlen == 2) p->max_concurrent_htlcs_per_channel = get_u16_be(v); break;
		case SS_POLICY_TLV_MAX_IN_FLIGHT_MSAT_PER_CHANNEL:
			if (vlen == 8) p->max_in_flight_msat_per_channel = get_u64_be(v); break;
		case SS_POLICY_TLV_MIN_FINAL_CLTV_EXPIRY_DELTA:
			if (vlen == 4) p->min_final_cltv_expiry_delta = get_u32_be(v); break;
		case SS_POLICY_TLV_CLTV_EXPIRY_DELTA_FORWARD:
			if (vlen == 4) p->cltv_expiry_delta_forward = get_u32_be(v); break;
		case SS_POLICY_TLV_MAX_ACCEPTED_HTLCS:
			if (vlen == 2) p->max_accepted_htlcs = get_u16_be(v); break;

		/* §4.7 */
		case SS_POLICY_TLV_AUTO_ACCEPT_JOINERS:
			if (vlen == 1) p->auto_accept_joiners = (v[0] != 0); break;
		case SS_POLICY_TLV_BANLIST:
			if (vlen % SS_POLICY_PUBKEY_LEN == 0) {
				uint16_t n = (uint16_t)(vlen / SS_POLICY_PUBKEY_LEN);
				if (n <= SS_POLICY_MAX_LIST_ENTRIES) {
					memcpy(p->banlist.entries, v, vlen);
					p->banlist.n_entries = n;
				}
			}
			break;
		case SS_POLICY_TLV_ALLOWLIST:
			if (vlen % SS_POLICY_PUBKEY_LEN == 0) {
				uint16_t n = (uint16_t)(vlen / SS_POLICY_PUBKEY_LEN);
				if (n <= SS_POLICY_MAX_LIST_ENTRIES) {
					memcpy(p->allowlist.entries, v, vlen);
					p->allowlist.n_entries = n;
				}
			}
			break;
		case SS_POLICY_TLV_PROOF_TIER_REQUIRED:
			if (vlen == 1) p->proof_tier_required = (ss_proof_tier_t)v[0]; break;
		case SS_POLICY_TLV_AUTO_FINALIZE_ON_DYING:
			if (vlen == 1) p->auto_finalize_on_dying = (v[0] != 0); break;
		case SS_POLICY_TLV_ALLOW_TIER_B_ROLLOVER:
			if (vlen == 1) p->allow_tier_b_rollover = (v[0] != 0); break;
		case SS_POLICY_TLV_JOINER_ADMISSION_WINDOW_BLOCKS:
			if (vlen == 4) p->joiner_admission_window_blocks = get_u32_be(v); break;

		/* §4.8 */
		case SS_POLICY_TLV_WATCHTOWER_MODE:
			if (vlen == 1) p->watchtower_mode = (ss_watchtower_mode_t)v[0]; break;
		case SS_POLICY_TLV_POISON_TX_STRATEGY:
			if (vlen == 1) p->poison_tx_strategy = (ss_poison_tx_strategy_t)v[0]; break;
		case SS_POLICY_TLV_BREACH_RESPONSE_FEE_RATE:
			if (vlen == 8) p->breach_response_fee_rate_sat_per_kvb = get_u64_be(v); break;
		case SS_POLICY_TLV_WT_STARTUP_SCAN_DEPTH:
			if (vlen == 2) p->wt_startup_scan_depth_blocks = get_u16_be(v); break;
		case SS_POLICY_TLV_REORG_ALARM_DEPTH:
			if (vlen == 1) p->reorg_alarm_depth_blocks = v[0]; break;
		case SS_POLICY_TLV_REORG_RESPONSE_STRATEGY:
			if (vlen == 1) p->reorg_response_strategy = (ss_reorg_response_t)v[0]; break;

		/* §4.9 */
		case SS_POLICY_TLV_MAX_ADVANCE_COUNT_PER_LEAF:
			if (vlen == 2) p->max_advance_count_per_leaf = get_u16_be(v); break;
		case SS_POLICY_TLV_ADVANCE_DUST_WARNING_SAT:
			if (vlen == 8) p->advance_dust_warning_threshold_sat = get_u64_be(v); break;
		case SS_POLICY_TLV_STATE_REPLAY_DEFENSE_WINDOW:
			if (vlen == 4) p->state_replay_defense_window_blocks = get_u32_be(v); break;

		/* §4.10 */
		case SS_POLICY_TLV_FEE_RATE_STRATEGY:
			if (vlen == 1) p->fee_rate_strategy = (ss_fee_rate_strategy_t)v[0]; break;
		case SS_POLICY_TLV_MIN_FEE_RATE_SAT_PER_KVB:
			if (vlen == 8) p->min_fee_rate_sat_per_kvb = get_u64_be(v); break;

		/* §4.11 */
		case SS_POLICY_TLV_MIGRATION_PATHS_SUPPORTED:
			if (vlen == 1) p->migration_paths_supported = v[0]; break;
		case SS_POLICY_TLV_ALLOW_SPLICE:
			if (vlen == 1) p->allow_splice = (v[0] != 0); break;
		case SS_POLICY_TLV_ALLOW_JIT_FALLBACK:
			if (vlen == 1) p->allow_jit_fallback = (v[0] != 0); break;

		/* §4.12 */
		case SS_POLICY_TLV_FORWARD_FEE_POLICY:
			if (vlen == 1) p->forward_fee_policy = (ss_forward_fee_policy_t)v[0]; break;
		case SS_POLICY_TLV_FORWARD_FEE_BASE_MSAT:
			if (vlen == 8) p->forward_fee_base_msat = get_u64_be(v); break;
		case SS_POLICY_TLV_FORWARD_FEE_PPM:
			if (vlen == 4) p->forward_fee_ppm = get_u32_be(v); break;
		case SS_POLICY_TLV_LSP_SELF_ROUTING_ALLOWED:
			if (vlen == 1) p->lsp_self_routing_allowed = (v[0] != 0); break;

		/* §4.13 */
		case SS_POLICY_TLV_AUTO_HOST_NEXT:
			if (vlen == 1) p->auto_host_next = (v[0] != 0); break;
		case SS_POLICY_TLV_LADDER_CADENCE_BLOCKS:
			if (vlen == 4) p->ladder_cadence_blocks = get_u32_be(v); break;
		case SS_POLICY_TLV_AUTO_ROTATE_PERIODICALLY:
			if (vlen == 1) p->auto_rotate_periodically = (v[0] != 0); break;
		case SS_POLICY_TLV_ROTATION_INTERVAL_BLOCKS:
			if (vlen == 4) p->rotation_interval_blocks = get_u32_be(v); break;
		case SS_POLICY_TLV_EXPECTED_ROTATION_BLOCKS:
			if (vlen == 4) p->expected_rotation_blocks = get_u32_be(v); break;

		default:
			/* Forward-compat: unknown TLV IDs are skipped silently */
			break;
		}
		off += vlen;
	}
	return (off == len) ? 1 : 0;
}
