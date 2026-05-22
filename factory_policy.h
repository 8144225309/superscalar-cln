/*
 * factory_policy.h — Canonical ss_factory_policy_t (per FACTORY_POLICY_V1
 * §4.1-§4.13) and the joiner's client_signing_prefs_t.
 *
 * Scope: PLUGIN-SIDE ONLY.  Per FACTORY_POLICY_V1 §2 the lib has no policy
 * concept — this struct, its defaults, validators, and TLV codec all live
 * in the plugin source tree.  The lib only sees discrete CLI flags +
 * factory/watchtower construction-arg structs that the plugin populates
 * from this policy at every call site.
 *
 * Wire format: TLV-diff-from-defaults, encoded inside the existing
 * factory_piggyback envelope (submsg 4, TLV 0x0400 carries the diff blob).
 * Encoder + decoder live in factory_policy.c (B1-step-2, not landed yet).
 *
 * Phase B1-step-1 (this file): struct + enums + defaults + TLV ID symbols
 * only.  No code paths read or write yet.  Subsequent steps:
 *   B1-step-2: TLV codec (encode/decode)
 *   B1-step-3: LSP build + attach to FACTORY_INFO_RESPONSE
 *   B1-step-4: Client decode + store on factory_instance_t
 *   B1-step-5: Validator + hook into FACTORY_PROPOSE before nonce gen
 *   B1-step-6: Smoke test on signet
 */

#ifndef SUPERSCALAR_CLN_FACTORY_POLICY_H
#define SUPERSCALAR_CLN_FACTORY_POLICY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* ============================================================================
 * Schema version + protocol_id (§4.1)
 * ========================================================================= */

#define SS_FACTORY_POLICY_SCHEMA_VERSION  1U
#define SS_FACTORY_POLICY_PROTOCOL_ID_DEFAULT  "SuperScalar/v1"

/* ============================================================================
 * Enums (§4.2 tree shape, §4.7 joiner admission, §4.8 watchtower,
 * §4.10 fee policy, §4.12 routing, §4.11 migration bitmask)
 * ========================================================================= */

typedef enum {
	ARITY_AUTO         = 0,
	ARITY_1            = 1,
	ARITY_2            = 2,
	ARITY_PS           = 3,
} ss_arity_mode_t;
#define SS_DEFAULT_ARITY_MODE  ARITY_PS  /* §4.2.1 — post-PS-canonical shift */

typedef enum {
	CHANNEL_TYPE_LN_PENALTY      = 0,
	CHANNEL_TYPE_PSEUDO_SPILMAN  = 1,
} ss_leaf_channel_type_t;
#define SS_DEFAULT_LEAF_CHANNEL_TYPE  CHANNEL_TYPE_PSEUDO_SPILMAN  /* §4.2.3 */

typedef enum {
	PROOF_TIER_CHANNEL  = 0,   /* highest trust — joiner has a channel */
	PROOF_TIER_INVOICE  = 1,
	PROOF_TIER_NONE     = 2,
} ss_proof_tier_t;
#define SS_DEFAULT_PROOF_TIER  PROOF_TIER_CHANNEL  /* §4.7.4 */

typedef enum {
	WT_DISABLED  = 0,
	WT_LOCAL     = 1,
	WT_BOTH      = 2,
} ss_watchtower_mode_t;
#define SS_DEFAULT_WT_MODE  WT_BOTH  /* §4.8.1 */

typedef enum {
	POISON_NEVER         = 0,
	POISON_ORACULAR      = 1,   /* post-#208 default */
	POISON_REACTIVE      = 2,
} ss_poison_tx_strategy_t;
#define SS_DEFAULT_POISON_STRATEGY  POISON_ORACULAR  /* §4.8.2 */

typedef enum {
	REORG_REBROADCAST     = 0,
	REORG_FORCE_CLOSE     = 1,
	REORG_ALARM_ONLY      = 2,
} ss_reorg_response_t;
#define SS_DEFAULT_REORG_RESPONSE  REORG_REBROADCAST  /* §4.8.6 */

typedef enum {
	FEE_STATIC      = 0,
	FEE_CONSERVATIVE = 1,
	FEE_BLOCKS      = 2,   /* lib default */
} ss_fee_rate_strategy_t;
#define SS_DEFAULT_FEE_STRATEGY  FEE_BLOCKS  /* §4.10.1 */

typedef enum {
	FWD_NO_FORWARD     = 0,
	FWD_OWN_FACTORY    = 1,
	FWD_ANY            = 2,
} ss_forward_fee_policy_t;
#define SS_DEFAULT_FORWARD_POLICY  FWD_NO_FORWARD  /* §4.12.1 */

/* migration_paths_supported is a bitmask, not an enum — §4.11.1 */
#define MIG_LN_PAYMENT      (1u << 0)
#define MIG_SPLICE          (1u << 1)
#define MIG_NEW_FACTORY     (1u << 2)
#define MIG_JIT_FALLBACK    (1u << 3)
#define SS_DEFAULT_MIGRATION_PATHS  (MIG_LN_PAYMENT)  /* §4.11.1 */

/* ============================================================================
 * Pubkey list cap (banlist + allowlist, §4.7.2 §4.7.3)
 * ========================================================================= */

#define SS_POLICY_PUBKEY_LEN     33
#define SS_POLICY_MAX_LIST_ENTRIES  64  /* per-list cap; encoder splits or refuses larger */

typedef struct {
	uint8_t  entries[SS_POLICY_MAX_LIST_ENTRIES][SS_POLICY_PUBKEY_LEN];
	uint16_t n_entries;  /* 0 = empty list */
} ss_policy_pubkey_list_t;

/* ============================================================================
 * The canonical struct — every field carries its §-ref and TLV ID
 *
 * Default values are zero unless noted, EXCEPT for fields whose runtime
 * meaning depends on a non-zero default — those are documented inline and
 * applied by ss_factory_policy_init_defaults() (next step).
 *
 * Field order matches the spec sections 4.1-4.13 for ease of cross-reference.
 * ========================================================================= */

typedef struct ss_factory_policy {
	/* --- §4.1 Schema / protocol --- */
	uint32_t  schema_version;             /* TLV 0x0000 — default 1, ALWAYS first in diff */
	uint8_t   protocol_id[32];            /* TLV 0x0001 — "SuperScalar/v1" zero-padded */

	/* --- §4.2 Tree shape (immutable) --- */
	ss_arity_mode_t        arity_mode;             /* TLV 0x0100 — ARITY_PS */
	uint8_t                leaf_arity;             /* TLV 0x0101 — 2 */
	ss_leaf_channel_type_t leaf_channel_type;      /* TLV 0x0102 — PSEUDO_SPILMAN */
	uint8_t                ps_subfactory_arity;    /* TLV 0x0103 — 2 */
	uint16_t               epoch_count;            /* TLV 0x0104 — 16 */
	uint8_t                n_layers;               /* TLV 0x0105 — 2 */
	uint16_t               dw_step_blocks;         /* TLV 0x0106 — 144 */
	uint8_t                static_near_root_layers; /* TLV 0x0107 — 0 */

	/* --- §4.3 Lifecycle (immutable, hard) --- */
	uint32_t  lifetime_blocks;            /* TLV 0x0200 — 4320 (~30d) */
	uint32_t  dying_period_blocks;        /* TLV 0x0201 — 288 (~2d) */
	uint16_t  block_early_count;          /* TLV 0x0202 — 144 (~1d) */
	uint32_t  confirm_timeout_sec;        /* TLV 0x0203 — 86400 (24h) */

	/* --- §4.4 Economics (hard) --- */
	uint64_t  per_client_capacity_sat;    /* TLV 0x0300 — 100_000 */
	uint64_t  lsp_reserve_per_leaf_sat;   /* TLV 0x0301 — 50_000 */
	uint8_t   lsp_initial_balance_pct;    /* TLV 0x0302 — 100 */
	uint64_t  lsp_fee_sat;                /* TLV 0x0303 — 0 */
	uint32_t  lsp_fee_ppm;                /* TLV 0x0304 — 0 */
	uint64_t  join_fee_sat;               /* TLV 0x0305 — 0 (soft) */
	uint64_t  min_capacity_per_join_sat;  /* TLV 0x0306 — 10_000 (joiner_enforceable_hard) */
	uint64_t  max_capacity_per_join_sat;  /* TLV 0x0307 — 0 (= per_client_capacity_sat) */

	/* --- §4.5 Channel options --- */
	bool      allow_bolt12;               /* TLV 0x0400 — true (soft) */
	bool      allow_amp;                  /* TLV 0x0401 — false (soft) */
	uint64_t  htlc_min_sat;               /* TLV 0x0402 — 1 (joiner_enforceable_hard) */
	uint64_t  htlc_max_sat;               /* TLV 0x0403 — 0 (= channel capacity) */
	bool      allow_blinded_paths;        /* TLV 0x0404 — true (soft) */

	/* --- §4.6 HTLC policy (joiner_enforceable_hard except max_accepted_htlcs which is hard) --- */
	uint16_t  max_concurrent_htlcs_per_channel; /* TLV 0x0500 — 30 */
	uint64_t  max_in_flight_msat_per_channel;   /* TLV 0x0501 — 0 (= 90% of cap) */
	uint32_t  min_final_cltv_expiry_delta;      /* TLV 0x0502 — block_early_count + 18 */
	uint32_t  cltv_expiry_delta_forward;        /* TLV 0x0503 — block_early_count + 40 */
	uint16_t  max_accepted_htlcs;               /* TLV 0x0504 — 483 (hard) */

	/* --- §4.7 Joiner admission --- */
	bool                       auto_accept_joiners;          /* TLV 0x0600 — false (soft) */
	ss_policy_pubkey_list_t    banlist;                      /* TLV 0x0601 — empty (soft) */
	ss_policy_pubkey_list_t    allowlist;                    /* TLV 0x0602 — empty (soft) */
	ss_proof_tier_t            proof_tier_required;          /* TLV 0x0603 — PROOF_TIER_CHANNEL */
	bool                       auto_finalize_on_dying;       /* TLV 0x0604 — true (soft) */
	bool                       allow_tier_b_rollover;        /* TLV 0x0605 — true (joiner_enforceable_hard) */
	uint32_t                   joiner_admission_window_blocks; /* TLV 0x0606 — lifetime - dying */

	/* --- §4.8 Watchtower policy (all soft) --- */
	ss_watchtower_mode_t       watchtower_mode;                       /* TLV 0x0700 — WT_BOTH */
	ss_poison_tx_strategy_t    poison_tx_strategy;                    /* TLV 0x0701 — POISON_ORACULAR */
	uint64_t                   breach_response_fee_rate_sat_per_kvb;  /* TLV 0x0702 — 1000 */
	uint16_t                   wt_startup_scan_depth_blocks;          /* TLV 0x0703 — 144 */
	uint8_t                    reorg_alarm_depth_blocks;              /* TLV 0x0704 — 2 */
	ss_reorg_response_t        reorg_response_strategy;               /* TLV 0x0705 — REORG_REBROADCAST */

	/* --- §4.9 PS chain policy --- */
	uint16_t  max_advance_count_per_leaf;        /* TLV 0x0800 — 10 (hard) */
	uint64_t  advance_dust_warning_threshold_sat; /* TLV 0x0801 — 1000 (soft) */
	uint32_t  state_replay_defense_window_blocks; /* TLV 0x0802 — lifetime_blocks (joiner_enforceable_hard) */

	/* --- §4.10 Fee policy (soft) --- */
	ss_fee_rate_strategy_t  fee_rate_strategy;        /* TLV 0x0900 — FEE_BLOCKS */
	uint64_t                min_fee_rate_sat_per_kvb;  /* TLV 0x0901 — 1000 */

	/* --- §4.11 Migration policy (soft) --- */
	uint8_t   migration_paths_supported;  /* TLV 0x0A00 — MIG_LN_PAYMENT (bitmask) */
	bool      allow_splice;               /* TLV 0x0A01 — false */
	bool      allow_jit_fallback;         /* TLV 0x0A02 — true */

	/* --- §4.12 Routing / forwarding policy (soft) --- */
	ss_forward_fee_policy_t  forward_fee_policy;     /* TLV 0x0B00 — FWD_NO_FORWARD */
	uint64_t                 forward_fee_base_msat;   /* TLV 0x0B01 — 1000 */
	uint32_t                 forward_fee_ppm;         /* TLV 0x0B02 — 1 */
	bool                     lsp_self_routing_allowed; /* TLV 0x0B03 — true */

	/* --- §4.13 Lifecycle commitments (soft) --- */
	bool      auto_host_next;              /* TLV 0x0C00 — true */
	uint32_t  ladder_cadence_blocks;       /* TLV 0x0C01 — 4320 */
	bool      auto_rotate_periodically;    /* TLV 0x0C02 — false */
	uint32_t  rotation_interval_blocks;    /* TLV 0x0C03 — 0 (joiner_enforceable_hard) */
	uint32_t  expected_rotation_blocks;    /* TLV 0x0C04 — 0 */
} ss_factory_policy_t;

/* ============================================================================
 * TLV ID symbols (for use by codec; matches spec §4.x.y entries above).
 * Categories partitioned per FACTORY_POLICY_V1 §4.0.3.
 * ========================================================================= */

#define SS_POLICY_TLV_SCHEMA_VERSION                  0x0000
#define SS_POLICY_TLV_PROTOCOL_ID                     0x0001

#define SS_POLICY_TLV_ARITY_MODE                      0x0100
#define SS_POLICY_TLV_LEAF_ARITY                      0x0101
#define SS_POLICY_TLV_LEAF_CHANNEL_TYPE               0x0102
#define SS_POLICY_TLV_PS_SUBFACTORY_ARITY             0x0103
#define SS_POLICY_TLV_EPOCH_COUNT                     0x0104
#define SS_POLICY_TLV_N_LAYERS                        0x0105
#define SS_POLICY_TLV_DW_STEP_BLOCKS                  0x0106
#define SS_POLICY_TLV_STATIC_NEAR_ROOT_LAYERS         0x0107

#define SS_POLICY_TLV_LIFETIME_BLOCKS                 0x0200
#define SS_POLICY_TLV_DYING_PERIOD_BLOCKS             0x0201
#define SS_POLICY_TLV_BLOCK_EARLY_COUNT               0x0202
#define SS_POLICY_TLV_CONFIRM_TIMEOUT_SEC             0x0203

#define SS_POLICY_TLV_PER_CLIENT_CAPACITY_SAT         0x0300
#define SS_POLICY_TLV_LSP_RESERVE_PER_LEAF_SAT        0x0301
#define SS_POLICY_TLV_LSP_INITIAL_BALANCE_PCT         0x0302
#define SS_POLICY_TLV_LSP_FEE_SAT                     0x0303
#define SS_POLICY_TLV_LSP_FEE_PPM                     0x0304
#define SS_POLICY_TLV_JOIN_FEE_SAT                    0x0305
#define SS_POLICY_TLV_MIN_CAPACITY_PER_JOIN_SAT       0x0306
#define SS_POLICY_TLV_MAX_CAPACITY_PER_JOIN_SAT       0x0307

#define SS_POLICY_TLV_ALLOW_BOLT12                    0x0400
#define SS_POLICY_TLV_ALLOW_AMP                       0x0401
#define SS_POLICY_TLV_HTLC_MIN_SAT                    0x0402
#define SS_POLICY_TLV_HTLC_MAX_SAT                    0x0403
#define SS_POLICY_TLV_ALLOW_BLINDED_PATHS             0x0404

#define SS_POLICY_TLV_MAX_CONCURRENT_HTLCS_PER_CHANNEL 0x0500
#define SS_POLICY_TLV_MAX_IN_FLIGHT_MSAT_PER_CHANNEL  0x0501
#define SS_POLICY_TLV_MIN_FINAL_CLTV_EXPIRY_DELTA     0x0502
#define SS_POLICY_TLV_CLTV_EXPIRY_DELTA_FORWARD       0x0503
#define SS_POLICY_TLV_MAX_ACCEPTED_HTLCS              0x0504

#define SS_POLICY_TLV_AUTO_ACCEPT_JOINERS             0x0600
#define SS_POLICY_TLV_BANLIST                         0x0601
#define SS_POLICY_TLV_ALLOWLIST                       0x0602
#define SS_POLICY_TLV_PROOF_TIER_REQUIRED             0x0603
#define SS_POLICY_TLV_AUTO_FINALIZE_ON_DYING          0x0604
#define SS_POLICY_TLV_ALLOW_TIER_B_ROLLOVER           0x0605
#define SS_POLICY_TLV_JOINER_ADMISSION_WINDOW_BLOCKS  0x0606

#define SS_POLICY_TLV_WATCHTOWER_MODE                 0x0700
#define SS_POLICY_TLV_POISON_TX_STRATEGY              0x0701
#define SS_POLICY_TLV_BREACH_RESPONSE_FEE_RATE        0x0702
#define SS_POLICY_TLV_WT_STARTUP_SCAN_DEPTH           0x0703
#define SS_POLICY_TLV_REORG_ALARM_DEPTH               0x0704
#define SS_POLICY_TLV_REORG_RESPONSE_STRATEGY         0x0705

#define SS_POLICY_TLV_MAX_ADVANCE_COUNT_PER_LEAF      0x0800
#define SS_POLICY_TLV_ADVANCE_DUST_WARNING_SAT        0x0801
#define SS_POLICY_TLV_STATE_REPLAY_DEFENSE_WINDOW     0x0802

#define SS_POLICY_TLV_FEE_RATE_STRATEGY               0x0900
#define SS_POLICY_TLV_MIN_FEE_RATE_SAT_PER_KVB        0x0901

#define SS_POLICY_TLV_MIGRATION_PATHS_SUPPORTED       0x0A00
#define SS_POLICY_TLV_ALLOW_SPLICE                    0x0A01
#define SS_POLICY_TLV_ALLOW_JIT_FALLBACK              0x0A02

#define SS_POLICY_TLV_FORWARD_FEE_POLICY              0x0B00
#define SS_POLICY_TLV_FORWARD_FEE_BASE_MSAT           0x0B01
#define SS_POLICY_TLV_FORWARD_FEE_PPM                 0x0B02
#define SS_POLICY_TLV_LSP_SELF_ROUTING_ALLOWED        0x0B03

#define SS_POLICY_TLV_AUTO_HOST_NEXT                  0x0C00
#define SS_POLICY_TLV_LADDER_CADENCE_BLOCKS           0x0C01
#define SS_POLICY_TLV_AUTO_ROTATE_PERIODICALLY        0x0C02
#define SS_POLICY_TLV_ROTATION_INTERVAL_BLOCKS        0x0C03
#define SS_POLICY_TLV_EXPECTED_ROTATION_BLOCKS        0x0C04

/* ============================================================================
 * Initialise a policy struct with canonical defaults (declared here, defined
 * in factory_policy.c which lands in B1-step-2).
 *
 * Some fields' defaults are derived from other fields (e.g.
 * max_capacity_per_join_sat = per_client_capacity_sat,
 * joiner_admission_window_blocks = lifetime_blocks - dying_period_blocks,
 * state_replay_defense_window_blocks = lifetime_blocks).  Init runs in two
 * passes: independent defaults first, then derived defaults.
 * ========================================================================= */

void ss_factory_policy_init_defaults(ss_factory_policy_t *p);

/* ============================================================================
 * client_signing_prefs_t — joiner-side thresholds for the 12 fields with
 * `joiner_enforceable_hard` strength per FACTORY_POLICY_V1 §4.0.2.
 *
 * The validator (lands in B1-step-5) compares an incoming
 * ss_factory_policy_t against these thresholds and refuses to sign
 * FACTORY_PROPOSE if any field is out of the acceptable range.
 *
 * Each field below either sets a min, max, or required-equality.  Defaults
 * are conservative — operators must opt in to looser policies.
 *
 * Persisted in wallet.db under setting key "client_signing_prefs" as JSON
 * (loader implemented in B1-step-5 alongside the validator).
 * ========================================================================= */

typedef struct ss_client_signing_prefs {
	/* htlc_min_sat: refuse if policy.htlc_min_sat > max_acceptable */
	uint64_t  max_htlc_min_sat;                  /* default 10_000 */

	/* htlc_max_sat: refuse if policy.htlc_max_sat in (0, min_acceptable) */
	uint64_t  min_htlc_max_sat;                  /* default 100_000 — at least 100k sat HTLCs */

	/* max_concurrent_htlcs: refuse if policy.value < min_acceptable */
	uint16_t  min_max_concurrent_htlcs;          /* default 5 */

	/* max_in_flight_msat: refuse if policy.value < min_acceptable */
	uint64_t  min_max_in_flight_msat;            /* default 1_000_000 (1k sat) */

	/* min_final_cltv_expiry_delta: refuse if policy.value > max_acceptable
	 * (we don't want absurd CLTVs we have to wait for) */
	uint32_t  max_min_final_cltv_delta;          /* default 200 (~33 hr) */

	/* cltv_expiry_delta_forward: refuse if policy.value > max_acceptable */
	uint32_t  max_cltv_delta_forward;            /* default 200 */

	/* min_capacity_per_join_sat: refuse if policy.value > max_acceptable
	 * (we won't pay more than this to join) */
	uint64_t  max_min_capacity_per_join_sat;     /* default 1_000_000 (~$1 BTC-equivalent) */

	/* max_capacity_per_join_sat: refuse if policy.value < min_acceptable */
	uint64_t  min_max_capacity_per_join_sat;     /* default 10_000 */

	/* proof_tier_required: refuse if policy.tier numerically > our max
	 * (lower enum value = stricter tier; CHANNEL=0 strictest, NONE=2 loosest)
	 *
	 * If require_strict_proof_tier is set, the LSP must require a tier
	 * AT LEAST as strict as max_proof_tier.  Otherwise we don't care. */
	bool             require_strict_proof_tier;  /* default true */
	ss_proof_tier_t  max_proof_tier;             /* default PROOF_TIER_INVOICE */

	/* rotation_interval_blocks: refuse if policy.value > 0 AND policy.value < min_acceptable
	 * (don't accept "rotate every 1 block" which would mean perma-ceremony) */
	uint32_t  min_rotation_interval_blocks;      /* default 144 (~1 day) */

	/* allow_tier_b_rollover: if require_tier_b_rollover, refuse if false */
	bool      require_tier_b_rollover;           /* default false (don't require) */

	/* state_replay_defense_window_blocks: refuse if policy.value < min_acceptable */
	uint32_t  min_state_replay_defense_window_blocks;  /* default 288 (~2 days) */

	/* D.1 toggle: when true (default), plugin auto-signs every proposal
	 * that passes the validator.  When false, plugin caches the proposal
	 * in pending_proposals and does NOT send NONCE_BUNDLE — the wallet
	 * UI is expected to surface a confirmation prompt and the user must
	 * call factory-approve-proposal (D.6) to release the held nonces. */
	bool      auto_sign_on_validator_pass;       /* default true */
} ss_client_signing_prefs_t;

void ss_client_signing_prefs_init_defaults(ss_client_signing_prefs_t *prefs);

/* ============================================================================
 * Wire codec — TLV-diff-from-defaults (§4 of FACTORY_POLICY_V1).
 *
 * Encoder: writes TLVs for every field where p differs from `defaults`.
 *   schema_version is ALWAYS emitted first (per §4.1.1).
 *   Returns total bytes written, or 0 on buffer overflow.
 *
 * Decoder: initialises p to canonical defaults, then overwrites each
 *   field for which a TLV is present.  Unknown TLV IDs are skipped
 *   silently for forward compatibility.
 *   Returns 1 on success, 0 if buf is truncated or malformed.
 * ========================================================================= */

size_t ss_factory_policy_encode_diff(const ss_factory_policy_t *p,
				       const ss_factory_policy_t *defaults,
				       uint8_t *buf, size_t cap);

int ss_factory_policy_decode(const uint8_t *buf, size_t len,
			       ss_factory_policy_t *p);

/* ============================================================================
 * Validation result — populated by the validator (B1-step-5).
 *
 * field_tlv is the TLV ID of the first violating field; on success it is
 * 0xFFFF (impossible TLV ID).  reason is a short null-terminated string
 * suitable for logging and for transmitting back to the LSP in CEREMONY_ABORT.
 * ========================================================================= */

#define SS_POLICY_VALIDATE_OK         0
#define SS_POLICY_VALIDATE_HARD_FAIL  1
#define SS_POLICY_VALIDATE_SOFT_FAIL  2  /* logged but not fatal */

typedef struct {
	int       result;       /* SS_POLICY_VALIDATE_* */
	uint16_t  field_tlv;    /* TLV ID of first violating field; 0xFFFF if OK */
	char      reason[128];  /* human-readable single-line description */
} ss_policy_validation_result_t;

/* B1.5 validator — declared here, defined in factory_policy.c.
 * Walks the 12 joiner_enforceable_hard fields per FACTORY_POLICY_V1 §4.0.2,
 * returns first violation found, or OK if all pass.  Populates `out`
 * with field_tlv + reason on violation. */
int ss_validate_policy_against_prefs(const ss_factory_policy_t *policy,
				       const ss_client_signing_prefs_t *prefs,
				       ss_policy_validation_result_t *out);

#endif  /* SUPERSCALAR_CLN_FACTORY_POLICY_H */
