/* Factory instance state management for the SuperScalar CLN plugin.
 *
 * Each factory_instance tracks:
 * - Participants (LSP + N clients)
 * - DW tree state via libsuperscalar
 * - MuSig2 ceremony progress
 * - Channel-to-leaf mappings
 * - Lifecycle (active/dying/expired)
 * - Breach/penalty data per epoch
 */
#ifndef SUPERSCALAR_FACTORY_STATE_H
#define SUPERSCALAR_FACTORY_STATE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "ceremony.h"
#include "nonce_exchange.h"

/* Max participants in a single factory (LSP + clients).
 * Matches FACTORY_MAX_SIGNERS in libsuperscalar v0.1.9. */
#define MAX_FACTORY_PARTICIPANTS 64

/* Max concurrent factories */
#define MAX_FACTORIES 32

/* Factory lifecycle.
 *
 * States 0-3 (INIT/ACTIVE/DYING/EXPIRED) are the original state machine driven
 * by the ceremony + force-close pathways.
 *
 * States 4-7 are terminal-closed states set by the watcher (Phase 1+ of the
 * trustless-watcher plan). Only CLOSED_EXTERNALLY is populated by Phase 1; the
 * remaining closed-* values are reserved so the persistence format stabilizes
 * in one go and Phase 2's classifier can populate them without another version
 * bump. Factories in any closed-* state are skipped by the breach scan and the
 * ceremony paths, and are safe to reap via factory-confirm-closed.
 *
 * Do not renumber — enum values are serialized as u8 in persist.c. */
typedef enum {
	FACTORY_LIFECYCLE_INIT = 0,		/* Being created, ceremony in progress */
	FACTORY_LIFECYCLE_ACTIVE = 1,		/* Signed tree, channels open */
	FACTORY_LIFECYCLE_DYING = 2,		/* Close initiated or timelock approaching */
	FACTORY_LIFECYCLE_EXPIRED = 3,		/* nLockTime distribution TX path */

	/* Watcher-populated terminal states (Phase 1+). */
	FACTORY_LIFECYCLE_CLOSED_EXTERNALLY = 4, /* Root spent outside plugin
						  * control (manual sweep, HSM-
						  * lost recovery, etc.). Set by
						  * the UTXO heartbeat in
						  * breach_utxo_checked when the
						  * factory was ACTIVE (i.e. we
						  * didn't initiate the close). */
	FACTORY_LIFECYCLE_CLOSED_COOPERATIVE = 5, /* Reserved — Phase 2 */
	FACTORY_LIFECYCLE_CLOSED_UNILATERAL = 6,  /* Reserved — Phase 2 */
	FACTORY_LIFECYCLE_CLOSED_BREACHED = 7,    /* Reserved — Phase 2+3 */
	FACTORY_LIFECYCLE_ABORTED = 8,            /* Phase 4c: ceremony stalled
						   * indefinitely (typically
						   * counterparty never
						   * responded). Operator-
						   * triggered via
						   * factory-abort-stuck.
						   * Funded ABORTED factories
						   * recover via the existing
						   * CLTV unilateral exit at
						   * factory expiry. */
} factory_lifecycle_t;

/* Helper: a factory in any closed terminal state should not be scanned,
 * advertised, or rotated. Centralizes the state check so Phase 2's classifier
 * can add new closed states without hunting down every gate. */
static inline bool factory_is_closed(factory_lifecycle_t l) {
	return l == FACTORY_LIFECYCLE_EXPIRED
	    || l == FACTORY_LIFECYCLE_CLOSED_EXTERNALLY
	    || l == FACTORY_LIFECYCLE_CLOSED_COOPERATIVE
	    || l == FACTORY_LIFECYCLE_CLOSED_UNILATERAL
	    || l == FACTORY_LIFECYCLE_CLOSED_BREACHED
	    || l == FACTORY_LIFECYCLE_ABORTED;
}

/* Phase 2a: values for factory_instance_t.closed_by. Stored as uint8_t
 * in persistence; do not renumber without a meta-version bump. */
#define CLOSED_BY_UNKNOWN       0 /* haven't classified, or scan found nothing */
#define CLOSED_BY_SELF          1 /* our dist_tx or our kickoff matched */
#define CLOSED_BY_COUNTERPARTY  2 /* scan found a TX we didn't sign — Phase 2b
				   * refines into normal-exit vs. breach */

/* Phase 3b: signal-observation bits for factory_instance_t.signals_observed.
 * The unified classifier (ss_apply_signals) reads these to decide lifecycle.
 * Persisted as a u8; don't renumber. */
#define SIGNAL_UTXO_SPENT          (1u << 0) /* heartbeat saw root spent */
#define SIGNAL_BROADCAST_MISSING   (1u << 1) /* sendrawtransaction got bad-txns-inputs-missingorspent */
#define SIGNAL_BROADCAST_KNOWN     (1u << 2) /* sendrawtransaction got "already in mempool/blockchain" */
#define SIGNAL_DIST_TXID_MATCHED   (1u << 3) /* spending TXID == dist_signed_txid */
#define SIGNAL_KICKOFF_TXID_MATCHED (1u << 4) /* spending TXID == kickoff txid */
#define SIGNAL_WITNESS_CURRENT_MATCH (1u << 5) /* witness sig matched current epoch */
#define SIGNAL_WITNESS_PAST_MATCH  (1u << 6) /* witness sig matched a past epoch */
#define SIGNAL_STATE_TX_MATCH      (1u << 7) /* downstream state TX matched a cached state root */
#define SIGNAL_PENALTY_CONFIRMED   (1u << 8) /* Phase 3c: our penalty TX confirmed on chain — breach neutralized */

/* Phase 3c: penalty pipeline.
 * A pending penalty is a burn TX we have broadcast (or are about to
 * broadcast) against a counterparty's revoked L-stock output. The
 * scheduler in handle_block_added re-runs each pending entry through
 * htlc_fee_bump_should_bump every block and CPFP-bumps if stuck.
 *
 * Deadline: derived from the CSV delay on the L-stock output — we MUST
 * confirm our burn before CSV unlocks (at which point the counterparty
 * can claim freely). Upstream htlc_fee_bump_t carries deadline_block.
 *
 * Budget: fraction of the L-stock amount we are willing to spend on
 * fees. Default 50% (HTLC_FEE_BUMP_DEFAULT_BUDGET_PCT from
 * htlc_fee_bump.h). Counterparty's alternative is keeping 100% of the
 * stolen amount, so we rationally outbid them up to (amount - dust).
 *
 * Persisted as TLV-style blocks in the factory meta under key
 * "pending_penalties" so restarts don't lose the fee state. */
#define MAX_PENDING_PENALTIES 16

typedef enum {
	PENALTY_STATE_PENDING   = 0, /* constructed, not yet broadcast */
	PENALTY_STATE_BROADCAST = 1, /* in mempool, awaiting confirm */
	PENALTY_STATE_CONFIRMED = 2, /* on chain with >=1 conf */
	PENALTY_STATE_REPLACED  = 3, /* counterparty won the race (RBF or
				      * CSV-expired claim) — we lost */
	PENALTY_STATE_STALE     = 4, /* Phase 4b: source UTXO no longer
				      * exists (counterparty RBF'd the
				      * state TX). Burn references a dead
				      * outpoint; need to re-scan to find
				      * the new state TX and rebuild. v2
				      * will auto-rebuild; v1 just flags. */
} penalty_state_t;

typedef struct {
	uint32_t epoch;          /* revoked epoch this burns */
	int32_t  leaf_index;     /* which leaf's L-stock we target */
	uint8_t  burn_txid[32];  /* txid of our burn broadcast (internal BE) */
	uint64_t lstock_sats;    /* value at stake — diagnostic only post-3c-redux */
	uint32_t csv_unlock_block; /* deadline: counterparty can claim after this */
	uint32_t first_broadcast_block;
	uint32_t last_broadcast_block;
	uint32_t confirmed_block; /* 0 if unconfirmed */
	/* Phase 3c-redux: last_feerate + tx_vsize were used by the original
	 * htlc_fee_bump-based RBF scheduler, which doesn't apply to burn
	 * TXs (they're 100%-fee by construction — full L-stock value goes
	 * to miner). Kept in struct for persist v12 backward compat;
	 * written at registration but not used for scheduling decisions. */
	uint64_t last_feerate;    /* DIAGNOSTIC ONLY — not used post-redux */
	uint32_t tx_vsize;        /* DIAGNOSTIC ONLY — not used post-redux */
	uint8_t  state;           /* penalty_state_t */
	uint8_t  cpfp_attempted;  /* reserved for Phase 3c2 CPFP-via-anchor */
} pending_penalty_t;

/* Phase 4d: CSV claim scheduler.
 *
 * Algorithm ported from upstream sweeper.c (see
 * feedback_reuse_superscalar_upstream). A pending sweep tracks a source
 * output (on-chain TX we want to claim) that becomes spendable after a
 * CSV delay from the source's confirmation. The scheduler walks this
 * array every block and flips entries through:
 *
 *   PENDING   — source TX not yet confirmed
 *   READY     — source confirmed + CSV expired, sweep TX buildable
 *   BROADCAST — we sent a sweep; waiting for confirmations
 *   CONFIRMED — sweep has ≥3 confs, entry is done (ready to drop)
 *   FAILED    — broadcast errored; retry next cycle
 *
 * Mirrors upstream's sweep_type_t but narrows to the cases that
 * actually apply inside a CLN plugin (the LN-channel cases belong to
 * CLN proper, not us):
 *
 *   SWEEP_FACTORY_LSTOCK  — burn-TX-confirmed L-stock output we've
 *                           claimed (needed if burn doesn't pay direct)
 *   SWEEP_FACTORY_LEAF    — our own P2TR share on a confirmed leaf
 *   SWEEP_FACTORY_TIMEOUT — post-timeout-spend output we need to
 *                           forward to our wallet
 *
 * Phase 4d v1 lands the state machine + persistence + dev RPCs for
 * testing. The actual sweep-TX construction is factory-leaf-type
 * specific and is deferred to Phase 4d2. The scheduler drives state
 * transitions based on the signals we have today. */
#define MAX_PENDING_SWEEPS 16

typedef enum {
	SWEEP_STATE_PENDING   = 0,
	SWEEP_STATE_READY     = 1,
	SWEEP_STATE_BROADCAST = 2,
	SWEEP_STATE_CONFIRMED = 3,
	SWEEP_STATE_FAILED    = 4,
} sweep_state_t;

typedef enum {
	SWEEP_TYPE_FACTORY_LSTOCK  = 0,
	SWEEP_TYPE_FACTORY_LEAF    = 1,
	SWEEP_TYPE_FACTORY_TIMEOUT = 2,
} sweep_type_t;

typedef struct {
	uint8_t  type;             /* sweep_type_t */
	uint8_t  state;            /* sweep_state_t */
	uint8_t  source_txid[32];  /* output we're sweeping (internal BE) */
	uint32_t source_vout;
	uint64_t amount_sats;
	uint32_t csv_delay;        /* blocks from source confirm to maturity */
	uint32_t confirmed_block;  /* source confirmed at this height (0=unconf) */
	uint8_t  sweep_txid[32];   /* our broadcast sweep (zero = not broadcast) */
	uint32_t broadcast_block;  /* block we broadcast sweep (0 = none) */
	uint32_t sweep_confirmed_block; /* sweep's own confirm (0 = unconfirmed) */
	uint8_t  reserved[4];      /* pad — keeps on-disk size stable */
} pending_sweep_t;

/* Phase 3c2: CPFP-via-anchor pipeline.
 *
 * For pre-signed multi-party TXs (dist TX broadcast at expiry, state
 * TX in DYING cascade, kickoff in DYING cascade), the parent fee is
 * baked in at signing time. If the network feerate has risen since
 * signing, the parent gets stuck in mempool. Bitcoin-Core 28+ supports
 * P2A (Pay-to-Anchor, BIP-431) outputs; upstream factory.c emits them
 * on dist/state/kickoff TXs. We CPFP-bump by spending the anchor +
 * a wallet UTXO in a child TX with high fee, amortized over the
 * parent+child package.
 *
 * Reference: upstream watchtower.c:watchtower_build_cpfp_tx (1305 LOC
 * of full impl with wallet_source_t vtable). Our Phase 3c2 v1 lands
 * the state machine + scheduler + dev RPCs; v2 (3c2.5) adds the
 * actual wally PSBT construction + CLN signpsbt RPC chain. */
#define MAX_PENDING_CPFPS 8

typedef enum {
	CPFP_STATE_PENDING   = 0, /* parent broadcast, child not yet built */
	CPFP_STATE_BROADCAST = 1, /* child in mempool, awaiting confirm */
	CPFP_STATE_CONFIRMED = 2, /* parent + child both confirmed */
	CPFP_STATE_FAILED    = 3, /* wallet input unavailable / construction failed */
	CPFP_STATE_RESOLVED  = 4, /* parent confirmed without our help (network bumped) */
} cpfp_state_t;

typedef enum {
	CPFP_PARENT_DIST    = 0, /* expiry-broadcast distribution TX */
	CPFP_PARENT_STATE   = 1, /* DW cascade state TX */
	CPFP_PARENT_KICKOFF = 2, /* DW cascade kickoff */
} cpfp_parent_kind_t;

typedef struct {
	uint8_t  parent_kind;       /* cpfp_parent_kind_t */
	uint8_t  state;             /* cpfp_state_t */
	uint8_t  parent_txid[32];   /* parent we're CPFP'ing (internal BE) */
	uint32_t parent_vout_anchor;/* P2A anchor vout (typically 1) */
	uint64_t parent_value_at_stake; /* budget basis for fee allocation */
	uint32_t parent_broadcast_block;
	uint32_t deadline_block;    /* when we MUST get the parent confirmed */
	uint8_t  cpfp_txid[32];     /* our CPFP child (zero = not built yet) */
	uint32_t cpfp_broadcast_block;
	uint64_t cpfp_last_feerate; /* sat/kvB on last child broadcast */
	uint32_t parent_confirmed_block; /* 0 if parent unconfirmed */
	uint8_t  reserved[4];       /* pad */
} pending_cpfp_t;

/* Per-epoch breach data */
typedef struct {
	uint32_t epoch;
	uint8_t revocation_secret[32];	/* Secret for this epoch */
	bool has_revocation;		/* Whether we have the secret */
	/* Serialized commitment txs per leaf — needed for penalty */
	uint8_t *commitment_data;
	size_t commitment_data_len;
} epoch_breach_data_t;

/* Channel-to-leaf mapping */
typedef struct {
	uint8_t channel_id[32];		/* CLN channel_id */
	int leaf_index;			/* Index into factory tree */
	int leaf_side;			/* 0=A (client), 1=B (LSP L-stock) */
} channel_leaf_map_t;

/* Per-client ceremony tracking */
typedef struct {
	uint8_t node_id[33];		/* Compressed pubkey */
	bool connected;			/* Currently connected */
	bool nonce_received;		/* Sent NONCE_BUNDLE this round */
	bool psig_received;		/* Sent PSIG_BUNDLE this round */
	int signer_slot;		/* Index in MuSig2 signer set */
	uint8_t factory_pubkey[33];	/* Real factory pubkey (from NONCE_BUNDLE) */
	bool has_factory_pubkey;	/* Whether factory_pubkey was received */
	uint64_t allocation_sats;	/* Sats allocated to this client's channel.
					 * 0 = use default even-split. Set by
					 * factory-create `allocations` param. */
	/* REVOKE delivery tracking (LSP-side only).
	 *
	 *   pending_revoke_epoch — epoch whose secret we sent REVOKE for
	 *                          and are still waiting on REVOKE_ACK.
	 *                          UINT32_MAX when nothing is pending.
	 *   last_acked_epoch     — highest epoch this client has acked.
	 *                          UINT32_MAX when no ack has ever been
	 *                          received (pre-rotation factories).
	 *
	 * The rotation path consults these before sending the NEXT REVOKE
	 * so we never race ahead of a client whose storage write is in
	 * flight or whose peer connection is flapping. Both fields are
	 * persisted in meta. On reconnect, any pending_revoke_epoch that
	 * hasn't been acked triggers a REVOKE resend. */
	uint32_t pending_revoke_epoch;
	uint32_t last_acked_epoch;
} client_state_t;

/* Factory instance */
typedef struct factory_instance {
	/* Identity */
	uint8_t instance_id[32];
	uint8_t protocol_id[32];

	/* Role */
	bool is_lsp;			/* Are we the LSP for this factory? */

	/* Participants */
	uint8_t lsp_node_id[33];
	client_state_t clients[MAX_FACTORY_PARTICIPANTS];
	size_t n_clients;

	/* Ceremony */
	ceremony_state_t ceremony;
	uint32_t ceremony_round;	/* Which round of nonce/sig exchange */

	/* DW state */
	uint32_t epoch;			/* Current DW epoch */
	uint32_t max_epochs;		/* Total states before exhaustion */

	/* Tier 2.6: arity policy for this factory. Values match libsuperscalar's
	 * factory_arity_t (1=ARITY_1, 2=ARITY_2, 3=ARITY_PS). The sentinel 0
	 * means "auto" — ss_effective_arity() falls back to ss_choose_arity()
	 * on n_clients+1. Set by factory-create's optional arity_mode param
	 * (LSP), or received from FACTORY_PROPOSE / ALL_NONCES (client). */
	uint8_t arity_mode;

	/* Tier 2.6: in-flight per-leaf advance ceremony (ARITY_1 DW leaf or
	 * ARITY_PS chain append). ps_pending_leaf != -1 means a PROPOSE has
	 * been sent (LSP) or received (client), and we're awaiting the next
	 * round's wire message. Fields:
	 *   ps_pending_leaf     — leaf_side (0..n_leaf_nodes-1) or -1 (idle)
	 *   ps_pending_node_idx — cached factory_t node index for that leaf
	 *   ps_pending_secnonce — heap-alloc'd secp256k1_musig_secnonce opaque
	 *                         (LSP: generated at PROPOSE send, freed after
	 *                         PSIG receive; client: generated at PROPOSE
	 *                         receive, freed after PSIG send)
	 * Memory-only; not persisted. On restart an in-flight advance is
	 * abandoned and the LSP may retry. */
	int32_t  ps_pending_leaf;
	uint32_t ps_pending_node_idx;
	void    *ps_pending_secnonce;
	uint32_t ps_pending_start_block; /* block at PROPOSE send; 0 = idle.
					  * handle_block_added clears pending
					  * state after PS_PENDING_TIMEOUT_BLOCKS
					  * elapse without PSIG/DONE. */
	uint8_t  ps_pending_is_realloc;  /* Follow-up #4: 1 if the in-flight
					  * ceremony is a LEAF_REALLOC (new
					  * amounts, no chain advance); 0 for
					  * LEAF_ADVANCE. Memory-only. */

	/* Cached LEAF_ADVANCE_PROPOSE wire payload + target peer for
	 * reconnect resume. Mirrors the cached_rotate_propose_wire
	 * pattern: if the peer drops between PROPOSE-send and PSIG-
	 * receipt, peer_connected resends the cached payload so the
	 * ceremony continues. Allocated at json_factory_ps_advance
	 * PROPOSE-send time; freed in ss_clear_ps_pending. */
	uint8_t *cached_ps_propose_wire;
	size_t   cached_ps_propose_len;
	uint8_t  cached_ps_propose_target_pid[33];

	/* Cached LEAF_ADVANCE_PSIG wire payload (CLIENT side). When the
	 * client receives a duplicate PROPOSE for the same leaf — caused
	 * by an LSP-side cached_ps_propose_wire resend after reconnect —
	 * it must re-send THIS cached PSIG rather than re-sign. Re-signing
	 * with a fresh nonce against the same MuSig session would leak
	 * the seckey (BIP-327 nonce reuse). Allocated when client sends
	 * its PSIG; freed in ss_clear_ps_pending. */
	uint8_t *cached_ps_psig_wire;
	size_t   cached_ps_psig_len;

	/* Task #93: ARITY_2 3-of-3 LEAF_REALLOC ceremony state.  ARITY_2
	 * leaves have 3 signers (LSP + 2 clients) — the simple 2-of-2
	 * pending fields above can't track which clients have replied.
	 * realloc_subtree_clients holds the two client participant_idx
	 * values (factory-wide, not slot-within-leaf) collected via
	 * factory_get_subtree_clients() at PROPOSE time on the LSP side.
	 * realloc_pubnonces / realloc_has_pubnonce / realloc_psigs /
	 * realloc_has_psig are indexed by signer_slot WITHIN the leaf
	 * (0..2 — slot 0 is always LSP). All zeroed when no 3-of-3
	 * ceremony is in flight. Memory-only. */
	uint32_t realloc_subtree_clients[2];
	uint8_t  realloc_pubnonces[3][66];
	uint8_t  realloc_psigs[3][32];
	uint8_t  realloc_has_pubnonce[3];
	uint8_t  realloc_has_psig[3];

	/* Lifecycle */
	factory_lifecycle_t lifecycle;
	uint32_t creation_block;	/* Block height at creation */
	uint32_t expiry_block;		/* Absolute block height of factory expiry */
	uint16_t early_warning_time;	/* Blocks before expiry to warn */

	/* Channel mappings */
	channel_leaf_map_t channels[MAX_FACTORY_PARTICIPANTS];
	size_t n_channels;

	/* Breach data (circular buffer of recent epochs) */
	epoch_breach_data_t *breach_data;
	size_t n_breach_epochs;

	/* Phase 3c: pending penalty records. Populated when classifier
	 * fires CLOSED_BREACHED (or when breach burn is built in
	 * breach_utxo_checked) and retained until the penalty TX confirms
	 * or becomes irrelevant. Per-block scheduler walks this array,
	 * running each entry through htlc_fee_bump_should_bump. */
	pending_penalty_t pending_penalties[MAX_PENDING_PENALTIES];
	size_t n_pending_penalties;

	/* Phase 4d: pending sweep records. Populated when we identify an
	 * output that needs CSV-delayed claim (our share of a leaf,
	 * residuals after a timeout-spend, etc.). Per-block scheduler
	 * ticks state transitions; actual TX construction + broadcast
	 * lives in the sweep-type-specific handler (Phase 4d2). */
	pending_sweep_t pending_sweeps[MAX_PENDING_SWEEPS];
	size_t n_pending_sweeps;

	/* Phase 3c2: pending CPFP-via-anchor records. Populated when we
	 * broadcast a parent TX with a P2A anchor output (dist, state,
	 * kickoff). Per-block scheduler ticks fee math via
	 * htlc_fee_bump_t and (in 3c2.5) builds + broadcasts a CPFP
	 * child spending the parent's anchor + a wallet UTXO. */
	pending_cpfp_t pending_cpfps[MAX_PENDING_CPFPS];
	size_t n_pending_cpfps;

	/* Phase 3c3: per-factory fee estimator. Passed to libsuperscalar's
	 * factory_t->fee pointer so factory_build_node_tx's
	 * fee_should_use_anchor() gate returns true, causing P2A anchor
	 * outputs to be appended to tree TXs. Without this, Phase
	 * 3c2/3c2.5's CPFP pipeline would never fire (no anchors to spend).
	 *
	 * Stored inline on factory_instance_t so its lifetime matches the
	 * factory_t (which holds a pointer to this struct's base member).
	 * Initialized to a static constant rate in json_factory_create and
	 * in the dispatch_superscalar_submsg LSP/client-side factory init.
	 *
	 * Declared as opaque bytes because factory_state.h is plain-C and
	 * doesn't pull in superscalar/fee_estimator.h. Actual type is
	 * fee_estimator_static_t (= base fee_estimator_t + u64 rate).
	 * sizeof check in superscalar.c asserts it fits. */
	uint8_t fee_estimator_storage[64];

	/* Rotation */
	bool rotation_in_progress;

	/* HTLC early-warning: set true the first time handle_block_added
	 * sees ss_factory_should_warn() fire and triggers force-closes on
	 * this factory's LN channels. Prevents repeated close RPCs on
	 * subsequent blocks while the close is in flight / settling. Not
	 * persisted on purpose — if the plugin restarts inside the early-
	 * warning window, we want to re-trigger closes for any channels
	 * that hadn't completed closing yet. */
	bool warning_close_triggered;

	/* Key turnover (assisted exit): per-client departure state.
	 * When a client departs, we store their extracted secret key
	 * so the LSP can sign on their behalf for the factory's lifetime. */
	bool client_departed[MAX_FACTORY_PARTICIPANTS];
	uint8_t extracted_keys[MAX_FACTORY_PARTICIPANTS][32];
	size_t n_departed;

	/* Funding info */
	uint8_t funding_txid[32];
	uint32_t funding_outnum;
	uint64_t funding_amount_sats;
	uint8_t funding_spk[34];
	uint8_t funding_spk_len;

	/* Block height at which the watcher observed the funding root spent
	 * outside plugin control. 0 for factories that never hit
	 * CLOSED_EXTERNALLY. Persisted in meta v6+ so operator tooling can
	 * show "zombie since block N" and forensics can line up with chain
	 * history. */
	uint32_t closed_externally_at_block;

	/* Phase 4c: block at which an operator (or auto-detector) flipped
	 * this factory to ABORTED via factory-abort-stuck. 0 means
	 * never aborted. Used by factory-list to show "aborted at block N"
	 * and by future auto-recovery to schedule unilateral CLTV exit
	 * once factory expiry is reached. */
	uint32_t aborted_at_block;

	/* Phase 2a: spending-TX identification.
	 *
	 * Populated by the block scan launched after the UTXO heartbeat
	 * detects the funding root spent. The scan walks recent blocks
	 * looking for a TX whose vin references our funding outpoint; once
	 * found, we match its txid against our own signed artifacts
	 * (dist_signed_tx for cooperative, lib_factory->nodes[0].txid for
	 * our unilateral kickoff) and set lifecycle/closed_by accordingly.
	 *
	 * When the scan fails to find the spending TX (the spend predates
	 * our scan window), spending_txid stays all-zero and classification
	 * remains CLOSED_EXTERNALLY with closed_by = CLOSED_BY_UNKNOWN.
	 *
	 * Phase 2b will add per-epoch tree reconstruction to distinguish
	 * counterparty-normal-exit from breach within the
	 * "closed_by != self" bucket. */
	uint8_t spending_txid[32];
	uint32_t first_noticed_block; /* block_added height when UTXO was first seen spent */

	/* Who drove the close, per Phase 2a classification. Values match the
	 * CLOSED_BY_* constants below. Stored as uint8_t for portable
	 * persistence; don't renumber the constants without a version bump. */
	uint8_t closed_by;

	/* Phase 2b: cooperative-close identification.
	 *
	 * When dist_signed_tx is set (distribution TX is MuSig2-signed and
	 * ready to broadcast), we precompute its segwit txid (BIP-141
	 * non-witness serialization, double-SHA256) and cache here. The
	 * classifier matches spending_txid against this value to recognize
	 * "factory was cooperatively closed" — could be either party that
	 * actually broadcast; same signed bytes, same txid either way.
	 * All-zero means no dist TX is signed yet. */
	uint8_t dist_signed_txid[32];

	/* Phase 2b: breach-epoch identification.
	 *
	 * When the classifier matches the spending TX's witness signature
	 * to a past epoch's kickoff signature, this records which epoch
	 * the counterparty published. Only meaningful when
	 * lifecycle == FACTORY_LIFECYCLE_CLOSED_BREACHED. UINT32_MAX sentinel
	 * when no breach has been classified. Phase 3 reads this to pick
	 * the right revocation secret when building the penalty TX. */
	uint32_t breach_epoch;

	/* Phase 2b: per-epoch kickoff witness signature cache.
	 *
	 * The kickoff TXID is stable across epochs (DW timelock race requires
	 * it — see the comment in json_factory_rotate) but the WITNESS
	 * (Schnorr signature) differs per epoch because MuSig2 signs the
	 * input with a per-epoch-aggregated key state. So matching a
	 * published kickoff against stored per-epoch witnesses tells us
	 * which epoch the counterparty broadcast.
	 *
	 * history_kickoff_sigs[i] holds the 64-byte Schnorr sig captured at
	 * the moment we rotated past epoch (history_kickoff_epochs[i]). Both
	 * LSP and client capture independently; signatures are identical
	 * because MuSig2 aggregation is deterministic. Capped at the max
	 * rotation count (16 per current default); grows monotonically.
	 *
	 * Factories that existed before Phase 2b shipped start with
	 * n_history_kickoff_sigs = 0 and can't be classified via sig match
	 * for any past epoch; the classifier falls back to
	 * closed_by=COUNTERPARTY without an epoch label. */
	#define MAX_HISTORY_SIGS 64
	uint8_t history_kickoff_sigs[MAX_HISTORY_SIGS][64];
	uint32_t history_kickoff_epochs[MAX_HISTORY_SIGS];
	size_t n_history_kickoff_sigs;

	/* Phase 3b: per-epoch state-tree-root TXID cache.
	 *
	 * Sibling to history_kickoff_sigs. The kickoff (nodes[0]) txid is
	 * stable across epochs, but the state-tree-root TX (nodes[1]) that
	 * spends the kickoff's output IS epoch-specific — its outputs
	 * encode the per-epoch revocation commitments. Matching a
	 * downstream-scan-found state-TX-spend against this cache tells us
	 * which epoch's state was actually broadcast.
	 *
	 * Same indexing as history_kickoff_*: history_state_root_txids[i]
	 * pairs with history_kickoff_epochs[i]. Snapshotted at rotation
	 * time alongside the kickoff sig.
	 *
	 * Pre-Phase-3b factories start empty. Phase 3b's downstream classifier
	 * falls back to "no past-epoch state TXIDs cached" when this is empty
	 * for an epoch the counterparty broadcast. */
	uint8_t history_state_root_txids[MAX_HISTORY_SIGS][32];

	/* Phase 3b: signal observation bitmask. Tracks which evidence
	 * sources contributed to the current lifecycle decision. Used by
	 * ss_apply_signals() to make idempotent classification decisions
	 * and by factory-list to surface the evidence trail.
	 *
	 * Widened from u8 to u16 in Phase 3c — bit 8 is SIGNAL_PENALTY_CONFIRMED. */
	uint16_t signals_observed;

	/* Phase 3b: matched epoch from downstream state-TX scan.
	 * UINT32_MAX when no match. Independent of breach_epoch (which
	 * comes from the witness-sig path); both can populate concurrently
	 * and the unified classifier reconciles them. */
	uint32_t state_tx_match_epoch;

	/* Cached tree node count (persisted so factory-list works after restart
	 * even when lib_factory hasn't been rebuilt yet). */
	uint32_t n_tree_nodes;

	/* Signed distribution TX (nLockTime fallback).
	 * Broadcast after factory expiry — clients get their funds. */
	uint8_t *dist_signed_tx;
	size_t dist_signed_tx_len;

	/* Handle to libsuperscalar factory_t.
	 * NULL until the library is initialized for this instance.
	 * Declared as void* to avoid requiring superscalar headers
	 * in every file that includes factory_state.h. */
	void *lib_factory;

	/* Distribution TX standalone MuSig2 signing session.
	 * Separate from tree node sessions — uses root keyagg. */
	void *dist_session;  /* musig_signing_session_t* */

	/* Follow-up #1 sub-PR 3B: collected partial sigs for the dist TX
	 * ceremony. Populated as each DIST_PSIG arrives on the LSP side,
	 * plus LSP's own psig when all client psigs are in. Aggregated
	 * via musig_aggregate_partial_sigs into the 64-byte Schnorr sig
	 * that becomes the dist TX witness. Indexed by participant_idx
	 * (0 = LSP, 1..N = clients). */
	uint8_t dist_psigs[MAX_FACTORY_PARTICIPANTS][32];
	uint8_t dist_has_psig[MAX_FACTORY_PARTICIPANTS];

	/* Cached nonce entries for ALL_NONCES broadcast (multi-client).
	 * Populated during FACTORY_PROPOSE (LSP's own nonces) and
	 * NONCE_BUNDLE (each client's nonces). Sent as ALL_NONCES
	 * when all clients have responded. Heap-allocated. */
	void *cached_nonces;     /* nonce_entry_t* array */
	size_t n_cached_nonces;
	size_t cached_nonces_cap;

	/* Cached serialized ALL_NONCES wire payload for reconnect recovery.
	 * Populated when ALL_NONCES is first sent; freed after PSIG phase.
	 * Allows re-sending ALL_NONCES if a client disconnects mid-ceremony. */
	uint8_t *cached_all_nonces_wire;
	size_t cached_all_nonces_len;

	/* Cached serialized ROTATE_PROPOSE wire payload for rotation reconnect.
	 * Populated at json_factory_rotate start; freed when rotation
	 * completes (CEREMONY_ROTATE_COMPLETE transition). If a client drops
	 * after receiving ROTATE_PROPOSE but before sending ROTATE_NONCE, the
	 * peer_connected handler resends this payload so rotation doesn't
	 * wedge. Same precedent as cached_all_nonces_wire — in-memory only,
	 * not persisted; covers the common disconnect case without LSP
	 * restart. */
	uint8_t *cached_rotate_propose_wire;
	size_t cached_rotate_propose_len;

	/* MuSig2 nonce pool (heap-allocated, secnonces live inside) */
	void *nonce_pool;
	/* Per-entry: which pool index maps to which tree node */
	uint32_t secnonce_node_idx[MAX_NONCE_ENTRIES];
	uint32_t secnonce_pool_idx[MAX_NONCE_ENTRIES];
	size_t n_secnonces;
	uint8_t our_seckey[32];
	int our_participant_idx;

	/* Per-client allocations (sats). Index 0 = client 0, index 1 = client 1...
	 * Populated on LSP from factory-create `allocations` param, and on
	 * clients from FACTORY_PROPOSE / ALL_NONCES payloads.
	 * n_allocations == 0 means fall back to even split. */
	uint8_t n_allocations;
	uint64_t allocations[MAX_FACTORY_PARTICIPANTS];

	/* Gap 9: MuSig2 keyagg cache snapshots per node, captured at
	 * factory_build_tree time and persisted in meta v15+. Restored onto
	 * lib_factory->nodes[i].keyagg after every rebuild so we never
	 * depend on the recompute being bit-for-bit identical to what the
	 * tree was originally signed with. Defends the signet-recovery
	 * incident where two factories produced sigs that failed on-chain
	 * validation despite the x-only agg pubkey matching.
	 *
	 * Blob layout:
	 *   u16  n_entries
	 *   for each entry:
	 *     u16  node_idx
	 *     u32  payload_size
	 *     u8[payload_size]   raw bytes of musig_keyagg_t (memcpy)
	 *
	 * n_entries == 0 (or NULL blob) means no snapshot — caller falls
	 * back to whatever factory_build_tree computed. Heap-owned; freed
	 * on factory destruction. */
	uint8_t *keyagg_snapshots;
	size_t   keyagg_snapshots_len;

} factory_instance_t;

/* Global plugin state */
typedef struct superscalar_state {
	factory_instance_t *factories[MAX_FACTORIES];
	size_t n_factories;
	bool is_lsp;			/* Global mode: LSP or client */
	uint8_t our_node_id[33];	/* Our compressed pubkey */
	uint32_t current_blockheight;

	/* Phase 4e2: previous block height observed, for reorg auto-
	 * trigger. handle_block_added checks if new <= prev and invokes
	 * ss_penalty_reorg_check on every factory with confirmed
	 * penalties. Starts at 0 — first block_added seed-populates it. */
	uint32_t last_observed_blockheight;

	uint8_t factory_master_key[32];	/* HSM-derived master key for factories */
	bool has_master_key;		/* Whether master key was derived */

	/* Monotonic counter feeding deterministic instance_id derivation
	 * (Gap 8). Each factory-create consumes the current value and
	 * increments. Persisted to the datastore under
	 * "superscalar/iid_counter"; reloaded on plugin startup so iids
	 * stay unique across restarts. On datastore loss with HSM intact,
	 * an operator recovers by deriving candidate iids for counter
	 * values 0..N and matching them against on-chain funding
	 * addresses. */
	uint32_t factory_counter;
	bool has_counter_loaded;	/* distinguishes "no counter yet" (fresh
					 * plugin) from "counter is 0" after load */
} superscalar_state_t;

/* State management functions */

/* Initialize global state */
void ss_state_init(superscalar_state_t *state);

/* Create a new factory instance */
factory_instance_t *ss_factory_new(superscalar_state_t *state,
				   const uint8_t *instance_id);

/* Find factory by instance_id */
factory_instance_t *ss_factory_find(superscalar_state_t *state,
				    const uint8_t *instance_id);

/* Find factory by channel_id (searches channel mappings) */
factory_instance_t *ss_factory_find_by_channel(superscalar_state_t *state,
					       const uint8_t *channel_id);

/* Find client within a factory by node_id */
client_state_t *ss_factory_find_client(factory_instance_t *fi,
				       const uint8_t *node_id);

/* Check if all clients have sent nonces for current round */
bool ss_factory_all_nonces_received(const factory_instance_t *fi);

/* Check if all clients have sent partial sigs for current round */
bool ss_factory_all_psigs_received(const factory_instance_t *fi);

/* Reset ceremony tracking for a new round */
void ss_factory_reset_ceremony(factory_instance_t *fi);

/* Add breach data for an epoch */
void ss_factory_add_breach_data(factory_instance_t *fi,
				uint32_t epoch,
				const uint8_t *revocation_secret,
				const uint8_t *commitment_data,
				size_t commitment_data_len);

/* Map a CLN channel to a factory leaf */
void ss_factory_map_channel(factory_instance_t *fi,
			    const uint8_t *channel_id,
			    int leaf_index, int leaf_side);

/* Lifecycle checks */
bool ss_factory_should_warn(const factory_instance_t *fi,
			    uint32_t current_block);
bool ss_factory_should_close(const factory_instance_t *fi,
			     uint32_t current_block);

#endif /* SUPERSCALAR_FACTORY_STATE_H */
